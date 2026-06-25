"""Flask web application for the Network Anomaly Detector."""

from flask import Flask, request, render_template, jsonify, send_file
import time
import io
import csv
import os
from datetime import datetime

from detector import analyze_file

app = Flask(__name__)

# Global state for last analysis results (used by /download-csv)
last_results = None

# Map scenario names to file paths
SAMPLE_FILES = {
    "brute_force": "sample_logs/brute_force.log",
    "port_scan": "sample_logs/port_scan.log",
    "normal_traffic": "sample_logs/normal_traffic.log",
    "combined_attack": "sample_logs/combined_attack.log",
}


@app.route("/")
def index():
    """Render the main page with no analysis data."""
    return render_template("index.html", results=None, metadata=None, error=None)


@app.route("/load-sample/<scenario>")
def load_sample(scenario):
    """Load and analyze a sample log file by scenario name."""
    global last_results

    if scenario not in SAMPLE_FILES:
        return render_template(
            "index.html",
            results=None,
            metadata=None,
            error=f"Unknown scenario: '{scenario}'. Valid options: {', '.join(SAMPLE_FILES.keys())}",
        )

    filepath = SAMPLE_FILES[scenario]

    start_time = time.time()
    results = analyze_file(filepath)
    end_time = time.time()

    processing_time_ms = int((end_time - start_time) * 1000)

    metadata = {
        "filename": os.path.basename(filepath),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "processing_time_ms": processing_time_ms,
    }

    last_results = results

    return render_template("index.html", results=results, metadata=metadata, error=None)


@app.route("/upload", methods=["POST"])
def upload():
    """Handle uploaded log file and analyze it."""
    global last_results

    # Check if file was provided
    if "logfile" not in request.files:
        return render_template(
            "index.html",
            results=None,
            metadata=None,
            error="No file provided. Please select a .log file to upload.",
        )

    file = request.files["logfile"]

    # Check if file is empty
    if file.filename == "":
        return render_template(
            "index.html",
            results=None,
            metadata=None,
            error="No file selected. Please choose a file to upload.",
        )

    # Check file extension
    if not file.filename.endswith(".log"):
        return render_template(
            "index.html",
            results=None,
            metadata=None,
            error="Only Zeek .log files are supported.",
        )

    # Save temporarily and analyze
    temp_path = "uploaded.log"
    file.save(temp_path)

    try:
        start_time = time.time()
        results = analyze_file(temp_path)
        end_time = time.time()

        processing_time_ms = int((end_time - start_time) * 1000)

        metadata = {
            "filename": file.filename,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "processing_time_ms": processing_time_ms,
        }

        last_results = results

        return render_template("index.html", results=results, metadata=metadata, error=None)

    except Exception:
        return render_template(
            "index.html",
            results=None,
            metadata=None,
            error="Could not parse file — make sure it is a valid Zeek conn.log file.",
        )


@app.route("/download-csv")
def download_csv():
    """Download the last analysis results as a CSV file."""
    global last_results

    if last_results is None:
        return "No analysis results available. Run an analysis first.", 404

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(["Type", "Source IP", "Count", "Timespan (seconds)", "Severity"])

    # Data rows from anomalies
    for anomaly in last_results.get("anomalies", []):
        writer.writerow([
            anomaly.get("type", ""),
            anomaly.get("src_ip", "N/A"),
            anomaly.get("count", anomaly.get("unique_ports", anomaly.get("connection_count", ""))),
            anomaly.get("timespan_seconds", ""),
            anomaly.get("severity", ""),
        ])

    # Convert to bytes for send_file
    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)

    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="anomaly_report.csv",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
