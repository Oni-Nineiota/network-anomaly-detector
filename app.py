"""Flask web application for the Network Anomaly Detector."""

from flask import Flask, request, render_template, jsonify, redirect, url_for
import time
import os
from datetime import datetime

from detector import analyze_file

app = Flask(__name__)

# Global state for last analysis results (used by /report)
last_results = None
last_metadata = None

# Map scenario names to file paths
SAMPLE_FILES = {
    "brute_force": "sample_logs/brute_force.log",
    "port_scan": "sample_logs/port_scan.log",
    "normal_traffic": "sample_logs/normal_traffic.log",
    "combined_attack": "sample_logs/combined_attack.log",
}


@app.route("/")
def index():
    """Render the main page."""
    return render_template("index.html")


@app.route("/load-sample/<scenario>")
def load_sample(scenario):
    """Load and analyze a sample log file, return JSON."""
    global last_results, last_metadata

    if scenario not in SAMPLE_FILES:
        return jsonify({
            "error": f"Unknown scenario: '{scenario}'. Valid options: {', '.join(SAMPLE_FILES.keys())}"
        }), 400

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
    last_metadata = metadata

    return jsonify({"results": results, "metadata": metadata})


@app.route("/upload", methods=["POST"])
def upload():
    """Handle uploaded log file and analyze it, return JSON."""
    global last_results, last_metadata

    if "logfile" not in request.files:
        return jsonify({"error": "No file provided. Please select a .log file to upload."}), 400

    file = request.files["logfile"]

    if file.filename == "":
        return jsonify({"error": "No file selected. Please choose a file to upload."}), 400

    if not file.filename.endswith(".log"):
        return jsonify({"error": "Only Zeek .log files are supported."}), 400

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
        last_metadata = metadata

        return jsonify({"results": results, "metadata": metadata})

    except Exception:
        return jsonify({
            "error": "Could not parse file — make sure it is a valid Zeek conn.log file."
        }), 400


@app.route("/report")
def report():
    """Render a terminal-style incident report from last analysis."""
    global last_results, last_metadata

    if last_results is None:
        return redirect(url_for("index"))

    # Build enriched flagged_ips list with reputation for template
    from detector import _get_ip_reputation
    flagged_ips_list = []
    for ip, detections in last_results.get("flagged_ips", {}).items():
        flagged_ips_list.append({
            "ip": ip,
            "detections": detections,
            "reputation": _get_ip_reputation(ip),
        })

    return render_template(
        "report.html",
        results=last_results,
        metadata=last_metadata,
        flagged_ips_list=flagged_ips_list,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
