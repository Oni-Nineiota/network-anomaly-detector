"""Flask web application for the Network Anomaly Detector."""

from flask import Flask, request, render_template, jsonify, redirect, url_for, Response
import time
import os
import json
import io
import csv
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
    "ddos_flood": "sample_logs/ddos_flood.log",
    "slow_scan": "sample_logs/slow_scan.log",
    "data_exfiltration": "sample_logs/data_exfiltration.log",
    "multi_attacker": "sample_logs/multi_attacker.log",
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


@app.route("/export/csv")
def export_csv():
    """Export analysis results as a downloadable CSV file."""
    global last_results, last_metadata

    if last_results is None:
        return jsonify({"error": "No analysis to export. Run an analysis first."}), 400

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "TYPE", "MITRE_ID", "MITRE_NAME", "SOURCE_IP", "SEVERITY",
        "COUNT", "UNIQUE_PORTS", "TIMESPAN_SECONDS", "MULTIPLIER",
        "BYTES_SENT", "DEST_IP"
    ])

    # Anomaly rows
    for a in last_results.get("anomalies", []):
        writer.writerow([
            a.get("type", ""),
            a.get("mitre_id", ""),
            a.get("mitre_name", ""),
            a.get("src_ip", ""),
            a.get("severity", ""),
            a.get("count", a.get("connection_count", "")),
            a.get("unique_ports", ""),
            a.get("timespan_seconds", ""),
            a.get("multiplier", ""),
            a.get("bytes_sent", ""),
            a.get("dest_ip", ""),
        ])

    # Add summary section
    writer.writerow([])
    writer.writerow(["SUMMARY"])
    writer.writerow(["Total Events", last_results.get("total_events", 0)])
    writer.writerow(["Threat Score", last_results.get("threat_score", 0)])
    writer.writerow(["Anomalies Found", len(last_results.get("anomalies", []))])
    writer.writerow(["File", last_metadata.get("filename", "") if last_metadata else ""])
    writer.writerow(["Analyzed At", last_metadata.get("analyzed_at", "") if last_metadata else ""])

    # Threat intel hits
    threat_hits = last_results.get("threat_intel_hits", [])
    if threat_hits:
        writer.writerow([])
        writer.writerow(["THREAT INTELLIGENCE HITS"])
        for ip in threat_hits:
            writer.writerow([ip, "KNOWN MALICIOUS"])

    content = output.getvalue()
    filename = "anomaly_report.csv"

    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/export/json")
def export_json():
    """Export full analysis results as a downloadable JSON file."""
    global last_results, last_metadata

    if last_results is None:
        return jsonify({"error": "No analysis to export. Run an analysis first."}), 400

    export_data = {
        "metadata": last_metadata,
        "results": {
            "total_events": last_results.get("total_events", 0),
            "threat_score": last_results.get("threat_score", 0),
            "anomalies": last_results.get("anomalies", []),
            "flagged_ips": last_results.get("flagged_ips", {}),
            "threat_intel_hits": last_results.get("threat_intel_hits", []),
            "protocol_breakdown": last_results.get("protocol_breakdown", {}),
            "connection_states": last_results.get("connection_states", {}),
            "top_talkers": last_results.get("top_talkers", []),
        }
    }

    content = json.dumps(export_data, indent=2)
    filename = "anomaly_report.json"

    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/full-log")
def full_log():
    """Return the full content of the last analyzed log file."""
    global last_metadata

    if last_metadata is None:
        return jsonify({"error": "No file has been analyzed yet."}), 400

    filename = last_metadata.get("filename", "")

    # Check if it's a sample file
    for scenario, filepath in SAMPLE_FILES.items():
        if os.path.basename(filepath) == filename:
            try:
                with open(filepath, "r") as f:
                    content = f.read()
                return jsonify({"filename": filename, "content": content})
            except FileNotFoundError:
                return jsonify({"error": "Log file not found."}), 404

    # Otherwise check uploaded file
    if os.path.exists("uploaded.log"):
        with open("uploaded.log", "r") as f:
            content = f.read()
        return jsonify({"filename": filename, "content": content})

    return jsonify({"error": "Log file not found."}), 404


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
