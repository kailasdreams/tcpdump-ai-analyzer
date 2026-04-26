from flask import Flask, request, render_template
import os
import subprocess
import shutil
from pcap_parser import parse_pcap_with_dpkt
from ai_engine import analyze_with_ai

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "changeme-in-production")
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def run_tcpdump(filepath: str, flags: str):
    """
    Try tcpdump first. Falls back to dpkt Python parser if unavailable or broken.
    Returns (output_text, method_label).
    """
    tcpdump_bin = shutil.which("tcpdump") or shutil.which("tcpdump.exe")

    if tcpdump_bin:
        cmd = f"{tcpdump_bin} {flags} -r {filepath} 2>&1"
        raw = subprocess.getoutput(cmd)
        fail_markers = [
            "not recognized", "not found", "No such file",
            "command not found", "Permission denied",
            "error opening", "isn't a tcpdump", "bad dump file",
        ]
        if any(m.lower() in raw.lower() for m in fail_markers):
            raw, method = parse_pcap_with_dpkt(filepath)
            return raw, method
        return raw, f"tcpdump {flags}"

    # tcpdump absent → Python fallback
    return parse_pcap_with_dpkt(filepath)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    api_key  = request.form.get("api_key", "").strip()
    provider = request.form.get("provider", "anthropic")
    model    = request.form.get("model", "claude-sonnet-4-20250514")
    flags    = request.form.get("flags", "-nn -v").strip()
    file     = request.files.get("pcap_file")

    errors = []
    if not api_key:
        errors.append("API key is required.")
    if not file or file.filename == "":
        errors.append("A PCAP / dump file is required.")
    if errors:
        return render_template("index.html", errors=errors,
                               provider=provider, model=model, flags=flags)

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    raw, method_used = run_tcpdump(filepath, flags)

    stats = {
        "total_lines": len(raw.splitlines()),
        "file_name":   file.filename,
        "cmd_used":    method_used,
    }

    ai_response, ai_error = analyze_with_ai(
        tcpdump_data=raw,
        provider=provider,
        model=model,
        api_key=api_key,
    )

    return render_template(
        "index.html",
        output=ai_response,
        ai_error=ai_error,
        raw_dump=raw[:8000],
        stats=stats,
        provider=provider,
        model=model,
        flags=flags,
    )


if __name__ == "__main__":
    app.run(debug=True)
