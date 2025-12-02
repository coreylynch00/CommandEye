from flask import Flask, request, render_template
from classifier import classify_command
from ioc_extractor import extract_iocs
import hashlib

app = Flask(__name__)

def vt_url_hash(url: str) -> str:
    """Return SHA256 hash of URL for VirusTotal URL report."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cmd = request.form["cmdline"]
        findings, verdict, summary = classify_command(cmd)
        iocs = extract_iocs(cmd)

        if not findings:
            findings = "No suspicious patterns detected."

        url_hashes = {u: vt_url_hash(u) for u in iocs.urls or []}

        return render_template(
            "template.html",
            result=findings,
            verdict=verdict,
            input_cmd=cmd,
            iocs=iocs,
            summary=summary,
            url_hashes=url_hashes
        )

    return render_template("template.html")

if __name__ == "__main__":
    app.run(debug=True)

