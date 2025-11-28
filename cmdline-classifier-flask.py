from flask import Flask, request, render_template_string
import re
from urllib.parse import urlparse

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Suspicious Command Line Classifier</title>
<style>
body {
    font-family: Consolas, monospace;
    margin: 20px;
    background: #000;
    color: #00ff9f;
    font-size: 12px;   
}
input[type=text] {
    width: 85%;
    padding: 6px;
    font-size: 12px;
    border-radius: 3px;
    border: 1px solid #0f6;
    background: #001a00;
    color: #00ff9f;
}
button {
    padding: 6px 12px;
    font-size: 12px;
    background: #003300;
    color: #00ff9f;
    border: 1px solid #0f6;
    border-radius: 3px;
    cursor: pointer;
    margin-left: 6px;
}
.panel {
    margin-top: 15px;
    padding: 10px;
    background: #001300;
    border-left: 3px solid #00ff9f;
    border-radius: 5px;
    animation: fadeIn 0.6s ease-in-out;
}
.code {
    white-space: pre-wrap;
    padding: 5px;
    background: #000;
    border-radius: 3px;
    border: 1px solid #0f6;
    color: #00ffbf;
    font-size: 12px;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}
.list-block {
    margin-left: 5px;
    padding-left: 5px;
    border-left: 2px dashed #0f6;
    font-size: 12px;
}
hr {
    border: none;
    border-top: 1px dashed #0f6;
    margin: 25px 0;
}
</style>
</head>
<body>

<h1 style="color:#33ffcc;">[ Suspicious Command Line Classifier ]</h1>
<p style="color:#009f6f;">SOC Analyst Utility • Real-Time Command Line Detection Engine</p>

<form method="POST">
    <input type="text" name="cmdline" placeholder="Enter command line..." required>
    <button type="submit">Analyze</button>
</form>

{% if result %}
<hr>

<div class="panel">
    <h2>➤ Input Command</h2>
    <div class="code">{{ input_cmd }}</div>
</div>

<div class="panel">
    <h2>➤ Detection Summary</h2>
    <div class="code">{{ result }}</div>
</div>

<div class="panel">
    <h2>➤ IOC Extraction</h2>

    <h3>• URLs</h3>
    <div class="list-block">
        {% if iocs.urls %}
            {% for u in iocs.urls %}
                <div>{{ u }}</div>
            {% endfor %}
        {% else %}
            <div>No URLs detected.</div>
        {% endif %}
    </div>

    <h3>• IP Addresses</h3>
    <div class="list-block">
        {% if iocs.ips %}
            {% for ip in iocs.ips %}
                <div>{{ ip }}</div>
            {% endfor %}
        {% else %}
            <div>No IPs detected.</div>
        {% endif %}
    </div>

    <h3>• Domains</h3>
    <div class="list-block">
        {% if iocs.domains %}
            {% for d in iocs.domains %}
                <div>{{ d }}</div>
            {% endfor %}
        {% else %}
            <div>No domains detected.</div>
        {% endif %}
    </div>
</div>

<div class="panel">
    <h2>➤ Verdict</h2>
    <div class="code">{{ verdict }}</div>
</div>

{% endif %}

</body>
</html>
"""

# ======== DETECTION RULES ========

SUSPICIOUS_PATTERNS = {

    # === POWERSHELL TRADECRAFT ===
    r"powershell.*-enc": "PowerShell EncodedCommand (MITRE: T1059.001)",
    r"powershell.*bypass": "PowerShell ExecutionPolicy Bypass (MITRE: T1059.001)",
    r"powershell.*-nop": "PowerShell NoProfile (MITRE: T1059.001)",
    r"powershell.*-w hidden": "PowerShell Hidden Window (MITRE: T1059.001)",
    r"powershell.*hidden": "PowerShell Hidden Execution (MITRE: T1059.001)",
    r"powershell.*invoke-webrequest": "PowerShell Web Download (MITRE: T1105)",
    r"powershell.*new-object net.webclient": "PowerShell WebClient Download (MITRE: T1105)",
    r"powershell.*downloadfile": "PowerShell File Download (MITRE: T1105)",
    r"powershell.*iex": "PowerShell IEX Remote Execution (MITRE: T1059.001)",
    r"powershell.*invoke-expression": "PowerShell Invoke-Expression (MITRE: T1059.001)",
    r"powershell.*invoke-command": "PowerShell Lateral/Remote Execution (MITRE: T1021)",
    r"powershell.*add-type": "PowerShell Add-Type Inline C# Injection (MITRE: T1059.001)",
    r"powershell.*reflection\.assembly": "PowerShell Assembly Loading (MITRE: T1620)",
    r"powershell.*frombase64string": "PowerShell Base64 Decode (MITRE: T1027)",
    r"powershell.*gzipstream": "PowerShell GZIP Decompression Obfuscation",
    r"powershell.*system\.io\.memorystream": "PowerShell Stream-Based Payload",
    r"powershell.*-command\s+\"?\$": "PowerShell Inlined Script Execution",

    # === WINDOWS LOLOBINS ===
    r"msiexec\.exe.*http": "msiexec Remote Payload Install (MITRE: T1105)",
    r"msiexec.*\/q": "msiexec Quiet Install (MITRE: T1105)",
    r"rundll32.*javascript": "rundll32 JavaScript Execution (MITRE: T1218)",
    r"rundll32.*vbscript": "rundll32 VBScript Execution (MITRE: T1218)",
    r"regsvr32.*\.sct": "regsvr32 COM Scriptlet Execution / Squiblydoo (MITRE: T1218.010)",
    r"regsvr32.*http": "regsvr32 Remote Script Execution (MITRE: T1218.010)",
    r"wmic.*process call create": "WMIC Remote Execution (MITRE: T1047)",
    r"wmic.*shadowcopy": "WMIC Shadow Copy Tampering (MITRE: T1490)",
    r"vssadmin.*delete shadows": "Shadow Copy Deletion (MITRE: T1490)",
    r"wbadmin.*delete catalog": "Backup Catalog Deletion (MITRE: T1490)",
    r"bcdedit.*bootstatuspolicy": "Boot Configuration Modification (MITRE: T1542)",
    r"bcdedit.*recoveryenabled": "Disable Automatic Recovery (MITRE: T1490)",

    # === DOWNLOADERS / C2 FETCHING ===
    r"curl.*http": "curl Remote Retrieval (MITRE: T1105)",
    r"wget.*http": "wget Remote Retrieval (MITRE: T1105)",
    r"certutil.*-urlcache": "certutil Download (MITRE: T1105)",
    r"certutil.*decode": "certutil Base64 Decode (MITRE: T1140)",
    r"bitsadmin.*transfer": "BITSAdmin Download (MITRE: T1105)",
    r"invoke-webrequest": "PowerShell Invoke-WebRequest Download (MITRE: T1105)",
    r"invoke-restmethod": "PowerShell Invoke-RestMethod Download (MITRE: T1105)",
    r"python.*requests\.get": "Python-Based HTTP Downloader",
    r"cmd\.exe\s*/c.*http": "cmd.exe Remote Fetch (MITRE: T1105)",
    r"ftp.exe.*-s": "FTP Script Automation (MITRE: T1105)",
    r"tftp.*get": "TFTP Remote File Retrieval (MITRE: T1105)",

    # === OBFUSCATION / ENCODING ===
    r"base64": "Base64 Obfuscation (MITRE: T1027)",
    r"frombase64string": "Base64 Decoding (MITRE: T1027)",
    r"^J[A-Za-z0-9+/]{20,}={0,2}$": "Likely Base64 Shellcode",
    r"gzipstream": "GZip Payload Obfuscation",
    r"xor": "XOR Payload Obfuscation",
    r"rot13": "ROT13 Encoding/Obfuscation",
    r"invoke-obfuscation": "Invoke-Obfuscation (MITRE: T1027)",
    r"char\[[0-9]{2,}\]": "Character Array String Obfuscation",
    r"\$\w{8,}\s*=": "Randomized Variable Names (MITRE: T1027)",

    # === LOLSCRIPTING / COM ABUSE ===
    r"wscript\.shell": "WScript Shell Execution (MITRE: T1059.005)",
    r"cscript\.exe.*//e:vbscript": "Cscript VBScript Execution (MITRE: T1059.005)",
    r"mshta.*http": "MSHTA Remote HTA Execution (MITRE: T1218.005)",
    r"mshta.*vbscript": "MSHTA VBScript Execution",
    r"mshta.*javascript": "MSHTA JavaScript Execution",
    r"createobject": "WScript COM Object Abuse (MITRE: T1059.005)",
    r"powershell\.exe.*wscript": "PowerShell spawning WScript",

    # === EXFIL / NETWORK ABUSE ===
    r"curl.*-d": "curl Data Exfiltration (MITRE: T1041)",
    r"powershell.*invoke-restmethod.*post": "PowerShell HTTP Exfiltration (MITRE: T1041)",
    r"scp .*@": "SCP Data Exfiltration (MITRE: T1041)",
    r"nc .* -e": "Netcat Reverse Shell (MITRE: T1059.004)",
    r"nc.*-lvp": "Netcat Listener",
    r"socat.*tcp": "Socat Reverse Shell",
    r"python.*-c.*socket": "Python Reverse Shell",
    r"bash.*\/dev\/tcp": "Bash TCP Reverse Shell (MITRE: T1059.004)",

    # === PERSISTENCE ===
    r"schtasks.*create": "Scheduled Task Creation (MITRE: T1053.005)",
    r"reg add .*run": "Registry Run Key Persistence (MITRE: T1547.001)",
    r"reg add .*runonce": "RunOnce Persistence",
    r"powershell.*new-scheduledtask": "PowerShell Scheduled Task (MITRE: T1053.005)",
    r"wmic.*startup": "WMIC Startup Persistence",

    # === PRIVILEGE ESCALATION ===
    r"icacls.*grant": "ICACLS Permission Abuse (MITRE: T1222)",
    r"takeown": "TakeOwn Privilege Manipulation (MITRE: T1222)",
    r"secedit": "Security Policy Manipulation",
    r"psexec": "PsExec Lateral Movement (MITRE: T1570)",
    r"runas .*": "runas Privilege Escalation Attempt",

    # === DEFENSE EVASION ===
    r"taskkill.*\/f.*defender": "Attempt to Kill Defender (MITRE: T1562.001)",
    r"taskkill.*\/f.*av": "Attempt to Kill AV",
    r"add-mppreference.*exclusion": "Defender Exclusion Added (MITRE: T1562.001)",
    r"reg add .*policies\\microsoft\\windows defender": "Modify Defender Registry (MITRE: T1562.001)",
    r"bcdedit.*disable": "OS Boot Security Modification (MITRE: T1542)",

    # === RANSOMWARE-STYLE ARTIFACTS ===
    r"vssadmin.*delete": "Volume Shadow Copy Deletion (MITRE: T1490)",
    r"cipher.exe.*\/w": "Drive Wiping Attempt (MITRE: T1485)",
    r"takeown.*\/r": "Mass File Ownership Takeover",

    # === LATERAL MOVEMENT ===
    r"wmic.*process call": "WMIC Remote Command Execution (MITRE: T1047)",
    r"psexec.*\\\\": "PsExec Lateral Movement (MITRE: T1570)",
    r"winrs": "WinRM Remote Exec (MITRE: T1021)",
    r"ssh .*@": "SSH Lateral Movement",
}


def extract_iocs(cmd):
    urls = re.findall(r'(https?://[^\s"\']+)', cmd)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', cmd)

    domains = []
    for u in urls:
        parsed = urlparse(u)
        if parsed.hostname:
            domains.append(parsed.hostname)

    return type("IOCs", (object,), {
        "urls": urls if urls else None,
        "ips": ips if ips else None,
        "domains": domains if domains else None,
    })()


def classify(cmd):
    findings = []
    for pattern, description in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, cmd, re.IGNORECASE):
            findings.append(f"[!] {description}")

    if not findings:
        return None, "Benign — No malicious indicators found."

    return "\n".join(findings), "Suspicious — Command contains high-risk indicators."


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cmd = request.form["cmdline"]

        findings, verdict = classify(cmd)
        iocs = extract_iocs(cmd)

        if not findings:
            findings = "No suspicious patterns detected."

        return render_template_string(
            HTML_PAGE,
            result=findings,
            verdict=verdict,
            input_cmd=cmd,
            iocs=iocs
        )

    return render_template_string(HTML_PAGE)


if __name__ == "__main__":
    app.run(debug=True)
