# classifier.py
import re
from rules import DETECTIONS  # make sure your rules.py file contains DETECTIONS

def classify_command(cmd):
    findings = []
    families_triggered = set()

    for pattern, meta in DETECTIONS.items():
        if re.search(pattern, cmd, re.IGNORECASE):
            families_triggered.add(meta["family"])
            findings.append(
                f"[{meta['family']}] {meta['technique']} ({meta['mitre']}): {meta['description']}"
            )

    summary = f"Indicators found: {len(findings)}"

    if not findings:
        return None, "Benign — No malicious indicators found.", summary

    # Build verdict lines based on families
    verdict_lines = ["[Suspicious]"]

    if "PowerShell Abuse" in families_triggered:
        verdict_lines.append("Suspicious PowerShell behavior detected")

    if "Obfuscation" in families_triggered:
        verdict_lines.append("Obfuscated content found")

    if "Persistence" in families_triggered:
        verdict_lines.append("Indicators of persistence detected")

    if "Privilege Escalation" in families_triggered:
        verdict_lines.append("Potential privilege escalation behavior detected")

    if "Defense Evasion" in families_triggered:
        verdict_lines.append("Possible attempts to evade defenses")

    if "Lateral Movement" in families_triggered:
        verdict_lines.append("Potential lateral movement activity detected")

    if "Reconnaissance" in families_triggered:
        verdict_lines.append("Reconnaissance or information gathering detected")

    if "Account Manipulation" in families_triggered:
        verdict_lines.append("User or account manipulation detected")

    if "Data Destruction" in families_triggered:
        verdict_lines.append("Indicators of destructive activity detected")

    if "Ransomware Activity" in families_triggered:
        verdict_lines.append("Indicators of ransomware activity detected")

    if "Credential Access" in families_triggered:
        verdict_lines.append("Suspicious credential access or dumping detected")

    if "LOLBIN Abuse" in families_triggered:
        verdict_lines.append("Suspicious use of living-off-the-land binaries detected")

    if "Exfiltration" in families_triggered:
        verdict_lines.append("Potential data exfiltration activity detected")

    if "Suspicious Execution" in families_triggered:
        verdict_lines.append("Suspicious execution behavior detected")

    if "Script Execution" in families_triggered:
        verdict_lines.append("Suspicious script interpreter usage detected")

    verdict_output = "\n\n".join(verdict_lines)

    return "\n\n".join(findings), verdict_output, summary

