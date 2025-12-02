DETECTIONS = {


    # POWERHELL / POWERSHELL ABUSE
    
    r"powershell.*-enc": {
        "family": "PowerShell Abuse",
        "technique": "EncodedCommand",
        "mitre": "T1059.001",
        "description": "Base64‑encoded PowerShell used for obfuscation."
    },
    r"powershell.*-encodedcommand": {
        "family": "PowerShell Abuse",
        "technique": "EncodedCommand",
        "mitre": "T1059.001",
        "description": "Explicit encoded payload execution."
    },
    r"powershell.*iex": {
        "family": "PowerShell Abuse",
        "technique": "Invoke-Expression Abuse",
        "mitre": "T1059.001",
        "description": "Runs dynamically constructed or remote-loaded PowerShell code."
    },
    r"powershell.*bypass": {
        "family": "PowerShell Abuse",
        "technique": "Execution Policy Bypass",
        "mitre": "T1059.001",
        "description": "Disables script execution policy for malicious code."
    },
    r"powershell.*-nop": {
        "family": "PowerShell Abuse",
        "technique": "NoProfile Execution",
        "mitre": "T1059.001",
        "description": "Stealth execution without loading user environment."
    },
    r"powershell.*hidden": {
        "family": "PowerShell Abuse",
        "technique": "Hidden Window Execution",
        "mitre": "T1059.001",
        "description": "Executes PowerShell invisibly to the user."
    },
    r"powershell.*invoke-webrequest": {
        "family": "PowerShell Abuse",
        "technique": "Remote Payload Download",
        "mitre": "T1105",
        "description": "Downloads files or payloads over HTTP."
    },
    r"powershell.*invoke-restmethod": {
        "family": "PowerShell Abuse",
        "technique": "Remote Payload Download",
        "mitre": "T1105",
        "description": "REST-based remote script or payload retrieval."
    },
    r"powershell.*downloadstring": {
        "family": "PowerShell Abuse",
        "technique": "Fileless Execution",
        "mitre": "T1105",
        "description": "Executes downloaded script directly in memory."
    },
    r"powershell.*new-object.*downloadfile": {
        "family": "PowerShell Abuse",
        "technique": "Payload Download",
        "mitre": "T1105",
        "description": "Downloads remote payloads using .NET WebClient."
    },
    r"powershell.*add-type.*kernel32": {
        "family": "PowerShell Abuse",
        "technique": "Process Injection",
        "mitre": "T1055",
        "description": "PowerShell loading Win32 APIs for injection."
    },
    r"powershell.*add-type.*-memberdefinition": {
        "family": "PowerShell Abuse",
        "technique": "Inline C# Compilation",
        "mitre": "T1059.001",
        "description": "Compiles and executes C# payloads in memory."
    },
    r"powershell.*reflection.assembly": {
        "family": "PowerShell Abuse",
        "technique": "Reflective Assembly Loading",
        "mitre": "T1027.004",
        "description": "Loads .NET assemblies directly in memory."
    },
    r"amsiutils\.amsiinitfailed": {
        "family": "Defense Evasion",
        "technique": "AMSI Patch",
        "mitre": "T1562.001",
        "description": "Patches AMSI in memory to disable scanning."
    },
    r"Disable-Transcript": {
        "family": "Defense Evasion",
        "technique": "Logging Disable",
        "mitre": "T1562.002",
        "description": "Attempts to disable PowerShell transcription logging."
    },
    r"powershell.*NoLog": {
        "family": "Defense Evasion",
        "technique": "Logging Bypass",
        "mitre": "T1562.002",
        "description": "Disables PowerShell logging features."
    },
    r"invoke-mimikatz": {
        "family": "Credential Access",
        "technique": "Credential Dumping",
        "mitre": "T1003",
        "description": "PowerShell-based credential theft tool."
    },

    
    # LOLBINS

    r"certutil.*-urlcache": {
        "family": "LOLBIN Abuse",
        "technique": "Malicious File Download",
        "mitre": "T1105",
        "description": "Downloads payloads using certutil."
    },
    r"certutil.*-decode": {
        "family": "LOLBIN Abuse",
        "technique": "Payload Decode",
        "mitre": "T1140",
        "description": "Decodes encoded malware."
    },
    r"mshta.*http": {
        "family": "LOLBIN Abuse",
        "technique": "Remote Script Execution",
        "mitre": "T1218.005",
        "description": "Executes remote HTA or JS/VBS scripts."
    },
    r"mshta.*vbscript": {
        "family": "LOLBIN Abuse",
        "technique": "Script Execution",
        "mitre": "T1218.005",
        "description": "HTA execution of VBScript payload."
    },
    r"regsvr32.*scrobj.dll": {
        "family": "LOLBIN Abuse",
        "technique": "COM Scriptlet Execution",
        "mitre": "T1218.010",
        "description": "Executes remote scriptlets."
    },
    r"rundll32.*javascript": {
        "family": "LOLBIN Abuse",
        "technique": "Script Execution via Rundll32",
        "mitre": "T1218.011",
        "description": "Executes JS through DLL runner."
    },
    r"rundll32.*shell32.dll,ShellExec_RunDLL": {
        "family": "LOLBIN Abuse",
        "technique": "ShellExec Abuse",
        "mitre": "T1218.011",
        "description": "Executes malicious files under trusted DLL context."
    },
    r"msiexec.*http": {
        "family": "LOLBIN Abuse",
        "technique": "Remote MSI Execution",
        "mitre": "T1218.007",
        "description": "Installs remote MSI payload."
    },
    r"bitsadmin.*transfer": {
        "family": "LOLBIN Abuse",
        "technique": "BITS Download",
        "mitre": "T1105",
        "description": "BITS used for stealthy payload downloading."
    },
    r"wmic.*process.*call.*create": {
        "family": "LOLBIN Abuse",
        "technique": "WMI Execution",
        "mitre": "T1047",
        "description": "Executes commands remotely via WMI."
    },
    r"installutil.*\.exe": {
        "family": "LOLBIN Abuse",
        "technique": "InstallUtil Execution",
        "mitre": "T1218.004",
        "description": "Executes .NET payloads using InstallUtil."
    },
    r"presentationhost\.exe.*\.xaml": {
        "family": "LOLBIN Abuse",
        "technique": "XAML Payload Execution",
        "mitre": "T1218.005",
        "description": "Executes XAML-based payloads."
    },
    r"msbuild.*\.xml": {
        "family": "LOLBIN Abuse",
        "technique": "Malicious Build Execution",
        "mitre": "T1127",
        "description": "Executes payloads embedded in MSBuild project files."
    },
    r"at.exe.*run": {
        "family": "LOLBIN Abuse",
        "technique": "Legacy Scheduled Task Execution",
        "mitre": "T1053",
        "description": "Uses AT.exe for persistence or remote execution."
    },

    
    # OBFUSCATION
    
    r"base64": {
        "family": "Obfuscation",
        "technique": "Base64 Encoding",
        "mitre": "T1027",
        "description": "Typically indicates encoded payload transport."
    },
    r"frombase64string": {
        "family": "Obfuscation",
        "technique": "Base64 Decode",
        "mitre": "T1027",
        "description": "Decodes encoded data into executable form."
    },
    r"xor": {
        "family": "Obfuscation",
        "technique": "XOR Encoding",
        "mitre": "T1027",
        "description": "Used commonly in malware to obfuscate payloads."
    },
    r"gzipstream": {
        "family": "Obfuscation",
        "technique": "Compressed Payload",
        "mitre": "T1027",
        "description": "Compressed malicious payload execution."
    },
    r"String\.Concat": {
        "family": "Obfuscation",
        "technique": "String Splitting",
        "mitre": "T1027",
        "description": "Obfuscates malicious command strings."
    },
    r"\\x[0-9a-fA-F]{2}": {
        "family": "Obfuscation",
        "technique": "Hex Encoding",
        "mitre": "T1027",
        "description": "Hex-encoded payload or code."
    },
    r"System.Management.Automation.Language": {
        "family": "Obfuscation",
        "technique": "AST Manipulation",
        "mitre": "T1027",
        "description": "PowerShell AST-based obfuscation indicators."
    },
    r"\$O00O00O0|^O0O0O0O": {
        "family": "Obfuscation",
        "technique": "Invoke-Obfuscation",
        "mitre": "T1027",
        "description": "Patterns from Invoke‑Obfuscation framework."
    },


    # PERSISTENCE

    r"schtasks.*create": {
        "family": "Persistence",
        "technique": "Scheduled Task",
        "mitre": "T1053.005",
        "description": "Creates scheduled tasks to maintain persistence."
    },
    r"reg add .*run": {
        "family": "Persistence",
        "technique": "Registry Run Key",
        "mitre": "T1547.001",
        "description": "Adds autorun registry key for persistence."
    },
    r"wmic.*startup": {
        "family": "Persistence",
        "technique": "WMI Startup Event",
        "mitre": "T1546.003",
        "description": "Uses WMI event subscriptions for persistence."
    },
    r"powershell.*new-scheduledtaskaction": {
        "family": "Persistence",
        "technique": "PowerShell Task Persistence",
        "mitre": "T1053",
        "description": "Creates persistent scheduled task via PowerShell."
    },
    r"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup": {
        "family": "Persistence",
        "technique": "Startup Folder Persistence",
        "mitre": "T1547.001",
        "description": "Adds files to Windows Startup folder."
    },
    r"sc.exe.*create": {
        "family": "Persistence",
        "technique": "Service Creation",
        "mitre": "T1543.003",
        "description": "Creates Windows service for persistence."
    },


    # PRIVILEGE ESCALATION

    r"net localgroup administrators .*add": {
        "family": "Privilege Escalation",
        "technique": "Admin Group Modification",
        "mitre": "T1068",
        "description": "Adds attacker-controlled admin account."
    },
    r"icacls .*grant .*f": {
        "family": "Privilege Escalation",
        "technique": "File Permission Manipulation",
        "mitre": "T1222",
        "description": "Grants full permissions to attacker."
    },
    r"Invoke-TokenManipulation": {
        "family": "Privilege Escalation",
        "technique": "Token Impersonation",
        "mitre": "T1134",
        "description": "Attempts to impersonate or elevate using tokens."
    },
    r"fodhelper\.exe": {
        "family": "Privilege Escalation",
        "technique": "UAC Bypass",
        "mitre": "T1548.002",
        "description": "UAC bypass via Fodhelper technique."
    },
    r"cmstp\.exe": {
        "family": "Privilege Escalation",
        "technique": "UAC Bypass",
        "mitre": "T1548.002",
        "description": "UAC bypass using CMSTP INF execution."
    },

    
    # DEFENSE EVASION
    
    r"taskkill.*defender": {
        "family": "Defense Evasion",
        "technique": "Security Tool Termination",
        "mitre": "T1562.001",
        "description": "Attempts to kill Windows Defender."
    },
    r"netsh advfirewall.*off": {
        "family": "Defense Evasion",
        "technique": "Firewall Disable",
        "mitre": "T1562.004",
        "description": "Disables firewall to reduce detection."
    },
    r"attrib \+h \+s": {
        "family": "Defense Evasion",
        "technique": "Hidden File Creation",
        "mitre": "T1564.001",
        "description": "Marks malicious files as hidden/system."
    },
    r"powershell.*amsiutils": {
        "family": "Defense Evasion",
        "technique": "AMSI Bypass",
        "mitre": "T1562.001",
        "description": "Attempts to disable AMSI scanning."
    },
    r"reg add .*\\Amsi": {
        "family": "Defense Evasion",
        "technique": "AMSI Tampering",
        "mitre": "T1562.001",
        "description": "Modifies AMSI registry keys to bypass scanning."
    },
    r"CreateRemoteThread": {
        "family": "Defense Evasion",
        "technique": "Process Injection",
        "mitre": "T1055",
        "description": "Process injection via remote thread creation."
    },


    # LATERAL MOVEMENT

    r"psexec.*\\\\": {
        "family": "Lateral Movement",
        "technique": "PsExec Remote Execution",
        "mitre": "T1570",
        "description": "Executes commands on remote systems."
    },
    r"wmic.*process call create": {
        "family": "Lateral Movement",
        "technique": "WMI Execution",
        "mitre": "T1047",
        "description": "Executes remote process via WMI."
    },
    r"ssh .*@": {
        "family": "Lateral Movement",
        "technique": "SSH Remote Access",
        "mitre": "T1021.004",
        "description": "Establishes SSH session to remote host."
    },
    r"net use \\\\": {
        "family": "Lateral Movement",
        "technique": "SMB Session",
        "mitre": "T1021.002",
        "description": "Mounts SMB shares for lateral movement."
    },
    r"winrm.*invoke": {
        "family": "Lateral Movement",
        "technique": "WinRM Remote Execution",
        "mitre": "T1021.006",
        "description": "Remote execution via Windows Remote Management."
    },
    r"crackmapexec": {
        "family": "Lateral Movement",
        "technique": "Offensive Tooling",
        "mitre": "T1550",
        "description": "Use of CrackMapExec for lateral movement or credential abuse."
    },


    # RECON / DISCOVERY
    
    r"whoami.*priv": {
        "family": "Reconnaissance",
        "technique": "Permission Discovery",
        "mitre": "T1069",
        "description": "Enumerates user privileges."
    },
    r"net user .*add": {
        "family": "Account Manipulation",
        "technique": "Account Creation",
        "mitre": "T1136",
        "description": "Creates new persistence accounts."
    },
    r"nltest.*dclist": {
        "family": "Reconnaissance",
        "technique": "Domain Discovery",
        "mitre": "T1087",
        "description": "Enumerates domain controllers."
    },
    r"ipconfig.*all": {
        "family": "Reconnaissance",
        "technique": "Network Discovery",
        "mitre": "T1016",
        "description": "Collects local network configuration."
    },
    r"netstat.*-an": {
        "family": "Reconnaissance",
        "technique": "Port/Connection Discovery",
        "mitre": "T1049",
        "description": "Identifies active network connections."
    },
    r"dsquery": {
        "family": "Reconnaissance",
        "technique": "Active Directory Query",
        "mitre": "T1087.002",
        "description": "Queries domain directory for objects."
    },
    r"bloodhound": {
        "family": "Reconnaissance",
        "technique": "AD Mapping",
        "mitre": "T1069",
        "description": "Extracts Active Directory structure and relationships."
    },
    r"procdump.*lsass": {
        "family": "Credential Access",
        "technique": "LSASS Dumping",
        "mitre": "T1003.001",
        "description": "Attempts to dump LSASS memory."
    },


    # EXFILTRATION

    r".*ftp.*put": {
        "family": "Exfiltration",
        "technique": "FTP Exfil",
        "mitre": "T1048",
        "description": "Possible data exfiltration via FTP PUT."
    },
    r"curl.*--upload-file": {
        "family": "Exfiltration",
        "technique": "HTTP Exfil",
        "mitre": "T1041",
        "description": "Uploads files to remote servers via HTTP."
    },


    # DATA DESTRUCTION / RANSOMWARE

    r"vssadmin.*delete shadows": {
        "family": "Ransomware Activity",
        "technique": "Shadow Copy Deletion",
        "mitre": "T1490",
        "description": "Eliminates restore points before encryption."
    },
    r"wmic.*shadowcopy.*delete": {
        "family": "Ransomware Activity",
        "technique": "Shadow Copy Deletion",
        "mitre": "T1490",
        "description": "Deletes shadow copies via WMI."
    },
    r"bcdedit.*recoveryenabled no": {
        "family": "Ransomware Activity",
        "technique": "Recovery Disable",
        "mitre": "T1490",
        "description": "Disables Windows recovery to prevent rollback."
    },
    r"cipher.*\/w:": {
        "family": "Data Destruction",
        "technique": "Secure Wipe",
        "mitre": "T1485",
        "description": "Wipes free space to prevent forensic recovery."
    },


# SUSPICIOUS EXECUTION

r"cmd\.exe.*\/c.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "Direct EXE Launch",
    "mitre": "T1059",
    "description": "Direct execution of an executable via cmd.exe."
},

r"cmd\.exe.*\/c.*powershell": {
    "family": "Suspicious Execution",
    "technique": "Chained Execution",
    "mitre": "T1059",
    "description": "Execution chaining from cmd → PowerShell, often seen in staged malware."
},

r"psexec\.exe": {
    "family": "Suspicious Execution",
    "technique": "Remote Execution Tool",
    "mitre": "T1570",
    "description": "PsExec launched; commonly used for lateral movement."
},

r"^.*\\temp\\.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "Execution from Temp Directory",
    "mitre": "T1204",
    "description": "Executable launched from Temp directory — common malware staging location."
},

r"^.*\\appdata\\.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "Execution from AppData",
    "mitre": "T1204",
    "description": "Executable launched from AppData — common persistence location."
},

r"^.*\\downloads\\.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "Execution from Downloads",
    "mitre": "T1204",
    "description": "User downloaded binary executed — often abused in phishing delivery."
},

r"^.*\\programdata\\.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "Execution from ProgramData",
    "mitre": "T1204",
    "description": "ProgramData used for stealth payload storage and execution."
},

r"mshta\.exe": {
    "family": "Suspicious Execution",
    "technique": "HTML Application Execution",
    "mitre": "T1218.005",
    "description": "Execution of mshta.exe — often abused for running malicious HTA payloads."
},

r"rundll32\.exe.*\.js": {
    "family": "Suspicious Execution",
    "technique": "Script Execution via Rundll32",
    "mitre": "T1218.011",
    "description": "JavaScript executed via rundll32 — strongly suspicious behavior."
},

r"wscript\.exe.*\.js": {
    "family": "Suspicious Execution",
    "technique": "Script Execution",
    "mitre": "T1059.007",
    "description": "JScript executed via WScript — common malware method."
},

r"cscript\.exe.*\.vbs": {
    "family": "Suspicious Execution",
    "technique": "Script Execution",
    "mitre": "T1059.005",
    "description": "VBS launched through CScript — often abused in phishing attacks."
},

r"powershell\.exe.*-command.*\.exe": {
    "family": "Suspicious Execution",
    "technique": "PowerShell Launching EXE",
    "mitre": "T1059.001",
    "description": "PowerShell launching a native EXE — indicative of loader behavior."
},


# SCRIPT INTERPRETER EXECUTION

r"powershell(\.exe)?\s+.*\.ps1": {
    "family": "Script Execution",
    "technique": "PowerShell Script Launch",
    "mitre": "T1059.001",
    "description": "PowerShell executing a .ps1 script file."
},

r"powershell(\.exe)?\s+-enc\s+": {
    "family": "Script Execution",
    "technique": "Encoded Command",
    "mitre": "T1059.001",
    "description": "PowerShell launched with encoded command — common obfuscation technique."
},

r"cscript(\.exe)?\s+.*\.(vbs|js|jse|vbe|wsf|wsc)": {
    "family": "Script Execution",
    "technique": "Windows Script Host",
    "mitre": "T1059.005",
    "description": "cscript.exe executing VBS/JS/WSH scripts — often abused by malware."
},

r"wscript(\.exe)?\s+.*\.(vbs|js|jse|vbe|wsf|wsc)": {
    "family": "Script Execution",
    "technique": "Windows Script Host",
    "mitre": "T1059.005",
    "description": "wscript.exe executing VBS/JS scripts — common malware dropper method."
},

r"mshta(\.exe)?\s+.*\.hta": {
    "family": "Script Execution",
    "technique": "HTA Execution",
    "mitre": "T1218.005",
    "description": "Execution of HTA files via mshta.exe — often used for code execution."
},

r"mshta(\.exe)?\s+http": {
    "family": "Script Execution",
    "technique": "Remote HTA Execution",
    "mitre": "T1218.005",
    "description": "mshta.exe executing remote HTA payload — strongly associated with malware."
},

r"wmic(\.exe)?\s+process\s+call\s+create": {
    "family": "Script Execution",
    "technique": "WMIC Execution",
    "mitre": "T1047",
    "description": "WMIC used for remote or local process creation — suspicious in modern Windows."
},

r"rundll32(\.exe)?\s+.*\.js": {
    "family": "Script Execution",
    "technique": "Script Execution via DLL Loader",
    "mitre": "T1218.011",
    "description": "Attempt to execute script content via rundll32 — abnormal and malicious."
},

r"rundll32(\.exe)?\s+.*\.vbs": {
    "family": "Script Execution",
    "technique": "Script Execution via DLL Loader",
    "mitre": "T1218.011",
    "description": "Execution of VBS via rundll32 — an evasion tactic."
},

r"cmd\.exe.*\/c.*\.ps1": {
    "family": "Script Execution",
    "technique": "Script Launch via CMD",
    "mitre": "T1059",
    "description": "PowerShell script launched through cmd.exe."
},

r"cmd\.exe.*\/c.*\.(vbs|js)": {
    "family": "Script Execution",
    "technique": "Script Launch via CMD",
    "mitre": "T1059",
    "description": "VBS/JS script launched using cmd.exe."
}

}