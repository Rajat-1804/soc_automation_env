import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Difficulty levels for curriculum learning
EASY = 1
MEDIUM = 2
HARD = 3
EXPERT = 4

DIFFICULTY_NAMES = {EASY: "EASY", MEDIUM: "MEDIUM", HARD: "HARD", EXPERT: "EXPERT"}


@dataclass
class Scenario:
    id: str
    attack_type: str
    is_real_threat: bool
    alert_text: str
    optimal_containment: str
    difficulty: int = EASY
    mitre_id: Optional[str] = None
    time_limit_mins: int = 20
    # The specific tool query keys that reveal meaningful evidence
    key_evidence_keys: List[str] = field(default_factory=list)
    logs_data: Dict[str, str] = field(default_factory=dict)
    threat_intel_data: Dict[str, str] = field(default_factory=dict)
    asset_inventory_data: Dict[str, str] = field(default_factory=dict)


def get_all_scenarios() -> List[Scenario]:
    return [

        # ─────────────────────────────────────────
        # EASY — Single tool reveals everything
        # ─────────────────────────────────────────
        Scenario(
            id="s1",
            difficulty=EASY,
            attack_type="credential_stuffing",
            is_real_threat=True,
            alert_text="Multiple failed login attempts detected for various user accounts from IP 192.168.1.101.",
            optimal_containment="block_ip",
            mitre_id="T1110",
            time_limit_mins=15,
            key_evidence_keys=["192.168.1.101"],
            logs_data={
                "192.168.1.101": "100+ failed login attempts across 50 different usernames in the last 10 minutes. 1 successful login for user 'jdoe'."
            },
            threat_intel_data={
                "192.168.1.101": "IP flagged for brute force attacks. Reputation: High Risk."
            },
            asset_inventory_data={
                "jdoe": "Jane Doe, HR Manager. Access to PII and payroll systems."
            }
        ),
        Scenario(
            id="s2",
            difficulty=EASY,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="High CPU utilization and suspicious script execution detected on Build-Server.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=15,
            key_evidence_keys=["Build-Server"],
            logs_data={
                "Build-Server": "Execution of compile_all.sh. CPU spiked to 100% for 30 minutes."
            },
            threat_intel_data={
                "compile_all.sh": "Standard build script."
            },
            asset_inventory_data={
                "Build-Server": "Jenkins build node. Expected behavior during nightly builds."
            }
        ),
        Scenario(
            id="s3",
            difficulty=EASY,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="Suspicious outbound network connection on port 53 (DNS) to non-standard server 8.8.8.8.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=15,
            key_evidence_keys=["8.8.8.8"],
            logs_data={
                "192.168.1.50": "A large number of DNS queries to Google Public DNS server."
            },
            threat_intel_data={
                "8.8.8.8": "Google Public DNS. Safe.",
                "192.168.1.50": "Internal guest Wi-Fi subnet."
            },
            asset_inventory_data={
                "192.168.1.50": "Guest network range."
            }
        ),
        Scenario(
            id="s16",
            difficulty=EASY,
            attack_type="unauthorized_access",
            is_real_threat=True,
            alert_text="Firewall denied 500+ connection attempts to internal database DB-Serv-01 on port 1433 from external IP 203.0.113.88.",
            optimal_containment="block_ip",
            mitre_id="T1190",
            time_limit_mins=15,
            key_evidence_keys=["203.0.113.88"],
            logs_data={
                "203.0.113.88": "Continuous SYN sweep on port 1433 over the last hour. No auth success yet."
            },
            threat_intel_data={
                "203.0.113.88": "Known scanning IP from bulletproof hosting provider."
            },
            asset_inventory_data={
                "DB-Serv-01": "Internal database. Should not be internet-accessible."
            }
        ),
        Scenario(
            id="s17",
            difficulty=EASY,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="Antivirus quarantined 'updates.exe' on Employee-Laptop-12 for generic heuristic.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=15,
            key_evidence_keys=["updates.exe"],
            logs_data={
                "Employee-Laptop-12": "'updates.exe' executed from C:\\Program Files\\InternalApp\\. Quarantined by AV."
            },
            threat_intel_data={
                "updates.exe": "Hash matches officially signed binary from internal development team."
            },
            asset_inventory_data={
                "Employee-Laptop-12": "Standard developer machine."
            }
        ),

        # ─────────────────────────────────────────
        # MEDIUM — 2–3 targeted queries needed
        # ─────────────────────────────────────────
        Scenario(
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
            }
        ),
        Scenario(
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
            }
        ),
        Scenario(
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
            }
        ),
        Scenario(
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
            }
        ),
        Scenario(
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
                "Marketing-PC": "Rclone utility spawned by unapproved script. Uploading C:\\Confidential\\ to external Drive.",
                "drive.google.com": "20GB transferred in 10 minutes."
            },
            threat_intel_data={
                "Marketing-PC": "Standard workstation. Corporate policy forbids external unauthorized cloud storage.",
                "drive.google.com": "Legitimate service, often abused for exfiltration."
            },
            asset_inventory_data={
                "Marketing-PC": "Workstation belonging to a recently terminated employee.",
            }
        ),
        Scenario(
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
            }
        ),

        # ─────────────────────────────────────────
        # HARD — Multi-vector, red herrings
        # ─────────────────────────────────────────
        Scenario(
            id="s8",
            difficulty=HARD,
            attack_type="ransomware_staging",
            is_real_threat=True,
            alert_text="AV alert: Suspicious execution of vssadmin.exe (shadow copy deletion) on DB-Serv-01.",
            optimal_containment="isolate_machine",
            mitre_id="T1486",
            time_limit_mins=15,
            key_evidence_keys=["DB-Serv-01", "45.33.22.11"],
            logs_data={
                "DB-Serv-01": "vssadmin.exe delete shadows /all /quiet executed. Unexpected outbound connections to 45.33.22.11 on port 443.",
                "45.33.22.11": "Connection established 3 times in 10 minutes. ~2MB data transferred outbound."
            },
            threat_intel_data={
                "45.33.22.11": "Known command and control (C2) server associated with LockBit ransomware group.",
                "DB-Serv-01": "Internal server — no external IP."
            },
            asset_inventory_data={
                "DB-Serv-01": "Primary production database server. Criticality: Very High. Contains customer PII."
            }
        ),
        Scenario(
            id="s9",
            difficulty=HARD,
            attack_type="data_exfiltration",
            is_real_threat=True,
            alert_text="High volume outbound traffic (50GB+) detected over port 443 from Dev-Server to unknown IP 188.4.5.6.",
            optimal_containment="block_ip",
            mitre_id="T1048",
            time_limit_mins=20,
            key_evidence_keys=["Dev-Server", "188.4.5.6"],
            logs_data={
                "Dev-Server": "Rclone utility executed with destination set to Mega cloud storage.",
                "188.4.5.6": "Continuous high-bandwidth stream over HTTPS for the last 3 hours."
            },
            threat_intel_data={
                "188.4.5.6": "IP belongs to a commercial cloud storage provider (Mega). Frequently abused for exfiltration.",
                "203.0.113.5": "Red herring — routine CDN IP used by internal dashboard."  # Red herring
            },
            asset_inventory_data={
                "Dev-Server": "Development server containing source code repositories. Criticality: High.",
                "203.0.113.5": "Akamai CDN endpoint — expected traffic."  # Red herring
            }
        ),
        Scenario(
            id="s10",
            difficulty=HARD,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="EDR alert: Unusual parent-child process relationship. cmd.exe spawned by Excel.exe on CFO-Laptop.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=25,
            key_evidence_keys=["CFO-Laptop", "Excel.exe"],
            logs_data={
                "CFO-Laptop": "Excel macro executed: ExportQuarterlyReport.xlsm. Called external script to generate PDF via cmd.exe.",
                "Excel.exe": "Signed Microsoft binary. Macro execution rate normal for this user."
            },
            threat_intel_data={
                "ExportQuarterlyReport.xlsm": "File present on SharePoint since Q3 2023. No modifications in 6 months.",
                "CFO-Laptop": "Standard workstation. User known to use automated Excel reports."
            },
            asset_inventory_data={
                "CFO-Laptop": "Laptop belonging to CFO. High-value target. macros enabled by IT per business request."
            }
        ),
        Scenario(
            id="s20",
            difficulty=HARD,
            attack_type="credential_access",
            is_real_threat=True,
            alert_text="Multiple Kerberos TGS-REQ tickets requested for Service Principal Names (Kerberoasting) from Dev-WS.",
            optimal_containment="isolate_machine",
            mitre_id="T1558",
            time_limit_mins=20,
            key_evidence_keys=["Dev-WS"],
            logs_data={
                "Dev-WS": "User 'rdev' requested 50+ TGS service tickets for various high-privileged service accounts. Extracted tickets saved to local file.",
                "rdev": "Account authenticated normally 1 hour ago."
            },
            threat_intel_data={
                "Dev-WS": "Internal workstation."
            },
            asset_inventory_data={
                "Dev-WS": "Developer workstation.",
                "rdev": "Junior developer. Should not be enumerating service accounts."
            }
        ),
        Scenario(
            id="s21",
            difficulty=HARD,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="Massive number of SQL injection attempts detected against DB-Prod by internal IP 10.0.0.55.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=20,
            key_evidence_keys=["10.0.0.55", "DB-Prod"],
            logs_data={
                "10.0.0.55": "Nmap and sqlmap signatures detected originating from this IP targeting the database subnet.",
                "DB-Prod": "Countless failed SQL queries logged. No unauthorized data access observed."
            },
            threat_intel_data={
                "10.0.0.55": "Internal IP. Known scanning subnet."
            },
            asset_inventory_data={
                "10.0.0.55": "Qualys vulnerability scanner appliance. Scheduled scans occur weekly.",
                "DB-Prod": "Production database."
            }
        ),

        # ─────────────────────────────────────────
        # EXPERT — APT-style, misleading evidence
        # ─────────────────────────────────────────
        Scenario(
            id="s11",
            difficulty=EXPERT,
            attack_type="supply_chain_attack",
            is_real_threat=True,
            alert_text="Integrity check failed for vendor library 'libpayment-sdk v2.3.1' on Payment-API-Server. Checksum mismatch.",
            optimal_containment="isolate_machine",
            mitre_id="T1195",
            time_limit_mins=30,
            key_evidence_keys=["libpayment-sdk", "Payment-API-Server", "45.77.91.200"],
            logs_data={
                "Payment-API-Server": "libpayment-sdk v2.3.1 loaded. Unexpected outbound HTTP POST to 45.77.91.200:8443. Card data patterns detected in payload.",
                "45.77.91.200": "3 POST requests in 24h. Payload size correlates with transaction volume.",
                "libpayment-sdk": "SHA256 mismatch vs official vendor manifest. Modified 3 weeks ago by 'vendor_update' svc account."
            },
            threat_intel_data={
                "45.77.91.200": "Newly registered IP. No reputation data. Geo: Eastern Europe.",
                "libpayment-sdk v2.3.1": "Official version released 4 months ago. Vendor confirms no updates in past 3 weeks."
            },
            asset_inventory_data={
                "Payment-API-Server": "Processes all card transactions. PCI-DSS scope. Criticality: Critical.",
                "vendor_update": "Shared service account used by vendor for deployments. Should only act during change windows."
            }
        ),
        Scenario(
            id="s12",
            difficulty=EXPERT,
            attack_type="insider_threat",
            is_real_threat=True,
            alert_text="DLP alert: Large batch download (8,000 files) from SharePoint by user 'rthomas' outside business hours.",
            optimal_containment="isolate_machine",
            mitre_id="T1048",
            time_limit_mins=25,
            key_evidence_keys=["rthomas", "SharePoint", "USB-001"],
            logs_data={
                "rthomas": "Downloaded 8,432 files between 01:00–03:30 AM. Files included IP docs, customer contracts, product roadmap.",
                "SharePoint": "Access pattern anomaly — 47x above baseline for this user.",
                "USB-001": "USB storage device registered to rthomas connected at 03:45 AM on same workstation."
            },
            threat_intel_data={
                "rthomas": "Internal user. No criminal record. Note: HR flagged resignation letter submitted yesterday.",
                "185.220.101.35": "Tor exit node — irrelevant to this incident, different user."  # Red herring
            },
            asset_inventory_data={
                "rthomas": "Rachel Thomas, Senior Product Manager. 8 years tenure. Submitted resignation yesterday. Last day in 2 weeks.",
                "USB-001": "USB device not in approved inventory. Policy violation."
            }
        ),
        Scenario(
            id="s13",
            difficulty=EXPERT,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="SIEM correlation rule triggered: 'APT Pattern — Multiple T1059 and T1071 MITRE techniques detected on ML-Training-Cluster-01 in 1 hour.'",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=25,
            key_evidence_keys=["ML-Training-Cluster-01", "python3", "curl"],
            logs_data={
                "ML-Training-Cluster-01": "Python training script spawned 64 child processes (normal for distributed training). curl used to fetch dataset from S3. Large outbound data transfer to S3 (model checkpoint upload).",
                "python3": "Signed binary. Command: python3 train_llm.py --nodes 64 --distributed.",
                "curl": "curl used for S3 presigned URL. Destination: company-ml-artifacts.s3.amazonaws.com."
            },
            threat_intel_data={
                "company-ml-artifacts.s3.amazonaws.com": "Legitimate company-owned AWS S3 bucket.",
                "ML-Training-Cluster-01": "Internal cluster. No external reputation data."
            },
            asset_inventory_data={
                "ML-Training-Cluster-01": "GPU training cluster. AI/ML team workload. Large-scale jobs scheduled weekly. Current job: LLM fine-tuning run approved by team lead."
            }
        ),
        Scenario(
            id="s14",
            difficulty=EXPERT,
            attack_type="zero_day_exploit",
            is_real_threat=True,
            alert_text="WAF alert: Unusual HTTP request pattern to /api/v1/users endpoint — unexpected binary payload in JSON field.",
            optimal_containment="isolate_machine",
            mitre_id="T1190",
            time_limit_mins=15,
            key_evidence_keys=["API-Gateway-01", "/api/v1/users", "10.10.5.200"],
            logs_data={
                "API-Gateway-01": "POST /api/v1/users — 'name' field contains base64-encoded shellcode. Java heap dump triggered on backend. Reverse shell observed from app server to 10.10.5.200:4444.",
                "/api/v1/users": "Endpoint should only accept ASCII. Deserialization library version: jackson-databind 2.9.8 (known CVE-2019-14540).",
                "10.10.5.200": "Outbound connection established. Interactive shell session detected. Commands executed: whoami, id, cat /etc/passwd."
            },
            threat_intel_data={
                "10.10.5.200": "Unknown external IP. Not in allowlist. Geo: Tor-associated datacenter.",
                "CVE-2019-14540": "Jackson-databind deserialization vulnerability. CVSS 9.8. Patch available."
            },
            asset_inventory_data={
                "API-Gateway-01": "Public-facing API gateway. Hosts customer-facing REST API. Criticality: Critical.",
                "Backend App Server": "Runs Java Spring application. Connects to customer database."
            }
        ),
        Scenario(
            id="s15",
            difficulty=EXPERT,
            attack_type="false_positive",
            is_real_threat=False,
            alert_text="UEBA alert: Domain Admin account 'da_deploy' performed 200+ WMI remote executions across the server fleet in 45 minutes.",
            optimal_containment="dismiss",
            mitre_id="None",
            time_limit_mins=25,
            key_evidence_keys=["da_deploy", "CMDB-Ticket-94821"],
            logs_data={
                "da_deploy": "Executed deployment script deploy_patch_kb5034441.ps1 via WMI on 212 servers.",
                "CMDB-Ticket-94821": "Approved change ticket: Emergency patch deployment for CVE-2024-21413. Authorized by CISO. Scheduled 02:00–05:00 AM."
            },
            threat_intel_data={
                "da_deploy": "Internal service account used exclusively for automated deployments. Normal pattern during patch windows.",
                "deploy_patch_kb5034441.ps1": "Script verified via code signing. SHA256 matches CMDB artifact."
            },
            asset_inventory_data={
                "da_deploy": "Domain Admin service account. Restricted to deployment automation tool. MFA enforced. Used exclusively by IT Ops pipeline.",
                "CMDB-Ticket-94821": "Change ticket in APPROVED state. Authorized emergency patch for Outlook RCE vulnerability."
            }
        ),
        Scenario(
            id="s22",
            difficulty=EXPERT,
            attack_type="cloud_compromise",
            is_real_threat=True,
            alert_text="AWS GuardDuty: Unusual IAM Role usage 'arn:aws:iam::123456789:role/DevOpsRole'. 20 new EC2 g4dn.xlarge instances launched in unexpected region (ap-southeast-1).",
            optimal_containment="password_reset",
            mitre_id="T1078",
            time_limit_mins=30,
            key_evidence_keys=["DevOpsRole", "ap-southeast-1"],
            logs_data={
                "DevOpsRole": "API call RunInstances executed via short-term credentials. Source IP: 185.33.22.11.",
                "185.33.22.11": "Not an AWS internal IP. Belongs to a proxy network.",
                "ap-southeast-1": "Region not normally used. Instances configured with crypto-miner AMIs."
            },
            threat_intel_data={
                "185.33.22.11": "Known anonymization VPN IP. Flagged for cryptojacking.",
                "DevOpsRole": "Role trusted by CI/CD pipeline."
            },
            asset_inventory_data={
                "DevOpsRole": "IAM Role for GitHub Actions. Contains administrative privileges.",
                "ap-southeast-1": "No operations in this region by policy."
            }
        ),
        Scenario(
            id="s23",
            difficulty=EXPERT,
            attack_type="supply_chain_attack",
            is_real_threat=True,
            alert_text="Unrecognized container image pushed to production registry 'corp-reg/frontend:latest' bypassing CI pipeline approvals.",
            optimal_containment="isolate_machine",
            mitre_id="T1195",
            time_limit_mins=30,
            key_evidence_keys=["corp-reg/frontend", "ci-build-node"],
            logs_data={
                "corp-reg/frontend:latest": "Image pushed with unauthorized backdoor process running alongside valid node app.",
                "ci-build-node": "GitLab runner compromised. An attacker modified the .gitlab-ci.yml file in the cache before build execution."
            },
            threat_intel_data={
                "corp-reg/frontend:latest": "Contains known malicious node packages (typosquatting).",
                "ci-build-node": "Exposed Docker daemon detected on host."
            },
            asset_inventory_data={
                "ci-build-node": "Build orchestration server. Has docker.sock mounted.",
                "corp-reg/frontend": "Main application frontend. Highly critical."
            }
        ),
    ]


def get_scenarios_by_difficulty(difficulty: int) -> List[Scenario]:
    """Return all scenarios at a given difficulty level."""
    return [s for s in get_all_scenarios() if s.difficulty == difficulty]


def get_curriculum_scenario(difficulty: int, seed: Optional[int] = None) -> Scenario:
    """
    Curriculum learning: return a scenario of the specified difficulty.
    Used to train the agent progressively from easy to expert.
    """
    pool = get_scenarios_by_difficulty(difficulty)
    if not pool:
        pool = get_all_scenarios()
    rng = random.Random(seed) if seed is not None else random
    return rng.choice(pool)


def get_random_scenario(seed: Optional[int] = None) -> Scenario:
    """
    Default random scenario. Maintains roughly 60% real threats, 40% false positives
    by drawing uniformly from all 15 scenarios.
    """
    rng = random.Random(seed) if seed is not None else random
    return rng.choice(get_all_scenarios())
