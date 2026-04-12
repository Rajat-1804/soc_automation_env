"""
Real SQLite-backed investigation database for each SOC episode.

Instead of returning hardcoded strings, each episode seeds an in-memory
SQLite database with realistic log records, asset entries, and threat intel.
Queries do actual SQL LIKE searches — results depend on what you query.
"""
from __future__ import annotations

import sqlite3
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class LogRecord:
    timestamp: str
    source_ip: str
    dest_ip: str
    event_type: str
    message: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    user: str = ""
    process: str = ""
    port: int = 0


@dataclass
class AssetRecord:
    hostname: str
    ip: str
    owner: str
    department: str
    criticality: str  # LOW / MEDIUM / HIGH / CRITICAL
    os: str
    notes: str
    known_safe: bool = False


@dataclass  
class ThreatIntelRecord:
    indicator: str        # IP / domain / hash / process name
    indicator_type: str   # ip / domain / hash / process
    reputation: str       # CLEAN / SUSPICIOUS / MALICIOUS
    confidence: int       # 0-100
    context: str
    mitre_techniques: str = ""


class EpisodeDatabase:
    """
    Per-episode in-memory SQLite database.
    
    Seeded with scenario-specific data plus realistic noise records.
    Queries do real SQL searches — agents must find the right evidence.
    """

    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                source_ip   TEXT NOT NULL,
                dest_ip     TEXT,
                event_type  TEXT,
                message     TEXT,
                severity    TEXT DEFAULT 'LOW',
                username    TEXT DEFAULT '',
                process     TEXT DEFAULT '',
                port        INTEGER DEFAULT 0
            );

            CREATE TABLE assets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname    TEXT NOT NULL,
                ip          TEXT NOT NULL,
                owner       TEXT,
                department  TEXT,
                criticality TEXT DEFAULT 'LOW',
                os          TEXT DEFAULT 'Windows 10',
                notes       TEXT DEFAULT '',
                known_safe  INTEGER DEFAULT 0
            );

            CREATE TABLE threat_intel (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator         TEXT NOT NULL,
                indicator_type    TEXT,
                reputation        TEXT DEFAULT 'CLEAN',
                confidence        INTEGER DEFAULT 50,
                context           TEXT DEFAULT '',
                mitre_techniques  TEXT DEFAULT ''
            );
        """)
        self.conn.commit()

    # ─── Seeding ────────────────────────────────────────────────

    def seed_logs(self, records: List[Dict[str, Any]]):
        cur = self.conn.cursor()
        for r in records:
            cur.execute("""
                INSERT INTO logs (timestamp, source_ip, dest_ip, event_type,
                                  message, severity, username, process, port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.get("timestamp", "2026-04-12T00:00:00Z"),
                r.get("source_ip", "0.0.0.0"),
                r.get("dest_ip", ""),
                r.get("event_type", "info"),
                r.get("message", ""),
                r.get("severity", "LOW"),
                r.get("username", ""),
                r.get("process", ""),
                r.get("port", 0),
            ))
        self.conn.commit()

    def seed_assets(self, records: List[Dict[str, Any]]):
        cur = self.conn.cursor()
        for r in records:
            cur.execute("""
                INSERT INTO assets (hostname, ip, owner, department, criticality,
                                    os, notes, known_safe)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.get("hostname", ""),
                r.get("ip", "0.0.0.0"),
                r.get("owner", "Unknown"),
                r.get("department", "Unknown"),
                r.get("criticality", "LOW"),
                r.get("os", "Windows 10"),
                r.get("notes", ""),
                1 if r.get("known_safe", False) else 0,
            ))
        self.conn.commit()

    def seed_threat_intel(self, records: List[Dict[str, Any]]):
        cur = self.conn.cursor()
        for r in records:
            cur.execute("""
                INSERT INTO threat_intel (indicator, indicator_type, reputation,
                                          confidence, context, mitre_techniques)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                r.get("indicator", ""),
                r.get("indicator_type", "ip"),
                r.get("reputation", "CLEAN"),
                r.get("confidence", 50),
                r.get("context", ""),
                r.get("mitre_techniques", ""),
            ))
        self.conn.commit()

    # ─── Query methods ───────────────────────────────────────────

    def query_logs(self, query: str) -> str:
        """Search logs for anything matching the query term."""
        cur = self.conn.cursor()
        pattern = f"%{query}%"
        cur.execute("""
            SELECT timestamp, source_ip, dest_ip, event_type, message,
                   severity, username, process, port
            FROM logs
            WHERE source_ip LIKE ?
               OR dest_ip    LIKE ?
               OR message    LIKE ?
               OR username   LIKE ?
               OR process    LIKE ?
            ORDER BY timestamp DESC
            LIMIT 20
        """, (pattern, pattern, pattern, pattern, pattern))
        rows = cur.fetchall()
        if not rows:
            return f"[LOGS] No log entries found matching '{query}'."
        
        lines = [f"[LOGS] Found {len(rows)} record(s) matching '{query}':"]
        for row in rows:
            line = (
                f"  [{row['timestamp']}] {row['severity']:8s} | "
                f"{row['source_ip']:>16} → {row['dest_ip'] or 'N/A':<16} | "
                f"{row['event_type']:20s} | {row['message']}"
            )
            if row["username"]:
                line += f" | user={row['username']}"
            if row["process"]:
                line += f" | proc={row['process']}"
            lines.append(line)
        return "\n".join(lines)

    def query_threat_intel(self, query: str) -> str:
        """Query threat intelligence for an indicator."""
        cur = self.conn.cursor()
        pattern = f"%{query}%"
        cur.execute("""
            SELECT indicator, indicator_type, reputation, confidence,
                   context, mitre_techniques
            FROM threat_intel
            WHERE indicator LIKE ?
               OR context   LIKE ?
            ORDER BY confidence DESC
            LIMIT 10
        """, (pattern, pattern))
        rows = cur.fetchall()
        if not rows:
            return f"[THREAT_INTEL] No intelligence records found for '{query}'. Indicator may be unknown or benign."

        lines = [f"[THREAT_INTEL] {len(rows)} record(s) for '{query}':"]
        for row in rows:
            mitres = f" | MITRE: {row['mitre_techniques']}" if row["mitre_techniques"] else ""
            lines.append(
                f"  Indicator: {row['indicator']} ({row['indicator_type'].upper()})\n"
                f"  Reputation: {row['reputation']} | Confidence: {row['confidence']}%\n"
                f"  Context: {row['context']}{mitres}"
            )
        return "\n".join(lines)

    def query_asset_inventory(self, query: str) -> str:
        """Look up an asset from inventory."""
        cur = self.conn.cursor()
        pattern = f"%{query}%"
        cur.execute("""
            SELECT hostname, ip, owner, department, criticality,
                   os, notes, known_safe
            FROM assets
            WHERE hostname   LIKE ?
               OR ip         LIKE ?
               OR owner      LIKE ?
               OR department LIKE ?
               OR notes      LIKE ?
            ORDER BY criticality DESC
            LIMIT 10
        """, (pattern, pattern, pattern, pattern, pattern))
        rows = cur.fetchall()
        if not rows:
            return f"[ASSET_INVENTORY] Asset '{query}' not found in CMDB. May be unregistered or external."

        lines = [f"[ASSET_INVENTORY] {len(rows)} asset(s) matching '{query}':"]
        for row in rows:
            safe_flag = " ✓ KNOWN_SAFE" if row["known_safe"] else ""
            lines.append(
                f"  Hostname: {row['hostname']} ({row['ip']}){safe_flag}\n"
                f"  Owner: {row['owner']} | Dept: {row['department']} | Criticality: {row['criticality']}\n"
                f"  OS: {row['os']}\n"
                f"  Notes: {row['notes']}"
            )
        return "\n".join(lines)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ─── Noise data injected into every episode ─────────────────────────────────

NOISE_LOGS = [
    {"timestamp": "2026-04-12T01:00:00Z", "source_ip": "10.0.0.5",  "dest_ip": "8.8.8.8",       "event_type": "DNS_QUERY",    "message": "Standard DNS lookup for google.com",           "severity": "LOW",  "process": "chrome.exe"},
    {"timestamp": "2026-04-12T01:15:00Z", "source_ip": "10.0.0.6",  "dest_ip": "10.0.0.1",      "event_type": "AUTH_SUCCESS", "message": "User bsmith logged in successfully",            "severity": "LOW",  "username": "bsmith"},
    {"timestamp": "2026-04-12T02:00:00Z", "source_ip": "10.0.0.3",  "dest_ip": "10.0.0.200",    "event_type": "FILE_ACCESS",  "message": "Normal file read: C:\\Users\\reports\\q1.xlsx",  "severity": "LOW",  "username": "cjones"},
    {"timestamp": "2026-04-12T02:30:00Z", "source_ip": "10.0.0.10", "dest_ip": "172.16.0.1",    "event_type": "NETWORK_CONN", "message": "Routine AD replication traffic",                "severity": "LOW",  "process": "lsass.exe"},
    {"timestamp": "2026-04-12T03:00:00Z", "source_ip": "10.0.0.2",  "dest_ip": "8.8.4.4",       "event_type": "DNS_QUERY",    "message": "DNS lookup: windows.update.microsoft.com",     "severity": "LOW",  "process": "svchost.exe"},
]

NOISE_ASSETS = [
    {"hostname": "WORKSTATION-01", "ip": "10.0.0.5",  "owner": "Alice Chen",    "department": "Engineering", "criticality": "LOW",    "os": "Windows 11",    "notes": "Developer workstation.",          "known_safe": True},
    {"hostname": "FILESERVER-01",  "ip": "10.0.0.200","owner": "IT Operations", "department": "IT",          "criticality": "HIGH",   "os": "Windows Server 2022", "notes": "Corporate file server.", "known_safe": True},
    {"hostname": "DC-01",          "ip": "172.16.0.1","owner": "IT Operations", "department": "IT",          "criticality": "CRITICAL","os": "Windows Server 2019", "notes": "Primary domain controller.", "known_safe": True},
    {"hostname": "HELPDESK-01",    "ip": "10.0.0.15", "owner": "Bob Smith",     "department": "Helpdesk",    "criticality": "LOW",    "os": "Windows 10",    "notes": "Helpdesk agent workstation.",     "known_safe": True},
]

NOISE_THREAT_INTEL = [
    {"indicator": "8.8.8.8",  "indicator_type": "ip",     "reputation": "CLEAN",     "confidence": 100, "context": "Google Public DNS resolver. Expected traffic for any network.", "mitre_techniques": ""},
    {"indicator": "8.8.4.4",  "indicator_type": "ip",     "reputation": "CLEAN",     "confidence": 100, "context": "Google Public DNS alternate resolver. Benign.", "mitre_techniques": ""},
    {"indicator": "1.1.1.1",  "indicator_type": "ip",     "reputation": "CLEAN",     "confidence": 100, "context": "Cloudflare DNS resolver. Benign.", "mitre_techniques": ""},
    {"indicator": "svchost.exe", "indicator_type": "process","reputation": "CLEAN",  "confidence": 100, "context": "Windows system host process. Normal operating system component.", "mitre_techniques": ""},
    {"indicator": "chrome.exe",  "indicator_type": "process","reputation": "CLEAN",  "confidence": 95,  "context": "Google Chrome browser. Expected user application.", "mitre_techniques": ""},
]


def build_episode_db(scenario_logs: List[Dict], scenario_assets: List[Dict],
                     scenario_threat_intel: List[Dict]) -> EpisodeDatabase:
    """
    Build a fresh in-memory database for one episode.
    Combines scenario-specific seed data with realistic noise records.
    """
    db = EpisodeDatabase()

    # Shuffle noise so record order is non-deterministic each episode
    noise_logs_shuffled = NOISE_LOGS.copy()
    random.shuffle(noise_logs_shuffled)

    db.seed_logs(noise_logs_shuffled + scenario_logs)
    db.seed_assets(NOISE_ASSETS + scenario_assets)
    db.seed_threat_intel(NOISE_THREAT_INTEL + scenario_threat_intel)
    return db
