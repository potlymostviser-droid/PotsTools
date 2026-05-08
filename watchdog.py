#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    WATCHDOG - DNS Change Monitor                            ║
║                    Bug Bounty Continuous Intelligence                       ║
║                                                                             ║
║  Philosophy:                                                                ║
║    Don't scan better. See changes faster.                                  ║
║    The alpha is the window between DNS change and hunter discovery.         ║
║                                                                             ║
║  What it does:                                                              ║
║    1. Snapshots DNS state for your target list                              ║
║    2. Diffs every N minutes against previous snapshot                       ║
║    3. Flags new takeover indicators immediately                             ║
║    4. Outputs JSON stream → pipe to nuclei/notify/slack                    ║
║                                                                             ║
║  What it is NOT:                                                            ║
║    A fingerprint scanner. Use nuclei for that.                              ║
║    A subdomain enumerator. Use subfinder for that.                          ║
║    A WHOIS parser. Don't do that to yourself.                               ║
║                                                                             ║
║  Workflow:                                                                  ║
║    subfinder -d target.com | python3 watchdog.py --watch                   ║
║    watchdog alerts → pipe to nuclei -t takeovers/ → pipe to notify         ║
║                                                                             ║
║  Dependencies: pip install dnspython requests                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import dns.resolver
import dns.exception
import requests
import sqlite3
import json
import sys
import re
import time
import threading
import argparse
import hashlib
import logging
import signal
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────────────────────
# SUPPRESS SSL WARNINGS
# ─────────────────────────────────────────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
# TAKEOVER CNAME SIGNATURES
#
# PHILOSOPHY:
#   This is NOT an HTTP fingerprint database.
#   This is ONLY the CNAME patterns that indicate a domain
#   is pointed at a service that allows takeover.
#
#   HTTP verification = nuclei's job, not ours.
#
# CONFIDENCE:
#   VERIFIED   = Confirmed via can-i-take-over-xyz community research
#   PROBABLE   = Strong evidence but not personally verified
#   UNCERTAIN  = Pattern exists, behavior may have changed
#
# SOURCE: https://github.com/EdOverflow/can-i-take-over-xyz
# YOU MUST RE-VERIFY THESE BEFORE REPORTING ANYTHING.
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_SIGNATURES: Dict[str, Dict] = {

    # ── Verified signatures ────────────────────────────────────────────────

    "github_pages": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.github\.io$",
            r"\.github\.com$",
        ],
        "notes": "Check if <user>.github.io account exists before reporting.",
    },
    "heroku": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"\.herokussl\.com$",
            r"\.herokudns\.com$",
        ],
        "notes": "App name extracted from CNAME - verify app is unclaimed.",
    },
    "aws_s3": {
        "confidence": "VERIFIED",
        "severity":   "CRITICAL",
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[\.\-]",
            r"\.s3\.[a-z0-9\-]+\.amazonaws\.com$",
        ],
        "notes": "Bucket name = subdomain. Verify bucket doesn't exist before reporting.",
    },
    "aws_cloudfront": {
        "confidence": "PROBABLE",
        "severity":   "CRITICAL",
        "cname_patterns": [
            r"\.cloudfront\.net$",
        ],
        "notes": "Complex to claim. Manual verification essential.",
    },
    "azure_websites": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.azure-mobile\.net$",
            r"\.cloudapp\.net$",
        ],
        "notes": "Verify app name availability in Azure portal.",
    },
    "azure_traffic_manager": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.trafficmanager\.net$",
        ],
        "notes": "UNCERTAIN - re-verify current behavior.",
    },
    "shopify": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.myshopify\.com$",
        ],
        "notes": "Verify shop name is claimable.",
    },
    "fastly": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.fastly\.net$",
            r"\.fastlylb\.net$",
        ],
        "notes": "",
    },
    "zendesk": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.zendesk\.com$",
        ],
        "notes": "",
    },
    "webflow": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"proxy\.webflow\.com$",
            r"proxy-ssl\.webflow\.com$",
        ],
        "notes": "UNCERTAIN - verify current error fingerprint.",
    },
    "tumblr": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"domains\.tumblr\.com$",
        ],
        "notes": "",
    },
    "ghost": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.ghost\.io$",
        ],
        "notes": "UNCERTAIN - re-verify current fingerprint.",
    },
    "netlify": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.netlify\.app$",
            r"\.netlify\.com$",
        ],
        "notes": "",
    },
    "pantheon": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.pantheonsite\.io$",
            r"\.panth\.io$",
        ],
        "notes": "",
    },
    "surge": {
        "confidence": "VERIFIED",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.surge\.sh$",
        ],
        "notes": "Easy to claim: surge --domain <domain>",
    },
    "bitbucket": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.bitbucket\.io$",
        ],
        "notes": "Bitbucket Pages may be deprecated - verify first.",
    },
    "unbounce": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.unbouncepages\.com$",
        ],
        "notes": "",
    },
    "statuspage": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.statuspage\.io$",
        ],
        "notes": "",
    },
    "helpjuice": {
        "confidence": "UNCERTAIN",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.helpjuice\.com$",
        ],
        "notes": "UNCERTAIN - do not report without manual verification.",
    },
    "helpscout": {
        "confidence": "UNCERTAIN",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.helpscoutdocs\.com$",
        ],
        "notes": "UNCERTAIN - do not report without manual verification.",
    },
    "wpengine": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.wpengine\.com$",
        ],
        "notes": "",
    },
    "readme_io": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"\.readme\.io$",
            r"\.readmessl\.com$",
        ],
        "notes": "",
    },
    "squarespace": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"ext-cust\.squarespace\.com$",
        ],
        "notes": "",
    },
    "intercom": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"custom\.intercom\.help$",
        ],
        "notes": "",
    },
    "smartjobboard": {
        "confidence": "UNCERTAIN",
        "severity":   "MEDIUM",
        "cname_patterns": [
            r"\.smartjobboard\.com$",
        ],
        "notes": "UNCERTAIN.",
    },
    "pingdom": {
        "confidence": "PROBABLE",
        "severity":   "LOW",
        "cname_patterns": [
            r"\.pingdom\.com$",
        ],
        "notes": "",
    },
}

# Pre-compile all patterns once at startup
_COMPILED_SIGNATURES: Dict[str, List] = {
    service: [
        re.compile(p, re.IGNORECASE)
        for p in sig["cname_patterns"]
    ]
    for service, sig in TAKEOVER_SIGNATURES.items()
}


# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLVERS
# ─────────────────────────────────────────────────────────────────────────────

DNS_RESOLVERS = [
    "8.8.8.8",        # Google
    "1.1.1.1",        # Cloudflare
    "9.9.9.9",        # Quad9
    "208.67.222.222", # OpenDNS
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DNSSnapshot:
    """
    Complete DNS state for one domain at one point in time.
    This is what we store and diff.
    """
    domain:      str
    timestamp:   str
    cname_chain: List[str]  = field(default_factory=list)
    a_records:   List[str]  = field(default_factory=list)
    ns_records:  List[str]  = field(default_factory=list)
    resolves:    bool       = False
    nxdomain:    bool       = False
    error:       Optional[str] = None

    def fingerprint(self) -> str:
        """
        Hash of the DNS state.
        If this changes between snapshots, something changed.
        """
        state = json.dumps({
            "cname": sorted(self.cname_chain),
            "a":     sorted(self.a_records),
            "ns":    sorted(self.ns_records),
            "nx":    self.nxdomain,
        }, sort_keys=True)
        return hashlib.sha256(state.encode()).hexdigest()[:16]


@dataclass
class DNSChange:
    """
    A detected change between two snapshots.
    This is what gets emitted as an alert.
    """
    domain:        str
    change_type:   str          # NEW_CNAME | CNAME_CHANGED | A_CHANGED | NS_CHANGED | RECORD_GONE | NEW_DOMAIN
    old_value:     List[str]
    new_value:     List[str]
    timestamp:     str

    # Takeover analysis
    takeover_risk:    bool  = False
    matched_service:  str   = ""
    severity:         str   = ""
    confidence:       str   = ""
    notes:            str   = ""

    # For pipeline integration
    ready_for_nuclei: bool  = False


@dataclass
class Alert:
    """
    A high-priority alert ready for immediate action.
    This gets written to stdout for pipeline consumption.
    """
    domain:          str
    service:         str
    severity:        str
    confidence:      str
    change_type:     str
    cname_chain:     List[str]
    notes:           str
    timestamp:       str
    nuclei_target:   str      # Formatted for nuclei input
    scan_id:         str = field(
        default_factory=lambda: hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:8]
    )


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE LAYER
# Simple SQLite. No external dependencies.
# Stores snapshots and change history.
# ─────────────────────────────────────────────────────────────────────────────

class WatchdogDB:
    """
    SQLite storage for DNS snapshots and change history.

    Schema is simple by design:
    - snapshots: current DNS state per domain
    - changes: history of all detected changes
    - alerts: high-priority findings
    """

    def __init__(self, db_path: str = "watchdog.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        """Thread-local connection"""
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent access
        return self._local.conn

    def _init_schema(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS snapshots (
                domain          TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                cname_chain     TEXT NOT NULL DEFAULT '[]',
                a_records       TEXT NOT NULL DEFAULT '[]',
                ns_records      TEXT NOT NULL DEFAULT '[]',
                resolves        INTEGER NOT NULL DEFAULT 0,
                nxdomain        INTEGER NOT NULL DEFAULT 0,
                error           TEXT,
                fingerprint     TEXT NOT NULL,
                PRIMARY KEY (domain)
            );

            CREATE TABLE IF NOT EXISTS change_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT NOT NULL,
                change_type     TEXT NOT NULL,
                old_value       TEXT NOT NULL,
                new_value       TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                takeover_risk   INTEGER NOT NULL DEFAULT 0,
                service         TEXT,
                severity        TEXT,
                confidence      TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                domain          TEXT NOT NULL,
                service         TEXT NOT NULL,
                severity        TEXT NOT NULL,
                confidence      TEXT NOT NULL,
                change_type     TEXT NOT NULL,
                cname_chain     TEXT NOT NULL,
                notes           TEXT,
                timestamp       TEXT NOT NULL,
                scan_id         TEXT NOT NULL,
                acknowledged    INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_domain
                ON snapshots(domain);
            CREATE INDEX IF NOT EXISTS idx_changes_domain
                ON change_history(domain);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON alerts(timestamp);
        """)
        conn.commit()

    def get_snapshot(self, domain: str) -> Optional[DNSSnapshot]:
        """Get last known DNS state for domain"""
        row = self._conn().execute(
            "SELECT * FROM snapshots WHERE domain = ?", (domain,)
        ).fetchone()

        if not row:
            return None

        return DNSSnapshot(
            domain      = row["domain"],
            timestamp   = row["timestamp"],
            cname_chain = json.loads(row["cname_chain"]),
            a_records   = json.loads(row["a_records"]),
            ns_records  = json.loads(row["ns_records"]),
            resolves    = bool(row["resolves"]),
            nxdomain    = bool(row["nxdomain"]),
            error       = row["error"],
        )

    def save_snapshot(self, snapshot: DNSSnapshot):
        """Upsert current DNS state"""
        fp = snapshot.fingerprint()
        self._conn().execute("""
            INSERT INTO snapshots
                (domain, timestamp, cname_chain, a_records, ns_records,
                 resolves, nxdomain, error, fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                timestamp   = excluded.timestamp,
                cname_chain = excluded.cname_chain,
                a_records   = excluded.a_records,
                ns_records  = excluded.ns_records,
                resolves    = excluded.resolves,
                nxdomain    = excluded.nxdomain,
                error       = excluded.error,
                fingerprint = excluded.fingerprint
        """, (
            snapshot.domain,
            snapshot.timestamp,
            json.dumps(snapshot.cname_chain),
            json.dumps(snapshot.a_records),
            json.dumps(snapshot.ns_records),
            int(snapshot.resolves),
            int(snapshot.nxdomain),
            snapshot.error,
            fp,
        ))
        self._conn().commit()

    def record_change(self, change: DNSChange):
        """Record a detected change to history"""
        self._conn().execute("""
            INSERT INTO change_history
                (domain, change_type, old_value, new_value, timestamp,
                 takeover_risk, service, severity, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            change.domain,
            change.change_type,
            json.dumps(change.old_value),
            json.dumps(change.new_value),
            change.timestamp,
            int(change.takeover_risk),
            change.matched_service,
            change.severity,
            change.confidence,
        ))
        self._conn().commit()

    def record_alert(self, alert: Alert):
        """Record a high-priority alert"""
        self._conn().execute("""
            INSERT INTO alerts
                (domain, service, severity, confidence, change_type,
                 cname_chain, notes, timestamp, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.domain,
            alert.service,
            alert.severity,
            alert.confidence,
            alert.change_type,
            json.dumps(alert.cname_chain),
            alert.notes,
            alert.timestamp,
            alert.scan_id,
        ))
        self._conn().commit()

    def get_all_domains(self) -> List[str]:
        """Return all tracked domains"""
        rows = self._conn().execute("SELECT domain FROM snapshots").fetchall()
        return [r["domain"] for r in rows]

    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get unacknowledged alerts from last N hours"""
        rows = self._conn().execute("""
            SELECT * FROM alerts
            WHERE acknowledged = 0
            ORDER BY timestamp DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_change_history(self, domain: str, limit: int = 20) -> List[Dict]:
        """Get change history for a domain"""
        rows = self._conn().execute("""
            SELECT * FROM change_history
            WHERE domain = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (domain, limit)).fetchall()
        return [dict(r) for r in rows]

    def domain_count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM snapshots"
        ).fetchone()[0]


# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLVER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DNSEngine:
    """
    Multi-resolver DNS engine.
    Cross-validates across 4 public resolvers.
    Follows CNAME chains recursively.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _make_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [nameserver]
        r.timeout    = self.timeout
        r.lifetime   = self.timeout
        return r

    def _query(
        self,
        domain: str,
        rtype: str,
        nameserver: str
    ) -> Tuple[List[str], bool]:
        """
        Query one record type from one nameserver.
        Returns (results, is_nxdomain).
        """
        try:
            resolver = self._make_resolver(nameserver)
            answers  = resolver.resolve(domain, rtype)

            if rtype == "CNAME":
                return [str(r.target).rstrip(".") for r in answers], False
            elif rtype in ("A", "AAAA"):
                return [str(r.address) for r in answers], False
            elif rtype == "NS":
                return [str(r.target).rstrip(".") for r in answers], False
            return [], False

        except dns.resolver.NXDOMAIN:
            return [], True
        except dns.resolver.NoAnswer:
            return [], False
        except dns.exception.Timeout:
            return [], False
        except Exception:
            return [], False

    def _follow_cname_chain(
        self,
        domain: str,
        nameserver: str,
        visited: Set[str] = None,
        depth: int = 0
    ) -> Tuple[List[str], bool]:
        """
        Recursively follow CNAME chain.
        Returns (full_chain, encountered_nxdomain)
        visited set prevents infinite loops.
        """
        if visited is None:
            visited = set()

        if depth > 10 or domain in visited:
            return [], False

        visited.add(domain)

        cnames, nxdomain = self._query(domain, "CNAME", nameserver)

        if nxdomain:
            return [], True

        if not cnames:
            return [], False

        chain = cnames[:]
        for cname in cnames:
            deeper, nx = self._follow_cname_chain(cname, nameserver, visited, depth + 1)
            if nx:
                return chain, True
            chain.extend(deeper)

        return chain, False

    def resolve(self, domain: str) -> DNSSnapshot:
        """
        Full multi-resolver DNS resolution.
        Returns a DNSSnapshot with all record types.
        """
        now = datetime.now(timezone.utc).isoformat()
        snapshot = DNSSnapshot(domain=domain, timestamp=now)

        cname_results: List[List[str]] = []
        a_records_set:  Set[str] = set()
        ns_records_set: Set[str] = set()
        nxdomain_votes = 0

        for ns in DNS_RESOLVERS:
            # CNAME chain
            chain, nx = self._follow_cname_chain(domain, ns)
            if nx:
                nxdomain_votes += 1
            if chain:
                cname_results.append(chain)

            # A records
            a_recs, _ = self._query(domain, "A", ns)
            a_records_set.update(a_recs)

            # NS records (less frequent, only from first resolver)
            if ns == DNS_RESOLVERS[0]:
                ns_recs, _ = self._query(domain, "NS", ns)
                ns_records_set.update(ns_recs)

        # Consensus CNAME: use longest chain
        if cname_results:
            snapshot.cname_chain = max(cname_results, key=len)

        snapshot.a_records  = sorted(a_records_set)
        snapshot.ns_records = sorted(ns_records_set)

        # NXDOMAIN consensus: 2+ resolvers must agree
        snapshot.nxdomain = nxdomain_votes >= 2

        snapshot.resolves = bool(
            snapshot.cname_chain or snapshot.a_records
        )

        return snapshot


# ─────────────────────────────────────────────────────────────────────────────
# CHANGE DETECTOR
# Core diffing logic. This is where the alpha lives.
# ─────────────────────────────────────────────────────────────────────────────

class ChangeDetector:
    """
    Diffs two DNS snapshots and produces change events.
    Analyzes each change for takeover risk.
    """

    def _match_takeover_signature(
        self,
        cname_chain: List[str]
    ) -> Tuple[bool, str, str, str]:
        """
        Check if any CNAME in the chain matches a known takeover signature.
        Returns (match, service, severity, confidence)
        """
        for cname in cname_chain:
            for service, patterns in _COMPILED_SIGNATURES.items():
                for pattern in patterns:
                    if pattern.search(cname):
                        sig = TAKEOVER_SIGNATURES[service]
                        return True, service, sig["severity"], sig["confidence"]
        return False, "", "", ""

    def diff(
        self,
        old: Optional[DNSSnapshot],
        new: DNSSnapshot,
    ) -> List[DNSChange]:
        """
        Compare old and new snapshots.
        Returns list of detected changes.

        Cases we care about:

        1. New domain (never seen before) with takeover signature → HIGH ALERT
        2. CNAME chain changed AND new chain has takeover signature → ALERT
        3. New CNAME added to chain with takeover signature → ALERT
        4. NS records changed → flag (manual investigation)
        5. Domain went NXDOMAIN when it wasn't → flag (dangling)
        6. A record changed significantly → flag
        """
        now = datetime.now(timezone.utc).isoformat()
        changes: List[DNSChange] = []

        # ── Case 1: Brand new domain ─────────────────────────────────────────
        if old is None:
            risk, service, severity, confidence = self._match_takeover_signature(
                new.cname_chain
            )
            changes.append(DNSChange(
                domain      = new.domain,
                change_type = "NEW_DOMAIN",
                old_value   = [],
                new_value   = new.cname_chain,
                timestamp   = now,
                takeover_risk   = risk,
                matched_service = service,
                severity        = severity,
                confidence      = confidence,
                notes           = "First time seeing this domain.",
                ready_for_nuclei = risk,
            ))
            return changes

        # ── Fast path: fingerprint unchanged → nothing to do ─────────────────
        if old.fingerprint() == new.fingerprint():
            return []

        # ── Case 2: CNAME chain changed ──────────────────────────────────────
        old_cnames = set(old.cname_chain)
        new_cnames = set(new.cname_chain)

        added_cnames   = new_cnames - old_cnames
        removed_cnames = old_cnames - new_cnames

        if added_cnames or removed_cnames:
            # Check new CNAMEs for takeover signatures
            risk, service, severity, confidence = self._match_takeover_signature(
                list(added_cnames)
            )

            change_type = "NEW_CNAME" if added_cnames else "CNAME_REMOVED"

            changes.append(DNSChange(
                domain      = new.domain,
                change_type = change_type,
                old_value   = list(old_cnames),
                new_value   = list(new_cnames),
                timestamp   = now,
                takeover_risk   = risk,
                matched_service = service,
                severity        = severity,
                confidence      = confidence,
                notes = (
                    f"Added: {added_cnames} | Removed: {removed_cnames}"
                    if added_cnames and removed_cnames
                    else f"Added: {added_cnames}" if added_cnames
                    else f"Removed: {removed_cnames}"
                ),
                ready_for_nuclei = risk,
            ))

        # ── Case 3: A records changed ────────────────────────────────────────
        old_a = set(old.a_records)
        new_a = set(new.a_records)
        if old_a != new_a:
            added_ips   = new_a - old_a
            removed_ips = old_a - new_a

            changes.append(DNSChange(
                domain      = new.domain,
                change_type = "A_CHANGED",
                old_value   = list(old_a),
                new_value   = list(new_a),
                timestamp   = now,
                takeover_risk = False,  # A records alone → not a takeover indicator here
                notes = (
                    f"IPs added: {added_ips} | removed: {removed_ips}"
                ),
                ready_for_nuclei = False,
            ))

        # ── Case 4: NS records changed ───────────────────────────────────────
        old_ns = set(old.ns_records)
        new_ns = set(new.ns_records)
        if old_ns != new_ns:
            added_ns   = new_ns - old_ns
            removed_ns = old_ns - new_ns

            # NS change is always worth noting - manual investigation needed
            changes.append(DNSChange(
                domain      = new.domain,
                change_type = "NS_CHANGED",
                old_value   = list(old_ns),
                new_value   = list(new_ns),
                timestamp   = now,
                takeover_risk = bool(added_ns),  # New NS records = interesting
                notes = (
                    f"NS added: {added_ns} | removed: {removed_ns}. "
                    f"Manual investigation recommended."
                ),
                severity  = "HIGH" if added_ns else "INFO",
                confidence = "PROBABLE",
                ready_for_nuclei = False,
            ))

        # ── Case 5: Domain went NXDOMAIN ────────────────────────────────────
        if not old.nxdomain and new.nxdomain:
            changes.append(DNSChange(
                domain      = new.domain,
                change_type = "WENT_NXDOMAIN",
                old_value   = old.cname_chain,
                new_value   = [],
                timestamp   = now,
                takeover_risk = True,  # Dangling - interesting
                notes = "Domain that previously resolved now returns NXDOMAIN.",
                severity  = "MEDIUM",
                confidence = "PROBABLE",
                ready_for_nuclei = False,
            ))

        return changes


# ─────────────────────────────────────────────────────────────────────────────
# NOTIFICATION LAYER
# Writes to: stdout (for pipeline), log file, optional webhook
# ─────────────────────────────────────────────────────────────────────────────

class Notifier:
    """
    Alert output handler.

    Stdout: JSON (for pipeline to nuclei/notify/slack)
    Stderr: Human-readable status
    Webhook: Optional Slack/Discord
    """

    SEVERITY_COLORS = {
        "CRITICAL": "\033[41m\033[97m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[96m",
        "INFO":     "\033[94m",
    }
    RESET = "\033[0m"

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        quiet: bool = False,
        json_output: bool = False,
    ):
        self.webhook_url = webhook_url
        self.quiet       = quiet
        self.json_output = json_output
        self._lock       = threading.Lock()

    def _stderr(self, message: str):
        """Status to stderr (doesn't pollute stdout pipeline)"""
        if not self.quiet:
            print(message, file=sys.stderr, flush=True)

    def emit_alert(self, alert: Alert):
        """
        Emit an alert.
        JSON to stdout for pipeline consumption.
        Human-readable to stderr.
        Webhook if configured.
        """
        alert_dict = asdict(alert)

        with self._lock:
            # Always write JSON to stdout (pipeline-safe)
            print(json.dumps(alert_dict), flush=True)

            # Human readable to stderr
            color = self.SEVERITY_COLORS.get(alert.severity, "")
            self._stderr(
                f"\n{color}[ALERT]{self.RESET} "
                f"{alert.severity} | {alert.domain} → {alert.service}\n"
                f"  Confidence: {alert.confidence}\n"
                f"  Change: {alert.change_type}\n"
                f"  CNAME: {' → '.join(alert.cname_chain)}\n"
                f"  Nuclei: echo '{alert.nuclei_target}' | "
                f"nuclei -t takeovers/\n"
                f"  Notes: {alert.notes}\n"
            )

        # Webhook notification
        if self.webhook_url:
            self._send_webhook(alert)

    def emit_change(self, change: DNSChange):
        """Emit a non-alert change (informational)"""
        if self.json_output:
            change_dict = asdict(change)
            print(json.dumps(change_dict), flush=True)
        else:
            self._stderr(
                f"[CHANGE] {change.domain} | {change.change_type} | "
                f"{change.old_value} → {change.new_value}"
            )

    def emit_status(self, message: str):
        """Status message"""
        self._stderr(f"[*] {message}")

    def _send_webhook(self, alert: Alert):
        """Send to Slack/Discord webhook"""
        try:
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH":     "🟠",
                "MEDIUM":   "🟡",
                "LOW":      "🟢",
            }.get(alert.severity, "⚪")

            payload = {
                "text": (
                    f"{severity_emoji} *WATCHDOG ALERT*\n"
                    f"*Domain:* `{alert.domain}`\n"
                    f"*Service:* {alert.service}\n"
                    f"*Severity:* {alert.severity}\n"
                    f"*Confidence:* {alert.confidence}\n"
                    f"*CNAME:* `{' → '.join(alert.cname_chain)}`\n"
                    f"*Notes:* {alert.notes}\n"
                    f"*Verify:* `echo '{alert.nuclei_target}' | nuclei -t takeovers/`"
                )
            }
            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception as e:
            self._stderr(f"[!] Webhook failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE
# Orchestrates: resolve → diff → alert
# ─────────────────────────────────────────────────────────────────────────────

class ScanEngine:
    """
    Core scanning logic.
    Resolves DNS, diffs against stored state, emits changes and alerts.
    """

    def __init__(
        self,
        db: WatchdogDB,
        dns_engine: DNSEngine,
        detector: ChangeDetector,
        notifier: Notifier,
        threads: int = 30,
        skip_uncertain: bool = True,
    ):
        self.db             = db
        self.dns            = dns_engine
        self.detector       = detector
        self.notifier       = notifier
        self.threads        = threads
        self.skip_uncertain = skip_uncertain

        # Stats
        self._lock          = threading.Lock()
        self.stats          = {
            "resolved":  0,
            "changed":   0,
            "alerted":   0,
            "errors":    0,
        }

    def _process_one(self, domain: str):
        """Full pipeline for one domain"""
        try:
            # Resolve current DNS state
            new_snapshot = self.dns.resolve(domain)

            # Get previous snapshot from DB
            old_snapshot = self.db.get_snapshot(domain)

            # Diff
            changes = self.detector.diff(old_snapshot, new_snapshot)

            # Save new snapshot
            self.db.save_snapshot(new_snapshot)

            with self._lock:
                self.stats["resolved"] += 1

            if not changes:
                return

            with self._lock:
                self.stats["changed"] += 1

            for change in changes:
                # Save change to history
                self.db.record_change(change)

                # Emit informational change
                self.notifier.emit_change(change)

                # Is this a takeover risk worth alerting on?
                if not change.takeover_risk:
                    continue

                # Skip uncertain fingerprints unless configured otherwise
                if (
                    self.skip_uncertain
                    and change.confidence == "UNCERTAIN"
                    and change.severity not in ("CRITICAL", "HIGH")
                ):
                    continue

                # Build alert
                alert = Alert(
                    domain        = change.domain,
                    service       = change.matched_service or "UNKNOWN",
                    severity      = change.severity or "MEDIUM",
                    confidence    = change.confidence or "PROBABLE",
                    change_type   = change.change_type,
                    cname_chain   = new_snapshot.cname_chain,
                    notes         = change.notes,
                    timestamp     = change.timestamp,
                    nuclei_target = change.domain,
                )

                # Save alert to DB
                self.db.record_alert(alert)

                # Emit alert (stdout JSON + stderr human + webhook)
                self.notifier.emit_alert(alert)

                with self._lock:
                    self.stats["alerted"] += 1

        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
            self.notifier.emit_status(f"Error processing {domain}: {e}")

    def run_scan(self, domains: List[str]) -> Dict:
        """Run a full scan pass over domain list"""
        start = time.time()
        self.notifier.emit_status(
            f"Scanning {len(domains)} domains with {self.threads} threads..."
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._process_one, domain): domain
                for domain in domains
            }
            done = 0
            for future in as_completed(futures):
                done += 1
                if done % 100 == 0 or done == len(domains):
                    self.notifier.emit_status(
                        f"Progress: {done}/{len(domains)} | "
                        f"Alerts: {self.stats['alerted']}"
                    )

        elapsed = time.time() - start
        self.stats["elapsed"] = round(elapsed, 2)
        self.stats["speed"]   = round(len(domains) / elapsed, 1)
        return self.stats


# ─────────────────────────────────────────────────────────────────────────────
# WATCHDOG - Main Daemon
# ─────────────────────────────────────────────────────────────────────────────

class Watchdog:
    """
    Main orchestrator.
    Runs single scan or continuous monitoring loop.
    """

    def __init__(self, config: Dict):
        self.config  = config
        self.running = True

        self.db = WatchdogDB(config.get("db_path", "watchdog.db"))

        self.dns_engine = DNSEngine(
            timeout=config.get("timeout", 5.0)
        )
        self.detector = ChangeDetector()

        self.notifier = Notifier(
            webhook_url = config.get("webhook"),
            quiet       = config.get("quiet", False),
            json_output = config.get("json_output", False),
        )

        self.engine = ScanEngine(
            db             = self.db,
            dns_engine     = self.dns_engine,
            detector       = self.detector,
            notifier       = self.notifier,
            threads        = config.get("threads", 30),
            skip_uncertain = not config.get("include_uncertain", False),
        )

        # Graceful shutdown
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum, frame):
        self.notifier.emit_status("Shutting down...")
        self.running = False
        sys.exit(0)

    def load_domains(self) -> List[str]:
        """Load target domains from file or argument"""
        domains = []

        if self.config.get("file"):
            try:
                with open(self.config["file"]) as fh:
                    domains = [
                        line.strip().lower()
                        for line in fh
                        if line.strip() and not line.startswith("#")
                    ]
            except FileNotFoundError:
                print(f"[ERROR] File not found: {self.config['file']}", file=sys.stderr)
                sys.exit(1)

        if self.config.get("domain"):
            domains.append(self.config["domain"].lower())

        # Deduplicate while preserving order
        seen = set()
        domains = [d for d in domains if not (d in seen or seen.add(d))]

        return domains

    def run_once(self, domains: List[str]) -> Dict:
        """Single scan pass"""
        stats = self.engine.run_scan(domains)
        self._print_stats(stats, len(domains))
        return stats

    def run_watch(self, domains: List[str], interval: int):
        """
        Continuous monitoring loop.
        Re-scans every `interval` minutes.
        This is the core value of Watchdog.
        """
        scan_count = 0

        self.notifier.emit_status(
            f"Watch mode: {len(domains)} domains | "
            f"Interval: {interval}min | "
            f"DB: {self.config.get('db_path', 'watchdog.db')}"
        )

        while self.running:
            scan_count += 1
            self.notifier.emit_status(f"Scan #{scan_count} starting...")

            stats = self.engine.run_scan(domains)
            self._print_stats(stats, len(domains))

            if not self.running:
                break

            self.notifier.emit_status(
                f"Next scan in {interval} minutes. "
                f"Ctrl+C to stop."
            )
            # Sleep in small chunks to remain responsive to Ctrl+C
            for _ in range(interval * 60):
                if not self.running:
                    break
                time.sleep(1)

    def _print_stats(self, stats: Dict, total: int):
        """Print scan statistics to stderr"""
        self.notifier.emit_status(
            f"Scan complete | "
            f"Resolved: {stats['resolved']}/{total} | "
            f"Changed: {stats['changed']} | "
            f"Alerted: {stats['alerted']} | "
            f"Errors: {stats['errors']} | "
            f"Speed: {stats.get('speed', 0)}/s | "
            f"Time: {stats.get('elapsed', 0)}s"
        )

    def show_alerts(self):
        """Display recent alerts from DB"""
        alerts = self.db.get_recent_alerts()
        if not alerts:
            print("[*] No pending alerts.", file=sys.stderr)
            return

        print(f"\n[*] {len(alerts)} pending alerts:\n", file=sys.stderr)
        for a in alerts:
            print(
                f"  [{a['severity']}] {a['domain']} → {a['service']} "
                f"({a['confidence']}) @ {a['timestamp']}",
                file=sys.stderr
            )

    def show_history(self, domain: str):
        """Show change history for a domain"""
        history = self.db.get_change_history(domain)
        if not history:
            print(f"[*] No history for {domain}", file=sys.stderr)
            return

        print(f"\n[*] Change history for {domain}:\n", file=sys.stderr)
        for h in history:
            print(
                f"  [{h['timestamp']}] {h['change_type']} | "
                f"Risk: {bool(h['takeover_risk'])} | "
                f"Service: {h['service'] or 'N/A'}",
                file=sys.stderr
            )

    def export_targets(self, output_file: str):
        """Export all alert domains in nuclei-ready format"""
        alerts = self.db.get_recent_alerts()
        if not alerts:
            print("[*] No alerts to export.", file=sys.stderr)
            return

        domains = list({a["domain"] for a in alerts})
        with open(output_file, "w") as fh:
            for d in domains:
                fh.write(d + "\n")

        print(f"[*] Exported {len(domains)} targets → {output_file}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝
██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗
██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║
╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝

  DNS Change Monitor | Bug Bounty Continuous Intelligence
  "Don't scan better. See changes faster."
"""


def main():
    parser = argparse.ArgumentParser(
        description="WATCHDOG - DNS Change Monitor for Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  MODES:

    scan      One-time scan. Good for initial baseline.
    watch     Continuous monitoring. This is the alpha.
    alerts    Show pending alerts from DB.
    history   Show change history for a domain.
    export    Export alert targets to file for nuclei.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  WORKFLOW:

    Step 1: Build your target list
      subfinder -d target.com -silent >> targets.txt
      amass enum -passive -d target.com >> targets.txt
      sort -u targets.txt -o targets.txt

    Step 2: Initial baseline scan
      python3 watchdog.py scan -f targets.txt

    Step 3: Continuous monitoring (runs forever)
      python3 watchdog.py watch -f targets.txt --interval 60

    Step 4: When alert fires, verify with nuclei
      python3 watchdog.py export -o nuclei_targets.txt
      nuclei -l nuclei_targets.txt -t takeovers/ -o nuclei_results.txt

    Step 5: Pipeline mode (stdout → nuclei directly)
      python3 watchdog.py watch -f targets.txt | \\
        jq -r '.nuclei_target' | \\
        nuclei -t takeovers/

    Step 6: With Slack notifications
      python3 watchdog.py watch -f targets.txt \\
        --webhook https://hooks.slack.com/services/YOUR/HOOK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )

    subparsers = parser.add_subparsers(dest="mode", help="Mode")

    # ── scan mode ────────────────────────────────────────────────────────────
    scan_p = subparsers.add_parser("scan", help="One-time DNS scan")
    scan_p.add_argument("-f", "--file",    help="Domain list file")
    scan_p.add_argument("-d", "--domain",  help="Single domain")
    scan_p.add_argument("-t", "--threads", type=int, default=30)
    scan_p.add_argument("--timeout",       type=float, default=5.0)
    scan_p.add_argument("--include-uncertain", action="store_true")
    scan_p.add_argument("--webhook",       help="Slack/Discord webhook URL")
    scan_p.add_argument("--db",            default="watchdog.db")
    scan_p.add_argument("-q", "--quiet",   action="store_true")

    # ── watch mode ───────────────────────────────────────────────────────────
    watch_p = subparsers.add_parser("watch", help="Continuous monitoring")
    watch_p.add_argument("-f", "--file",    help="Domain list file")
    watch_p.add_argument("-d", "--domain",  help="Single domain")
    watch_p.add_argument("-t", "--threads", type=int, default=30)
    watch_p.add_argument("--interval",      type=int, default=60,
                         help="Scan interval in minutes (default: 60)")
    watch_p.add_argument("--timeout",       type=float, default=5.0)
    watch_p.add_argument("--include-uncertain", action="store_true")
    watch_p.add_argument("--webhook",       help="Slack/Discord webhook URL")
    watch_p.add_argument("--db",            default="watchdog.db")
    watch_p.add_argument("-q", "--quiet",   action="store_true")

    # ── alerts mode ──────────────────────────────────────────────────────────
    alerts_p = subparsers.add_parser("alerts", help="Show pending alerts")
    alerts_p.add_argument("--db", default="watchdog.db")

    # ── history mode ─────────────────────────────────────────────────────────
    history_p = subparsers.add_parser("history", help="Show domain change history")
    history_p.add_argument("domain", help="Domain to inspect")
    history_p.add_argument("--db",   default="watchdog.db")

    # ── export mode ──────────────────────────────────────────────────────────
    export_p = subparsers.add_parser("export", help="Export alert targets for nuclei")
    export_p.add_argument("-o", "--output", default="nuclei_targets.txt")
    export_p.add_argument("--db",           default="watchdog.db")

    args = parser.parse_args()

    if not args.mode:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    print(BANNER, file=sys.stderr)

    # Build config
    config = {
        "file":              getattr(args, "file",    None),
        "domain":            getattr(args, "domain",  None),
        "threads":           getattr(args, "threads", 30),
        "timeout":           getattr(args, "timeout", 5.0),
        "include_uncertain": getattr(args, "include_uncertain", False),
        "webhook":           getattr(args, "webhook", None),
        "db_path":           getattr(args, "db",      "watchdog.db"),
        "quiet":             getattr(args, "quiet",   False),
        "json_output":       True,
    }

    watchdog = Watchdog(config)

    if args.mode in ("scan", "watch"):
        domains = watchdog.load_domains()
        if not domains:
            print("[ERROR] No domains specified.", file=sys.stderr)
            sys.exit(1)

        print(
            f"[*] Loaded {len(domains)} domains | "
            f"DB: {config['db_path']} | "
            f"Signatures: {len(TAKEOVER_SIGNATURES)}",
            file=sys.stderr
        )

        if args.mode == "scan":
            watchdog.run_once(domains)
        else:
            watchdog.run_watch(domains, args.interval)

    elif args.mode == "alerts":
        watchdog.show_alerts()

    elif args.mode == "history":
        watchdog.show_history(args.domain)

    elif args.mode == "export":
        watchdog.export_targets(args.output)


if __name__ == "__main__":
    main()
