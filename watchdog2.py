#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    WATCHDOG v2.0 - DNS Change Monitor                      ║
║                    Bug Bounty Continuous Intelligence                       ║
║                                                                             ║
║  Changes from v1.0:                                                         ║
║    FIX 1: Alert deduplication (no more webhook spam)                       ║
║    FIX 2: Silent baseline on first scan (alerts only on delta)             ║
║    FIX 3: Stats reset per scan (accurate per-cycle reporting)              ║
║    FIX 4: Set → List conversion everywhere (no JSON crash)                 ║
║    FIX 5: DB connection cleanup on thread pool exit                        ║
║    FIX 6: DNS rate limiting (won't get throttled at scale)                 ║
║    FIX 7: ThreadPoolExecutor reuse (no memory leak in watch mode)          ║
║                                                                             ║
║  Philosophy:                                                                ║
║    Don't scan better. See changes faster.                                  ║
║    The alpha is the window between DNS change and hunter discovery.         ║
║                                                                             ║
║  What it does:                                                              ║
║    1. Snapshots DNS state for your target list (silent baseline)           ║
║    2. Diffs every N minutes against stored state                           ║
║    3. Flags NEW takeover indicators only (not pre-existing ones)           ║
║    4. Deduplicates alerts (one alert per domain per issue)                 ║
║    5. Outputs JSON to stdout → pipe to nuclei/notify/slack                 ║
║                                                                             ║
║  Dependencies: pip install dnspython requests                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import dns.resolver
import dns.exception
import dns.rdatatype
import requests
import sqlite3
import json
import sys
import re
import time
import threading
import argparse
import hashlib
import signal
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
# TAKEOVER CNAME SIGNATURES
#
# CNAME-only patterns. No HTTP body matching. That's nuclei's job.
#
# CONFIDENCE:
#   VERIFIED   = Confirmed via can-i-take-over-xyz
#   PROBABLE   = Strong evidence, not personally verified
#   UNCERTAIN  = Pattern exists, behavior may have changed
#
# SOURCE: https://github.com/EdOverflow/can-i-take-over-xyz
# ALWAYS re-verify against that repo before reporting anything.
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_SIGNATURES: Dict[str, Dict] = {
    "github_pages": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.github\.io$", r"\.github\.com$"],
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
        "notes": "Verify app name is unclaimed at herokuapp.com.",
    },
    "aws_s3": {
        "confidence": "VERIFIED",
        "severity":   "CRITICAL",
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[\.\-]",
            r"\.s3\.[a-z0-9\-]+\.amazonaws\.com$",
        ],
        "notes": "Bucket name = subdomain. Verify bucket doesn't exist.",
    },
    "aws_cloudfront": {
        "confidence": "PROBABLE",
        "severity":   "CRITICAL",
        "cname_patterns": [r"\.cloudfront\.net$"],
        "notes": "Complex claim. Manual verification essential.",
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
        "cname_patterns": [r"\.trafficmanager\.net$"],
        "notes": "Re-verify current behavior before reporting.",
    },
    "shopify": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.myshopify\.com$"],
        "notes": "Verify shop name is claimable.",
    },
    "fastly": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "notes": "",
    },
    "zendesk": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.zendesk\.com$"],
        "notes": "",
    },
    "webflow": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [
            r"proxy\.webflow\.com$",
            r"proxy-ssl\.webflow\.com$",
        ],
        "notes": "Verify current error fingerprint before reporting.",
    },
    "tumblr": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"domains\.tumblr\.com$"],
        "notes": "",
    },
    "ghost": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [r"\.ghost\.io$"],
        "notes": "Re-verify current fingerprint.",
    },
    "netlify": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "notes": "",
    },
    "pantheon": {
        "confidence": "VERIFIED",
        "severity":   "HIGH",
        "cname_patterns": [r"\.pantheonsite\.io$", r"\.panth\.io$"],
        "notes": "",
    },
    "surge": {
        "confidence": "VERIFIED",
        "severity":   "MEDIUM",
        "cname_patterns": [r"\.surge\.sh$"],
        "notes": "Easy claim: surge --domain <domain>",
    },
    "bitbucket": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [r"\.bitbucket\.io$"],
        "notes": "Bitbucket Pages may be deprecated — verify first.",
    },
    "unbounce": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [r"\.unbouncepages\.com$"],
        "notes": "",
    },
    "statuspage": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [r"\.statuspage\.io$"],
        "notes": "",
    },
    "helpjuice": {
        "confidence": "UNCERTAIN",
        "severity":   "MEDIUM",
        "cname_patterns": [r"\.helpjuice\.com$"],
        "notes": "UNCERTAIN — do not report without manual verification.",
    },
    "helpscout": {
        "confidence": "UNCERTAIN",
        "severity":   "MEDIUM",
        "cname_patterns": [r"\.helpscoutdocs\.com$"],
        "notes": "UNCERTAIN — do not report without manual verification.",
    },
    "wpengine": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [r"\.wpengine\.com$"],
        "notes": "",
    },
    "readme_io": {
        "confidence": "PROBABLE",
        "severity":   "HIGH",
        "cname_patterns": [r"\.readme\.io$", r"\.readmessl\.com$"],
        "notes": "",
    },
    "squarespace": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [r"ext-cust\.squarespace\.com$"],
        "notes": "",
    },
    "intercom": {
        "confidence": "PROBABLE",
        "severity":   "MEDIUM",
        "cname_patterns": [r"custom\.intercom\.help$"],
        "notes": "",
    },
    "pingdom": {
        "confidence": "PROBABLE",
        "severity":   "LOW",
        "cname_patterns": [r"\.pingdom\.com$"],
        "notes": "",
    },
}

# Pre-compile all regex patterns once at startup
_COMPILED_SIGNATURES: Dict[str, List] = {
    service: [re.compile(p, re.IGNORECASE) for p in sig["cname_patterns"]]
    for service, sig in TAKEOVER_SIGNATURES.items()
}

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
    """DNS state for one domain at one point in time."""
    domain:      str
    timestamp:   str
    cname_chain: List[str] = field(default_factory=list)
    a_records:   List[str] = field(default_factory=list)
    ns_records:  List[str] = field(default_factory=list)
    resolves:    bool      = False
    nxdomain:    bool      = False
    error:       Optional[str] = None

    def fingerprint(self) -> str:
        """
        SHA-256 of sorted DNS state.
        If this matches between snapshots, nothing changed — skip processing.
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

    FIX 4: old_value and new_value are always List[str].
    Sets are converted before construction. No JSON crash.
    """
    domain:      str
    change_type: str       # NEW_CNAME | CNAME_REMOVED | A_CHANGED | NS_CHANGED | WENT_NXDOMAIN
    old_value:   List[str] # Always List, never Set
    new_value:   List[str] # Always List, never Set
    timestamp:   str

    takeover_risk:    bool = False
    matched_service:  str  = ""
    severity:         str  = ""
    confidence:       str  = ""
    notes:            str  = ""
    ready_for_nuclei: bool = False


@dataclass
class Alert:
    """
    A high-priority finding ready for action.
    Written as JSON to stdout for pipeline consumption.
    """
    domain:        str
    service:       str
    severity:      str
    confidence:    str
    change_type:   str
    cname_chain:   List[str]
    notes:         str
    timestamp:     str
    nuclei_target: str
    scan_id:       str = field(
        default_factory=lambda: hashlib.md5(
            str(time.time()).encode()
        ).hexdigest()[:8]
    )


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────

class WatchdogDB:
    """
    SQLite storage.

    FIX 5: Explicit connection cleanup via close_thread_connection().
           Called by ScanEngine after each ThreadPoolExecutor lifecycle.

    FIX 1: Alert deduplication via is_alert_pending().
           One unacknowledged alert per (domain, service) pair.

    FIX 2: Domain baseline tracking via is_baseline_established().
           First scan per domain sets baseline silently.
    """

    def __init__(self, db_path: str = "watchdog.db"):
        self.db_path = db_path
        self._local  = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        """Thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")  # Faster writes, safe with WAL
            self._local.conn = conn
        return self._local.conn

    def close_thread_connection(self):
        """
        FIX 5: Explicitly close this thread's DB connection.
        Call this from worker threads before they exit.
        Prevents WAL file accumulation from abandoned connections.
        """
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _init_schema(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS snapshots (
                domain          TEXT NOT NULL PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                cname_chain     TEXT NOT NULL DEFAULT '[]',
                a_records       TEXT NOT NULL DEFAULT '[]',
                ns_records      TEXT NOT NULL DEFAULT '[]',
                resolves        INTEGER NOT NULL DEFAULT 0,
                nxdomain        INTEGER NOT NULL DEFAULT 0,
                error           TEXT,
                fingerprint     TEXT NOT NULL,
                scan_count      INTEGER NOT NULL DEFAULT 0
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
            CREATE INDEX IF NOT EXISTS idx_alerts_pending
                ON alerts(domain, service, acknowledged);
        """)
        conn.commit()

    # ── Snapshot operations ───────────────────────────────────────────────

    def get_snapshot(self, domain: str) -> Optional[DNSSnapshot]:
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
        """Upsert DNS state. Increments scan_count for baseline tracking."""
        fp = snapshot.fingerprint()
        self._conn().execute("""
            INSERT INTO snapshots
                (domain, timestamp, cname_chain, a_records, ns_records,
                 resolves, nxdomain, error, fingerprint, scan_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(domain) DO UPDATE SET
                timestamp   = excluded.timestamp,
                cname_chain = excluded.cname_chain,
                a_records   = excluded.a_records,
                ns_records  = excluded.ns_records,
                resolves    = excluded.resolves,
                nxdomain    = excluded.nxdomain,
                error       = excluded.error,
                fingerprint = excluded.fingerprint,
                scan_count  = scan_count + 1
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

    def is_baseline_established(self, domain: str) -> bool:
        """
        FIX 2: Returns True if this domain has been seen before.

        On first scan (scan_count == 0 or no row), the domain
        is being baselined. No alerts should fire.
        On subsequent scans (scan_count >= 1), changes trigger alerts.
        """
        row = self._conn().execute(
            "SELECT scan_count FROM snapshots WHERE domain = ?", (domain,)
        ).fetchone()
        return row is not None and row["scan_count"] >= 1

    # ── Alert operations ──────────────────────────────────────────────────

    def is_alert_pending(self, domain: str, service: str) -> bool:
        """
        FIX 1: Check if an unacknowledged alert already exists
        for this (domain, service) pair.

        Prevents duplicate alerts on repeated scans of the same issue.
        """
        row = self._conn().execute("""
            SELECT id FROM alerts
            WHERE domain = ? AND service = ? AND acknowledged = 0
            LIMIT 1
        """, (domain, service)).fetchone()
        return row is not None

    def record_alert(self, alert: Alert):
        """
        FIX 1: Only insert if no pending alert exists for (domain, service).
        Deduplication at DB level — not application level.
        """
        if self.is_alert_pending(alert.domain, alert.service):
            return  # Already have an open alert for this issue

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

    def acknowledge_alert(self, domain: str, service: str):
        """Mark an alert as acknowledged (investigated/resolved)."""
        self._conn().execute("""
            UPDATE alerts SET acknowledged = 1
            WHERE domain = ? AND service = ? AND acknowledged = 0
        """, (domain, service))
        self._conn().commit()

    def record_change(self, change: DNSChange):
        """Record change to audit trail."""
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

    # ── Query operations ──────────────────────────────────────────────────

    def get_recent_alerts(self) -> List[Dict]:
        rows = self._conn().execute("""
            SELECT * FROM alerts
            WHERE acknowledged = 0
            ORDER BY timestamp DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_change_history(self, domain: str, limit: int = 20) -> List[Dict]:
        rows = self._conn().execute("""
            SELECT * FROM change_history
            WHERE domain = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (domain, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_all_tracked_domains(self) -> List[str]:
        rows = self._conn().execute(
            "SELECT domain FROM snapshots"
        ).fetchall()
        return [r["domain"] for r in rows]

    def domain_count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) FROM snapshots"
        ).fetchone()[0]


# ─────────────────────────────────────────────────────────────────────────────
# DNS ENGINE
#
# FIX 6: Rate limiting between resolver queries.
#         At 30 threads × 4 resolvers × CNAME depth, we generate
#         enormous query volume. A small sleep prevents throttling.
# ─────────────────────────────────────────────────────────────────────────────

class DNSEngine:
    """
    Multi-resolver DNS engine.

    FIX 6: dns_delay_seconds between resolver calls.
           Default 0.1s × 4 resolvers = 0.4s per domain.
           At 30 threads: ~75 queries/sec (well under any limit).
    """

    def __init__(self, timeout: float = 5.0, dns_delay: float = 0.05):
        self.timeout   = timeout
        self.dns_delay = dns_delay  # FIX 6: delay between resolver calls

    def _make_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [nameserver]
        r.timeout     = self.timeout
        r.lifetime    = self.timeout
        return r

    def _query(
        self,
        domain: str,
        rtype: str,
        nameserver: str,
    ) -> Tuple[List[str], bool]:
        """
        Query one record type from one nameserver.
        Returns (results, is_nxdomain).
        Always returns List[str] — never Set.  (FIX 4)
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
        visited: Optional[Set[str]] = None,
        depth: int = 0,
    ) -> Tuple[List[str], bool]:
        """
        Recursively follow CNAME chain.
        Returns (chain_as_list, encountered_nxdomain).

        visited is initialized fresh per call from resolve(),
        so it is never shared across resolvers.
        """
        if visited is None:
            visited = set()  # Fresh set — not a mutable default

        if depth > 10 or domain in visited:
            return [], False

        visited.add(domain)

        cnames, nxdomain = self._query(domain, "CNAME", nameserver)

        if nxdomain:
            return [], True
        if not cnames:
            return [], False

        chain = list(cnames)  # FIX 4: explicit list
        for cname in cnames:
            # Each recursive call shares the same visited set (by design —
            # prevents loops within one resolver's chain traversal)
            deeper, nx = self._follow_cname_chain(
                cname, nameserver, visited, depth + 1
            )
            if nx:
                return chain, True
            chain.extend(deeper)

        return chain, False

    def resolve(self, domain: str) -> DNSSnapshot:
        """
        Multi-resolver DNS resolution.

        FIX 6: Small delay between resolver calls.
        Each resolver gets a fresh visited set for CNAME chain following.
        """
        now      = datetime.now(timezone.utc).isoformat()
        snapshot = DNSSnapshot(domain=domain, timestamp=now)

        cname_chains:   List[List[str]] = []
        a_records_set:  Set[str]        = set()
        ns_records_set: Set[str]        = set()
        nxdomain_votes: int             = 0

        for i, ns in enumerate(DNS_RESOLVERS):
            # FIX 6: Rate limit between resolver calls
            if i > 0 and self.dns_delay > 0:
                time.sleep(self.dns_delay)

            # Fresh visited set per resolver — correct, independent chains
            chain, nx = self._follow_cname_chain(domain, ns, visited=None)
            if nx:
                nxdomain_votes += 1
            if chain:
                cname_chains.append(chain)

            a_recs, _ = self._query(domain, "A", ns)
            a_records_set.update(a_recs)

            # NS records: only one resolver needed
            if ns == DNS_RESOLVERS[0]:
                ns_recs, _ = self._query(domain, "NS", ns)
                ns_records_set.update(ns_recs)

        # Use longest CNAME chain (most complete traversal)
        if cname_chains:
            snapshot.cname_chain = max(cname_chains, key=len)

        # FIX 4: Always produce sorted lists, never sets
        snapshot.a_records  = sorted(a_records_set)
        snapshot.ns_records = sorted(ns_records_set)

        # NXDOMAIN consensus: 2+ resolvers must agree
        snapshot.nxdomain = nxdomain_votes >= 2

        snapshot.resolves = bool(snapshot.cname_chain or snapshot.a_records)

        return snapshot


# ─────────────────────────────────────────────────────────────────────────────
# CHANGE DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class ChangeDetector:
    """
    Diffs two DNSSnapshots and produces DNSChange events.
    All List[str] — no sets in output. (FIX 4)
    """

    def _match_signature(
        self,
        cname_list: List[str],
    ) -> Tuple[bool, str, str, str]:
        """
        Check list of CNAMEs against takeover signatures.
        Returns (matched, service, severity, confidence).
        """
        for cname in cname_list:
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
        baseline_established: bool,
    ) -> List[DNSChange]:
        """
        Diff old vs new snapshot.

        FIX 2: baseline_established parameter.
               If False, this is the first scan for this domain.
               We record it silently — no changes emitted, no alerts.
               Changes only fire when baseline_established is True.

        FIX 4: All set operations convert to sorted lists before
               building DNSChange objects.
        """
        now = datetime.now(timezone.utc).isoformat()
        changes: List[DNSChange] = []

        # ── FIX 2: Baseline scan ─────────────────────────────────────────────
        # First time seeing this domain: store snapshot silently.
        # No changes, no alerts. Baseline is established.
        if not baseline_established:
            return []

        # ── Brand new domain seen during monitoring (not first scan) ─────────
        if old is None:
            # This domain was added to the list after baseline.
            # Check its current state for takeover signatures.
            risk, service, severity, confidence = self._match_signature(
                new.cname_chain
            )
            if risk:
                changes.append(DNSChange(
                    domain          = new.domain,
                    change_type     = "NEW_MONITORED_DOMAIN",
                    old_value       = [],
                    new_value       = list(new.cname_chain),  # FIX 4: list()
                    timestamp       = now,
                    takeover_risk   = True,
                    matched_service = service,
                    severity        = severity,
                    confidence      = confidence,
                    notes           = "Domain added to monitoring after baseline. Takeover signature present.",
                    ready_for_nuclei = True,
                ))
            return changes

        # ── Fast path: fingerprint unchanged ────────────────────────────────
        if old.fingerprint() == new.fingerprint():
            return []

        # ── Case 1: CNAME chain changed ──────────────────────────────────────
        old_cname_set = set(old.cname_chain)
        new_cname_set = set(new.cname_chain)

        added_cnames   = new_cname_set - old_cname_set
        removed_cnames = old_cname_set - new_cname_set

        if added_cnames or removed_cnames:
            # FIX 4: Convert sets to sorted lists immediately
            added_list   = sorted(added_cnames)
            removed_list = sorted(removed_cnames)

            # Only check ADDED CNAMEs for takeover signatures
            # Existing CNAMEs were already baselined
            risk, service, severity, confidence = self._match_signature(added_list)

            if added_cnames:
                change_type = "NEW_CNAME"
                notes = f"Added: {added_list}"
                if removed_cnames:
                    notes += f" | Removed: {removed_list}"
            else:
                change_type = "CNAME_REMOVED"
                notes = f"Removed: {removed_list}"

            changes.append(DNSChange(
                domain          = new.domain,
                change_type     = change_type,
                old_value       = sorted(old_cname_set),  # FIX 4: sorted list
                new_value       = sorted(new_cname_set),  # FIX 4: sorted list
                timestamp       = now,
                takeover_risk   = risk,
                matched_service = service,
                severity        = severity,
                confidence      = confidence,
                notes           = notes,
                ready_for_nuclei = risk,
            ))

        # ── Case 2: A records changed ────────────────────────────────────────
        old_a_set = set(old.a_records)
        new_a_set = set(new.a_records)

        if old_a_set != new_a_set:
            added_ips   = sorted(new_a_set - old_a_set)   # FIX 4
            removed_ips = sorted(old_a_set - new_a_set)   # FIX 4

            changes.append(DNSChange(
                domain      = new.domain,
                change_type = "A_CHANGED",
                old_value   = sorted(old_a_set),           # FIX 4
                new_value   = sorted(new_a_set),           # FIX 4
                timestamp   = now,
                takeover_risk = False,
                notes = (
                    f"IPs added: {added_ips} | removed: {removed_ips}"
                ),
            ))

        # ── Case 3: NS records changed ───────────────────────────────────────
        old_ns_set = set(old.ns_records)
        new_ns_set = set(new.ns_records)

        if old_ns_set != new_ns_set:
            added_ns   = sorted(new_ns_set - old_ns_set)  # FIX 4
            removed_ns = sorted(old_ns_set - new_ns_set)  # FIX 4

            changes.append(DNSChange(
                domain          = new.domain,
                change_type     = "NS_CHANGED",
                old_value       = sorted(old_ns_set),      # FIX 4
                new_value       = sorted(new_ns_set),      # FIX 4
                timestamp       = now,
                takeover_risk   = bool(added_ns),
                severity        = "HIGH" if added_ns else "INFO",
                confidence      = "PROBABLE",
                notes           = (
                    f"NS added: {added_ns} | removed: {removed_ns}. "
                    f"Manual investigation recommended."
                ),
            ))

        # ── Case 4: Went NXDOMAIN ────────────────────────────────────────────
        if not old.nxdomain and new.nxdomain:
            changes.append(DNSChange(
                domain          = new.domain,
                change_type     = "WENT_NXDOMAIN",
                old_value       = list(old.cname_chain),   # FIX 4: already list
                new_value       = [],
                timestamp       = now,
                takeover_risk   = True,
                severity        = "MEDIUM",
                confidence      = "PROBABLE",
                notes           = (
                    "Domain previously resolved, now NXDOMAIN. "
                    "Potential dangling DNS record."
                ),
            ))

        return changes


# ─────────────────────────────────────────────────────────────────────────────
# NOTIFIER
# ─────────────────────────────────────────────────────────────────────────────

class Notifier:
    """
    Alert output.
    JSON → stdout (pipeline safe).
    Status → stderr (doesn't pollute pipeline).
    Webhook → optional Slack/Discord.
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
    ):
        self.webhook_url = webhook_url
        self.quiet       = quiet
        self._lock       = threading.Lock()

    def _err(self, msg: str):
        """Status to stderr — doesn't pollute stdout pipeline."""
        if not self.quiet:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {msg}", file=sys.stderr, flush=True)

    def emit_alert(self, alert: Alert):
        """
        Emit alert as JSON to stdout.
        Human summary to stderr.
        Webhook if configured.
        """
        # FIX 4: asdict() works cleanly because Alert contains only
        # List[str] fields — no sets anywhere in the object graph
        alert_dict = asdict(alert)

        with self._lock:
            print(json.dumps(alert_dict), flush=True)

        color = self.SEVERITY_COLORS.get(alert.severity, "")
        self._err(
            f"{color}[ALERT]{self.RESET} "
            f"{alert.severity} | {alert.domain} → {alert.service} | "
            f"{alert.confidence} | {alert.change_type}\n"
            f"         CNAME: {' → '.join(alert.cname_chain)}\n"
            f"         Verify: echo '{alert.nuclei_target}' | "
            f"nuclei -t takeovers/\n"
            f"         Notes: {alert.notes}"
        )

        if self.webhook_url:
            self._send_webhook(alert)

    def emit_change(self, change: DNSChange):
        """Non-alert change notification (to stderr only)."""
        self._err(
            f"[CHANGE] {change.domain} | {change.change_type} | "
            f"Risk: {change.takeover_risk}"
        )

    def status(self, msg: str):
        self._err(f"[*] {msg}")

    def _send_webhook(self, alert: Alert):
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
            alert.severity, "⚪"
        )
        try:
            payload = {
                "text": (
                    f"{emoji} *WATCHDOG ALERT*\n"
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
            self._err(f"[!] Webhook failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# SCAN ENGINE
#
# FIX 3: Stats reset at start of each run_scan() call.
# FIX 5: DB connection cleanup after ThreadPoolExecutor exits.
# FIX 7: ThreadPoolExecutor created once per Watchdog instance,
#         reused across scan cycles (no memory leak in watch mode).
# ─────────────────────────────────────────────────────────────────────────────

class ScanEngine:
    """
    Orchestrates: resolve → diff → alert pipeline.

    FIX 3: self.stats is reset at the top of run_scan().
    FIX 5: Worker threads call db.close_thread_connection() on cleanup.
    FIX 7: ThreadPoolExecutor is managed externally (by Watchdog),
           not created/destroyed per scan.
    """

    def __init__(
        self,
        db:             WatchdogDB,
        dns_engine:     DNSEngine,
        detector:       ChangeDetector,
        notifier:       Notifier,
        threads:        int  = 30,
        skip_uncertain: bool = True,
    ):
        self.db             = db
        self.dns            = dns_engine
        self.detector       = detector
        self.notifier       = notifier
        self.threads        = threads
        self.skip_uncertain = skip_uncertain
        self._lock          = threading.Lock()

        # FIX 3: stats initialized here but reset per scan
        self.stats: Dict = {}

    def _process_one(self, domain: str):
        """Full pipeline for one domain."""
        try:
            # Check baseline BEFORE resolving
            # (avoids resolving just to discard result)
            baseline_ok = self.db.is_baseline_established(domain)

            # Resolve current DNS state
            new_snapshot = self.dns.resolve(domain)

            # Get previous snapshot
            old_snapshot = self.db.get_snapshot(domain)

            # FIX 2: Pass baseline flag to diff()
            changes = self.detector.diff(old_snapshot, new_snapshot, baseline_ok)

            # Save new snapshot (increments scan_count)
            self.db.save_snapshot(new_snapshot)

            with self._lock:
                self.stats["resolved"] += 1

            if not changes:
                return

            with self._lock:
                self.stats["changed"] += 1

            for change in changes:
                # Record to audit trail
                self.db.record_change(change)

                # Emit informational change to stderr
                self.notifier.emit_change(change)

                if not change.takeover_risk:
                    continue

                # FIX 2: Don't alert on baseline scan
                if not baseline_ok:
                    continue

                # Skip UNCERTAIN unless configured otherwise
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
                    cname_chain   = list(new_snapshot.cname_chain),  # FIX 4
                    notes         = change.notes,
                    timestamp     = change.timestamp,
                    nuclei_target = change.domain,
                )

                # FIX 1: Deduplicate at DB level before emitting
                if self.db.is_alert_pending(alert.domain, alert.service):
                    self.notifier.status(
                        f"Suppressed duplicate alert: {alert.domain} → {alert.service}"
                    )
                    continue

                # Record alert (DB-level dedup as second guard)
                self.db.record_alert(alert)

                # Emit (stdout JSON + stderr human + webhook)
                self.notifier.emit_alert(alert)

                with self._lock:
                    self.stats["alerted"] += 1

        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
            self.notifier.status(f"Error [{domain}]: {e}")

        finally:
            # FIX 5: Close this thread's DB connection on task completion
            # ThreadPoolExecutor reuses threads, but closing and reopening
            # connections is cheap and prevents WAL file accumulation
            self.db.close_thread_connection()

    def run_scan(self, domains: List[str], executor: ThreadPoolExecutor) -> Dict:
        """
        Run one scan pass.

        FIX 3: Stats reset at start of each call.
        FIX 7: Executor passed in — not created here.
               Watchdog manages the executor lifecycle.
        """
        # FIX 3: Reset stats for this scan cycle
        with self._lock:
            self.stats = {
                "resolved": 0,
                "changed":  0,
                "alerted":  0,
                "errors":   0,
            }

        start = time.time()

        futures = {
            executor.submit(self._process_one, domain): domain
            for domain in domains
        }

        done = 0
        total = len(domains)
        for future in as_completed(futures):
            done += 1
            domain = futures[future]

            try:
                future.result()
            except Exception as e:
                self.notifier.status(f"Unhandled error [{domain}]: {e}")

            if done % 100 == 0 or done == total:
                with self._lock:
                    alerted = self.stats["alerted"]
                self.notifier.status(
                    f"Progress: {done}/{total} | Alerts: {alerted}"
                )

        elapsed = time.time() - start
        with self._lock:
            self.stats["elapsed"] = round(elapsed, 2)
            self.stats["speed"]   = round(total / max(elapsed, 0.001), 1)

        return dict(self.stats)


# ─────────────────────────────────────────────────────────────────────────────
# WATCHDOG - Main Orchestrator
#
# FIX 7: One ThreadPoolExecutor for the lifetime of the process.
#         Not created/destroyed per scan. No thread leak in watch mode.
# ─────────────────────────────────────────────────────────────────────────────

class Watchdog:
    """
    Main orchestrator.

    FIX 7: Creates one ThreadPoolExecutor at startup.
           Reused across all scan cycles in watch mode.
           Shut down cleanly on SIGINT/SIGTERM.
    """

    def __init__(self, config: Dict):
        self.config  = config
        self.running = True

        self.db = WatchdogDB(config.get("db_path", "watchdog.db"))

        self.dns_engine = DNSEngine(
            timeout   = config.get("timeout", 5.0),
            dns_delay = config.get("dns_delay", 0.05),
        )
        self.detector = ChangeDetector()
        self.notifier = Notifier(
            webhook_url = config.get("webhook"),
            quiet       = config.get("quiet", False),
        )

        self.engine = ScanEngine(
            db             = self.db,
            dns_engine     = self.dns_engine,
            detector       = self.detector,
            notifier       = self.notifier,
            threads        = config.get("threads", 30),
            skip_uncertain = not config.get("include_uncertain", False),
        )

        # FIX 7: One executor, reused across all scans
        self._executor = ThreadPoolExecutor(
            max_workers = config.get("threads", 30)
        )

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum, frame):
        """Graceful shutdown: stop loop, shutdown executor, exit."""
        self.notifier.status("Shutting down gracefully...")
        self.running = False
        # FIX 7: Clean shutdown of the shared executor
        self._executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(0)

    def load_domains(self) -> List[str]:
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
                print(
                    f"[ERROR] File not found: {self.config['file']}",
                    file=sys.stderr
                )
                sys.exit(1)

        if self.config.get("domain"):
            domains.append(self.config["domain"].lower())

        # Deduplicate, preserve order
        seen: Set[str] = set()
        return [d for d in domains if not (d in seen or seen.add(d))]

    def run_once(self, domains: List[str]) -> Dict:
        """Single scan pass."""
        baseline_count = sum(
            1 for d in domains
            if self.db.is_baseline_established(d)
        )
        new_count = len(domains) - baseline_count

        if new_count > 0:
            self.notifier.status(
                f"Baseline: {new_count} new domains (silent) | "
                f"Monitoring: {baseline_count} known domains"
            )

        stats = self.engine.run_scan(domains, self._executor)
        self._print_stats(stats, len(domains))
        return stats

    def run_watch(self, domains: List[str], interval: int):
        """
        Continuous monitoring loop.

        FIX 7: Reuses self._executor across all scan cycles.
        """
        scan_count = 0
        self.notifier.status(
            f"Watch mode: {len(domains)} domains | "
            f"Interval: {interval}min | "
            f"DB: {self.config.get('db_path', 'watchdog.db')}"
        )

        while self.running:
            scan_count += 1
            self.notifier.status(f"─── Scan #{scan_count} ───")

            stats = self.engine.run_scan(domains, self._executor)
            self._print_stats(stats, len(domains))

            if not self.running:
                break

            self.notifier.status(
                f"Next scan in {interval} minutes. Ctrl+C to stop."
            )

            # Chunked sleep: responsive to Ctrl+C
            for _ in range(interval * 60):
                if not self.running:
                    break
                time.sleep(1)

    def _print_stats(self, stats: Dict, total: int):
        """FIX 3: These stats are now per-scan, not cumulative."""
        self.notifier.status(
            f"Scan complete | "
            f"Resolved: {stats.get('resolved', 0)}/{total} | "
            f"Changed: {stats.get('changed', 0)} | "
            f"Alerted: {stats.get('alerted', 0)} | "
            f"Errors: {stats.get('errors', 0)} | "
            f"{stats.get('speed', 0)}/s | "
            f"{stats.get('elapsed', 0)}s"
        )

    def show_alerts(self):
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

    def acknowledge(self, domain: str, service: str):
        """Acknowledge an alert (mark as investigated)."""
        self.db.acknowledge_alert(domain, service)
        self.notifier.status(f"Acknowledged: {domain} → {service}")

    def export_targets(self, output_file: str):
        alerts  = self.db.get_recent_alerts()
        domains = sorted({a["domain"] for a in alerts})
        if not domains:
            print("[*] No pending alerts to export.", file=sys.stderr)
            return
        with open(output_file, "w") as fh:
            fh.write("\n".join(domains) + "\n")
        print(
            f"[*] Exported {len(domains)} targets → {output_file}",
            file=sys.stderr
        )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """
██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝
██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗
██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║
╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝

  DNS Change Monitor v2.0 | Bug Bounty Continuous Intelligence
  "Don't scan better. See changes faster."
"""


def main():
    parser = argparse.ArgumentParser(
        description="WATCHDOG v2.0 - DNS Change Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES:
  scan      One-time scan (baseline + detect changes)
  watch     Continuous monitoring (the actual alpha)
  alerts    Show pending alerts
  history   Show change history for a domain
  ack       Acknowledge an alert
  export    Export alert targets for nuclei

WORKFLOW:
  # Build target list
  subfinder -d target.com -silent > targets.txt

  # First scan = silent baseline (no alerts)
  python3 watchdog.py scan -f targets.txt

  # Continuous monitoring
  python3 watchdog.py watch -f targets.txt --interval 60

  # Pipeline: alerts direct to nuclei
  python3 watchdog.py watch -f targets.txt | \\
    jq -r '.nuclei_target' | \\
    nuclei -t takeovers/

  # Slack notifications
  python3 watchdog.py watch -f targets.txt \\
    --webhook https://hooks.slack.com/services/YOUR/HOOK

  # After investigating an alert
  python3 watchdog.py ack api.target.com github_pages

  # Export for nuclei
  python3 watchdog.py export -o verify.txt && \\
    nuclei -l verify.txt -t takeovers/
        """
    )

    sub = parser.add_subparsers(dest="mode")

    # Shared arguments
    def add_shared(p):
        p.add_argument("-f", "--file",    help="Domain list file")
        p.add_argument("-d", "--domain",  help="Single domain")
        p.add_argument("-t", "--threads", type=int,   default=30)
        p.add_argument("--timeout",       type=float, default=5.0)
        p.add_argument("--dns-delay",     type=float, default=0.05,
                       help="Delay between DNS resolver calls (default: 0.05s)")
        p.add_argument("--include-uncertain", action="store_true")
        p.add_argument("--webhook",       help="Slack/Discord webhook URL")
        p.add_argument("--db",            default="watchdog.db")
        p.add_argument("-q", "--quiet",   action="store_true")

    scan_p = sub.add_parser("scan",    help="One-time scan")
    add_shared(scan_p)

    watch_p = sub.add_parser("watch",   help="Continuous monitoring")
    add_shared(watch_p)
    watch_p.add_argument("--interval", type=int, default=60,
                         help="Scan interval in minutes (default: 60)")

    alerts_p = sub.add_parser("alerts",  help="Show pending alerts")
    alerts_p.add_argument("--db", default="watchdog.db")

    history_p = sub.add_parser("history", help="Show domain change history")
    history_p.add_argument("domain")
    history_p.add_argument("--db", default="watchdog.db")

    ack_p = sub.add_parser("ack",  help="Acknowledge an alert")
    ack_p.add_argument("domain")
    ack_p.add_argument("service")
    ack_p.add_argument("--db", default="watchdog.db")

    export_p = sub.add_parser("export", help="Export alert targets")
    export_p.add_argument("-o", "--output", default="nuclei_targets.txt")
    export_p.add_argument("--db", default="watchdog.db")

    args = parser.parse_args()

    if not args.mode:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    print(BANNER, file=sys.stderr)

    config = {
        "file":              getattr(args, "file",             None),
        "domain":            getattr(args, "domain",           None),
        "threads":           getattr(args, "threads",          30),
        "timeout":           getattr(args, "timeout",          5.0),
        "dns_delay":         getattr(args, "dns_delay",        0.05),
        "include_uncertain": getattr(args, "include_uncertain",False),
        "webhook":           getattr(args, "webhook",          None),
        "db_path":           getattr(args, "db",               "watchdog.db"),
        "quiet":             getattr(args, "quiet",            False),
    }

    watchdog = Watchdog(config)

    if args.mode in ("scan", "watch"):
        domains = watchdog.load_domains()
        if not domains:
            print("[ERROR] No domains provided.", file=sys.stderr)
            sys.exit(1)

        print(
            f"[*] Targets: {len(domains)} | "
            f"Threads: {config['threads']} | "
            f"Signatures: {len(TAKEOVER_SIGNATURES)} | "
            f"DB: {config['db_path']}",
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

    elif args.mode == "ack":
        watchdog.acknowledge(args.domain, args.service)

    elif args.mode == "export":
        watchdog.export_targets(args.output)


if __name__ == "__main__":
    main()
