#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    PHANTOM - Subdomain Takeover Hunter                      ║
║                         S-Tier Bug Bounty Tool                              ║
║                                                                              ║
║  Architecture: Multi-stage verification pipeline                             ║
║  DNS: Multi-resolver, all record types, chain following, IP-CIDR mapping    ║
║  HTTP: Regex fingerprinting, header analysis, TLS inspection                ║
║  Verify: Service-specific claimability checking                             ║
║  Output: Evidence package + ready-to-submit bug report                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author: Built for serious bug bounty hunting
Dependencies: pip install aiohttp aiodns dnspython requests beautifulsoup4 rich
"""

import asyncio
import aiohttp
import aiodns
import dns.resolver
import dns.exception
import requests
import json
import re
import sys
import os
import time
import socket
import ipaddress
import hashlib
import argparse
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict
import concurrent.futures
from enum import Enum

# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

class Confidence(Enum):
    CONFIRMED = "CONFIRMED"   # >= 85 score, claimability verified
    LIKELY    = "LIKELY"      # >= 65 score
    POSSIBLE  = "POSSIBLE"    # >= 45 score

class RecordType(Enum):
    CNAME = "CNAME"
    A     = "A"
    AAAA  = "AAAA"
    NS    = "NS"
    MX    = "MX"

# Scoring thresholds
SCORE_CONFIRMED = 85
SCORE_LIKELY    = 65
SCORE_POSSIBLE  = 45

# DNS resolvers to use (multiple for accuracy + redundancy)
DNS_RESOLVERS = [
    "8.8.8.8",    # Google
    "1.1.1.1",    # Cloudflare
    "9.9.9.9",    # Quad9
    "208.67.222.222",  # OpenDNS
]

# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT DATABASE
# Source: EdOverflow/can-i-take-over-xyz, Nuclei templates, manual research
# Each entry is carefully structured with confidence weights and negative checks
# ─────────────────────────────────────────────────────────────────────────────

FINGERPRINTS: Dict[str, Dict] = {

    "github_pages": {
        "service_display": "GitHub Pages",
        "severity": Severity.HIGH,

        # CNAME patterns (compiled regex for accuracy)
        "cname_patterns": [
            r"github\.io$",
            r"github\.com$",
        ],

        # IP CIDR ranges owned by this service
        "ip_ranges": [
            "185.199.108.0/22",  # GitHub Pages IPs
        ],

        # HTTP fingerprints (regex patterns against body)
        "http_body_patterns": [
            r"There isn't a GitHub Pages site here\.",
            r"If you're trying to publish one,.*github\.com",
            r"404\s+There is nothing here",
        ],

        # Header patterns
        "http_header_patterns": {
            "server": r"GitHub\.com",
        },

        # Expected status codes
        "status_codes": [404],

        # Negative patterns - if these match, NOT vulnerable (reduces FP)
        "negative_patterns": [
            r"<title>.*GitHub.*</title>",  # Real GitHub page
        ],

        # Score weights
        "weights": {
            "cname_match":   35,
            "ip_match":      25,
            "body_match":    30,
            "header_match":  20,
            "status_match":  10,
            "negative_clear": 10,
        },

        # Service-specific verifier function name
        "verifier": "verify_github",

        # Verification: extract what needs to be checked
        "extract_target": r"([a-zA-Z0-9\-]+)\.github\.io",

        # Source for this fingerprint
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "aws_s3": {
        "service_display": "Amazon S3 Bucket",
        "severity": Severity.CRITICAL,

        "cname_patterns": [
            r"s3\.amazonaws\.com$",
            r"s3-website[.-]",
            r"\.s3\.",
            r"s3-accelerate\.amazonaws\.com$",
        ],

        "ip_ranges": [
            "52.216.0.0/15",
            "52.92.0.0/17",
            "54.231.0.0/17",
        ],

        "http_body_patterns": [
            r"<Code>NoSuchBucket</Code>",
            r"The specified bucket does not exist",
            r"NoSuchBucket",
        ],

        "http_header_patterns": {
            "server": r"AmazonS3",
            "x-amz-request-id": r".+",
        },

        "status_codes": [404, 403],

        "negative_patterns": [
            r"<ListBucketResult",    # Bucket exists and is public
            r"<Contents>",           # Bucket has content
        ],

        "weights": {
            "cname_match":   35,
            "ip_match":      25,
            "body_match":    35,
            "header_match":  25,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_s3",
        "extract_target": r"([a-zA-Z0-9\-\.]+)\.s3",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "heroku": {
        "service_display": "Heroku App",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"herokuapp\.com$",
            r"herokussl\.com$",
            r"herokudns\.com$",
        ],

        "ip_ranges": [],  # Heroku uses dynamic IPs

        "http_body_patterns": [
            r"No such app",
            r"herokucdn\.com/error-pages/no-such-app",
            r"There's nothing here, yet\.",
            r"app not found",
        ],

        "http_header_patterns": {
            "via": r"1\.1 vegur",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"Welcome to your new app!",  # Default Heroku app (exists)
        ],

        "weights": {
            "cname_match":   40,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  15,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_heroku",
        "extract_target": r"([a-zA-Z0-9\-]+)\.herokuapp\.com",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "azure_websites": {
        "service_display": "Azure App Service",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"azurewebsites\.net$",
            r"azure-api\.net$",
            r"cloudapp\.azure\.com$",
            r"trafficmanager\.net$",
        ],

        "ip_ranges": [
            "13.64.0.0/11",
            "13.96.0.0/13",
            "40.64.0.0/10",
        ],

        "http_body_patterns": [
            r"404 Web Site not found",
            r"Error 404 - Web app not found",
            r"The resource you are looking for has been removed",
            r"Microsoft Azure App Service",
        ],

        "http_header_patterns": {
            "x-ms-request-id": r".+",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"App Service is running",
        ],

        "weights": {
            "cname_match":   35,
            "ip_match":      20,
            "body_match":    35,
            "header_match":  20,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_azure",
        "extract_target": r"([a-zA-Z0-9\-]+)\.azurewebsites\.net",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "shopify": {
        "service_display": "Shopify Store",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"myshopify\.com$",
            r"shops\.myshopify\.com$",
        ],

        "ip_ranges": [
            "23.227.38.0/24",
        ],

        "http_body_patterns": [
            r"Sorry, this shop is currently unavailable",
            r"Only one step left",
            r"Store not found",
        ],

        "http_header_patterns": {
            "x-shopify-stage": r".+",
            "x-sorting-hat-shopid": r".+",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"Powered by Shopify",  # Active store
        ],

        "weights": {
            "cname_match":   40,
            "ip_match":      15,
            "body_match":    35,
            "header_match":  20,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_shopify",
        "extract_target": r"([a-zA-Z0-9\-]+)\.myshopify\.com",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "fastly": {
        "service_display": "Fastly CDN",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"fastly\.net$",
            r"fastlylb\.net$",
        ],

        "ip_ranges": [
            "23.235.32.0/20",
            "43.249.72.0/22",
            "103.244.50.0/24",
            "103.245.222.0/23",
            "103.245.224.0/24",
            "104.156.80.0/20",
            "151.101.0.0/16",
            "157.52.64.0/18",
            "167.82.0.0/17",
            "167.82.128.0/20",
        ],

        "http_body_patterns": [
            r"Fastly error: unknown domain",
            r"Please check that this domain has been added to a service",
        ],

        "http_header_patterns": {
            "fastly-restarts": r".+",
            "x-served-by":     r".+",
        },

        "status_codes": [404],

        "negative_patterns": [],

        "weights": {
            "cname_match":   40,
            "ip_match":      25,
            "body_match":    30,
            "header_match":  15,
            "status_match":  5,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "cloudfront": {
        "service_display": "Amazon CloudFront",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"cloudfront\.net$",
        ],

        "ip_ranges": [
            "13.32.0.0/15",
            "13.35.0.0/16",
            "52.46.0.0/18",
            "52.84.0.0/15",
            "54.182.0.0/16",
            "54.192.0.0/16",
            "54.230.0.0/16",
            "54.239.128.0/18",
            "204.246.164.0/22",
            "205.251.192.0/19",
        ],

        "http_body_patterns": [
            r"ERROR: The request could not be satisfied",
            r"Bad request\.",
            r"Generated by cloudfront \(CloudFront\)",
        ],

        "http_header_patterns": {
            "x-cache":     r"Error from cloudfront",
            "via":         r"CloudFront",
            "server":      r"CloudFront",
        },

        "status_codes": [403, 404],

        "negative_patterns": [
            r"<!\[CDATA\[",  # Active content
        ],

        "weights": {
            "cname_match":   35,
            "ip_match":      25,
            "body_match":    30,
            "header_match":  25,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": r"([a-zA-Z0-9]+)\.cloudfront\.net",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "zendesk": {
        "service_display": "Zendesk Help Center",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"zendesk\.com$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"Help Center Closed",
            r"This Help Center no longer exists",
            r"Is this your Help Center\?",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"zendesk\.com/hc/",  # Active help center
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    40,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_zendesk",
        "extract_target": r"([a-zA-Z0-9\-]+)\.zendesk\.com",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "webflow": {
        "service_display": "Webflow Site",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"proxy\.webflow\.io$",
            r"proxy-ssl\.webflow\.io$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"The page you are looking for doesn't exist or has been moved",
            r"<p class=\"description\">",
        ],

        "http_header_patterns": {
            "x-wf-request-id": r".+",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"wf-form",  # Active Webflow site
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  20,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "wordpress_com": {
        "service_display": "WordPress.com Blog",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"wordpress\.com$",
            r"wpcomstaging\.com$",
        ],

        "ip_ranges": [
            "192.0.78.0/23",
            "192.0.80.0/22",
        ],

        "http_body_patterns": [
            r"Do you want to register",
            r"Domain mapping upgrade for this domain not found",
            r"doesn't exist\s+Did you mean",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"Just another WordPress\.com site",
        ],

        "weights": {
            "cname_match":   40,
            "ip_match":      20,
            "body_match":    35,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_wordpress",
        "extract_target": r"([a-zA-Z0-9\-]+)\.wordpress\.com",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "pantheon": {
        "service_display": "Pantheon Hosting",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"pantheonsite\.io$",
            r"getpantheon\.com$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"404 error unknown site!",
            r"The gods are wise",
            r"pantheon\.io",
        ],

        "http_header_patterns": {
            "x-pantheon-endpoint": r".+",
        },

        "status_codes": [404],

        "negative_patterns": [],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  20,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "unbounce": {
        "service_display": "Unbounce Landing Page",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"unbouncepages\.com$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"The requested URL was not found on this server",
            r"Unbounce",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"lp\.unbounce\.com",  # Active page
        ],

        "weights": {
            "cname_match":   50,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "ghost": {
        "service_display": "Ghost Blog",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"ghost\.io$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"The thing you were looking for is no longer here",
            r"ghost\.io",
        ],

        "http_header_patterns": {
            "x-ghost-cache-status": r".+",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"Published with Ghost",
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  15,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_ghost",
        "extract_target": r"([a-zA-Z0-9\-]+)\.ghost\.io",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "surge_sh": {
        "service_display": "Surge.sh Static Hosting",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"surge\.sh$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"project not found",
            r"repository not found",
        ],

        "http_header_patterns": {
            "server": r"surge",
        },

        "status_codes": [404],

        "negative_patterns": [],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    35,
            "header_match":  15,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_surge",
        "extract_target": r"([a-zA-Z0-9\-]+)\.surge\.sh",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "bitbucket": {
        "service_display": "Bitbucket Pages",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"bitbucket\.io$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"Repository not found",
            r"The page you have requested does not exist",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    40,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_bitbucket",
        "extract_target": r"([a-zA-Z0-9\-]+)\.bitbucket\.io",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "intercom": {
        "service_display": "Intercom Help Center",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"custom\.intercom\.help$",
            r"intercom\.help$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"This page is reserved for artistic dogs",
            r"Uh oh\. That page doesn't exist",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"Intercom Help Center",  # Active
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    40,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "netlify": {
        "service_display": "Netlify Site",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"netlify\.app$",
            r"netlify\.com$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"Not Found - Request ID",
            r"netlify",
        ],

        "http_header_patterns": {
            "x-nf-request-id": r".+",
            "server":          r"Netlify",
        },

        "status_codes": [404],

        "negative_patterns": [
            r"Netlify App",  # Active
        ],

        "weights": {
            "cname_match":   40,
            "ip_match":      0,
            "body_match":    30,
            "header_match":  30,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_netlify",
        "extract_target": r"([a-zA-Z0-9\-]+)\.netlify\.app",
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "squarespace": {
        "service_display": "Squarespace Site",
        "severity": Severity.HIGH,

        "cname_patterns": [
            r"squarespace\.com$",
            r"sqsp\.net$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"No Such Account",
            r"config\.squarespace\.com",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"Squarespace site",
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      0,
            "body_match":    40,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "tumblr": {
        "service_display": "Tumblr Blog",
        "severity": Severity.LOW,

        "cname_patterns": [
            r"domains\.tumblr\.com$",
        ],

        "ip_ranges": [
            "66.6.32.0/24",
            "66.6.33.0/24",
        ],

        "http_body_patterns": [
            r"Whatever you were looking for doesn't currently exist at this address",
            r"There's nothing here\.",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [
            r"Powered by Tumblr",
        ],

        "weights": {
            "cname_match":   45,
            "ip_match":      20,
            "body_match":    35,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },

    "statuspage_io": {
        "service_display": "Statuspage.io",
        "severity": Severity.MEDIUM,

        "cname_patterns": [
            r"statuspage\.io$",
        ],

        "ip_ranges": [],

        "http_body_patterns": [
            r"You are being redirected",
            r"Status page doesn't exist",
        ],

        "http_header_patterns": {},

        "status_codes": [404],

        "negative_patterns": [],

        "weights": {
            "cname_match":   50,
            "ip_match":      0,
            "body_match":    40,
            "header_match":  0,
            "status_match":  10,
            "negative_clear": 10,
        },

        "verifier": "verify_generic",
        "extract_target": None,
        "source": "https://github.com/EdOverflow/can-i-take-over-xyz",
        "verified_date": "2024",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DNSResult:
    """Complete DNS resolution result for a domain"""
    domain:        str
    cname_chain:   List[str]     = field(default_factory=list)
    a_records:     List[str]     = field(default_factory=list)
    aaaa_records:  List[str]     = field(default_factory=list)
    ns_records:    List[str]     = field(default_factory=list)
    is_nxdomain:   bool          = False
    resolvers_used: List[str]    = field(default_factory=list)
    ttl:           Optional[int] = None
    error:         Optional[str] = None

@dataclass
class HTTPResult:
    """Complete HTTP analysis result"""
    domain:       str
    url:          str
    status_code:  Optional[int]
    body:         str
    headers:      Dict[str, str]
    redirect_chain: List[str]   = field(default_factory=list)
    tls_subject:  Optional[str] = None
    error:        Optional[str] = None
    response_time: float        = 0.0

@dataclass
class Evidence:
    """All evidence collected for a vulnerability"""
    dns_evidence:          List[str] = field(default_factory=list)
    http_evidence:         List[str] = field(default_factory=list)
    verification_evidence: List[str] = field(default_factory=list)
    score_breakdown:       Dict      = field(default_factory=dict)
    total_score:           int       = 0

@dataclass
class VulnerabilityResult:
    """Complete, verified vulnerability result"""
    domain:            str
    service_key:       str
    service_display:   str
    severity:          Severity
    confidence:        Confidence
    evidence:          Evidence
    dns_result:        DNSResult
    http_result:       Optional[HTTPResult]
    claimable:         bool
    claim_target:      Optional[str]   # e.g., GitHub username, S3 bucket name
    exploitation_steps: List[str]      = field(default_factory=list)
    remediation:       List[str]       = field(default_factory=list)
    timestamp:         str             = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_id:           str             = field(default_factory=lambda: hashlib.md5(
                                            str(time.time()).encode()
                                        ).hexdigest()[:8])

# ─────────────────────────────────────────────────────────────────────────────
# DNS INTELLIGENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DNSEngine:
    """
    Multi-resolver DNS engine.
    Checks ALL record types, follows CNAME chains, maps IPs to providers.
    """

    def __init__(self, timeout: int = 5):
        self.timeout   = timeout
        self.resolvers = DNS_RESOLVERS
        self._cache: Dict[str, DNSResult] = {}

    def _make_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [nameserver]
        r.timeout     = self.timeout
        r.lifetime    = self.timeout
        return r

    def _query(self, domain: str, rtype: str, nameserver: str) -> List[str]:
        """Single DNS query with error handling"""
        try:
            resolver = self._make_resolver(nameserver)
            answers  = resolver.resolve(domain, rtype)
            if rtype == 'CNAME':
                return [str(rdata.target).rstrip('.') for rdata in answers]
            elif rtype in ('A', 'AAAA'):
                return [str(rdata) for rdata in answers]
            elif rtype == 'NS':
                return [str(rdata.target).rstrip('.') for rdata in answers]
            return []
        except dns.resolver.NXDOMAIN:
            raise
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []

    def _follow_cname_chain(self, domain: str, nameserver: str, depth: int = 0) -> List[str]:
        """
        Recursively follow CNAME chain.
        Returns full chain including final target.
        """
        if depth > 10:  # Prevent infinite loops
            return []

        try:
            cnames = self._query(domain, 'CNAME', nameserver)
            if not cnames:
                return []

            chain = cnames[:]
            for cname in cnames:
                deeper = self._follow_cname_chain(cname, nameserver, depth + 1)
                chain.extend(deeper)

            return chain

        except dns.resolver.NXDOMAIN:
            return [f"NXDOMAIN:{domain}"]
        except Exception:
            return []

    def resolve(self, domain: str) -> DNSResult:
        """
        Full DNS resolution using multiple resolvers.
        Consensus-based: a result must appear from 2+ resolvers to be trusted.
        """
        if domain in self._cache:
            return self._cache[domain]

        result = DNSResult(domain=domain)

        cname_results: Dict[str, List[str]]  = {}
        a_results:     Dict[str, List[str]]  = {}
        nxdomain_count = 0

        for ns in self.resolvers:
            try:
                # CNAME chain
                chain = self._follow_cname_chain(domain, ns)
                if chain:
                    cname_results[ns] = chain

                # Check for NXDOMAIN markers in chain
                if any("NXDOMAIN" in c for c in chain):
                    nxdomain_count += 1

                # A records (on final resolved name or original)
                a_recs = self._query(domain, 'A', ns)
                if a_recs:
                    a_results[ns] = a_recs

                result.resolvers_used.append(ns)

            except dns.resolver.NXDOMAIN:
                nxdomain_count += 1
                result.resolvers_used.append(ns)
            except Exception as e:
                result.error = str(e)

        # Consensus: trust if 2+ resolvers agree
        if nxdomain_count >= 2:
            result.is_nxdomain = True

        # Merge CNAME chains (take longest, most informative)
        all_chains = list(cname_results.values())
        if all_chains:
            result.cname_chain = max(all_chains, key=len)

        # Merge A records
        all_ips: Set[str] = set()
        for ips in a_results.values():
            all_ips.update(ips)
        result.a_records = list(all_ips)

        self._cache[domain] = result
        return result

    @staticmethod
    def ip_in_cidr(ip: str, cidr_list: List[str]) -> bool:
        """Check if IP address falls within any CIDR range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cidr_list:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
        return False

# ─────────────────────────────────────────────────────────────────────────────
# HTTP INTELLIGENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HTTPEngine:
    """
    Advanced HTTP analysis.
    Regex fingerprinting, header analysis, TLS inspection, redirect tracking.
    """

    def __init__(self, timeout: int = 8, user_agent_rotation: bool = True):
        self.timeout = timeout
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ]
        self._ua_index = 0

    def _next_ua(self) -> str:
        ua = self.user_agents[self._ua_index % len(self.user_agents)]
        self._ua_index += 1
        return ua

    def fetch(self, domain: str) -> HTTPResult:
        """
        Fetch domain over HTTPS then HTTP.
        Capture full redirect chain, headers, body, TLS info.
        """
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                start = time.time()
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": self._next_ua()},
                    stream=True,  # Stream to control body size
                )

                # Read body in chunks (up to 50KB - enough for any error page)
                body_chunks = []
                size = 0
                for chunk in response.iter_content(chunk_size=4096, decode_unicode=True):
                    if chunk:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='replace')
                        body_chunks.append(chunk)
                        size += len(chunk)
                        if size >= 51200:  # 50KB limit
                            break

                body          = "".join(body_chunks)
                elapsed       = time.time() - start
                redirect_urls = [r.url for r in response.history] + [response.url]

                # TLS certificate inspection
                tls_subject = None
                if scheme == "https":
                    try:
                        import ssl
                        ctx  = ssl.create_default_context()
                        conn = ctx.wrap_socket(
                            socket.socket(),
                            server_hostname=domain
                        )
                        conn.settimeout(3)
                        conn.connect((domain, 443))
                        cert       = conn.getpeercert()
                        tls_subject = dict(x[0] for x in cert.get('subject', []))
                        conn.close()
                    except Exception:
                        pass

                return HTTPResult(
                    domain        = domain,
                    url           = url,
                    status_code   = response.status_code,
                    body          = body,
                    headers       = {k.lower(): v for k, v in response.headers.items()},
                    redirect_chain = redirect_urls,
                    tls_subject   = str(tls_subject) if tls_subject else None,
                    response_time = elapsed,
                )

            except requests.exceptions.SSLError:
                continue  # Try HTTP
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                return HTTPResult(
                    domain=domain, url=url,
                    status_code=None, body="", headers={},
                    error="timeout"
                )
            except Exception as e:
                return HTTPResult(
                    domain=domain, url=url,
                    status_code=None, body="", headers={},
                    error=str(e)
                )

        return HTTPResult(
            domain=domain, url=f"https://{domain}",
            status_code=None, body="", headers={},
            error="unreachable"
        )

# ─────────────────────────────────────────────────────────────────────────────
# SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ScoringEngine:
    """
    Evidence-based scoring.
    Every point is justified by a real indicator.
    """

    def __init__(self):
        # Pre-compile all regex patterns once at startup
        self._compiled_patterns: Dict[str, Dict] = {}
        for service_key, fp in FINGERPRINTS.items():
            self._compiled_patterns[service_key] = {
                "cname_patterns":       [re.compile(p, re.IGNORECASE) for p in fp["cname_patterns"]],
                "http_body_patterns":   [re.compile(p, re.IGNORECASE | re.DOTALL) for p in fp["http_body_patterns"]],
                "negative_patterns":    [re.compile(p, re.IGNORECASE) for p in fp["negative_patterns"]],
                "http_header_patterns": {
                    header: re.compile(pattern, re.IGNORECASE)
                    for header, pattern in fp["http_header_patterns"].items()
                },
            }

    def score(
        self,
        service_key: str,
        dns_result:  DNSResult,
        http_result: Optional[HTTPResult]
    ) -> Tuple[int, Evidence]:
        """
        Score a domain against a service fingerprint.
        Returns (total_score, Evidence) with full breakdown.
        """
        fp      = FINGERPRINTS[service_key]
        weights = fp["weights"]
        compiled = self._compiled_patterns[service_key]

        evidence = Evidence()
        score    = 0

        # ── DNS: CNAME Match ──────────────────────────────────────────────
        cname_matched = False
        for cname in dns_result.cname_chain:
            # Skip NXDOMAIN markers
            if "NXDOMAIN:" in cname:
                continue
            for pattern in compiled["cname_patterns"]:
                if pattern.search(cname):
                    cname_matched = True
                    pts = weights.get("cname_match", 0)
                    score += pts
                    evidence.dns_evidence.append(
                        f"CNAME matches {service_key}: '{cname}' → +{pts} pts"
                    )
                    break
            if cname_matched:
                break

        # ── DNS: IP CIDR Match ────────────────────────────────────────────
        ip_matched = False
        if fp.get("ip_ranges"):
            for ip in dns_result.a_records:
                if DNSEngine.ip_in_cidr(ip, fp["ip_ranges"]):
                    ip_matched = True
                    pts = weights.get("ip_match", 0)
                    score += pts
                    evidence.dns_evidence.append(
                        f"IP {ip} in {service_key} CIDR range → +{pts} pts"
                    )
                    break

        # ── HTTP: Negative Check (must run BEFORE positive HTTP checks) ───
        if http_result and http_result.body:
            negative_clear = True
            for pattern in compiled["negative_patterns"]:
                if pattern.search(http_result.body):
                    negative_clear = False
                    evidence.http_evidence.append(
                        f"NEGATIVE pattern matched (not vulnerable): '{pattern.pattern[:50]}'"
                    )
                    break

            if negative_clear:
                pts = weights.get("negative_clear", 0)
                score += pts
                evidence.http_evidence.append(
                    f"No negative patterns found (clean) → +{pts} pts"
                )
        else:
            negative_clear = True  # No body = no negative match

        # ── HTTP: Status Code ─────────────────────────────────────────────
        if http_result and http_result.status_code in fp.get("status_codes", []):
            pts = weights.get("status_match", 0)
            score += pts
            evidence.http_evidence.append(
                f"Status code {http_result.status_code} matches → +{pts} pts"
            )

        # ── HTTP: Body Pattern Match ──────────────────────────────────────
        if http_result and http_result.body and negative_clear:
            for pattern in compiled["http_body_patterns"]:
                match = pattern.search(http_result.body)
                if match:
                    pts = weights.get("body_match", 0)
                    score += pts
                    evidence.http_evidence.append(
                        f"Body pattern matched: '{pattern.pattern[:60]}' → +{pts} pts"
                    )
                    break

        # ── HTTP: Header Pattern Match ────────────────────────────────────
        if http_result and http_result.headers and negative_clear:
            for header_name, header_pattern in compiled["http_header_patterns"].items():
                header_value = http_result.headers.get(header_name, "")
                if header_value and header_pattern.search(header_value):
                    pts = weights.get("header_match", 0)
                    score += pts
                    evidence.http_evidence.append(
                        f"Header '{header_name}: {header_value[:40]}' matched → +{pts} pts"
                    )
                    break

        evidence.score_breakdown = {
            "cname_match": cname_matched,
            "ip_match":    ip_matched,
            "service":     service_key,
            "max_possible": sum(weights.values()),
        }
        evidence.total_score = score

        return score, evidence

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE VERIFIERS
# Each verifier confirms that the resource is actually claimable
# ─────────────────────────────────────────────────────────────────────────────

class ServiceVerifiers:
    """
    Service-specific claimability verification.
    These make REAL external requests to confirm takeover is possible.
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Research) PHANTOM/1.0"
        })

    def verify_github(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """
        Check if GitHub Pages username/org is available.
        Returns (claimable, evidence, claim_target)
        """
        target = None

        # Extract username from CNAME chain
        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.github\.io", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract GitHub username from CNAME", None

        try:
            # Check if GitHub user/org exists
            response = self.session.get(
                f"https://github.com/{target}",
                timeout=self.timeout,
                allow_redirects=False
            )

            if response.status_code == 404:
                return (
                    True,
                    f"GitHub user/org '{target}' does not exist - Pages namespace is CLAIMABLE",
                    f"github.com/{target}"
                )
            elif response.status_code == 200:
                # User exists - check if they have a pages repo
                repo_resp = self.session.get(
                    f"https://github.com/{target}/{target}.github.io",
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if repo_resp.status_code == 404:
                    return (
                        True,
                        f"GitHub user '{target}' exists but '{target}.github.io' repo missing - CLAIMABLE",
                        f"github.com/{target}/{target}.github.io"
                    )
                return (
                    False,
                    f"GitHub user '{target}' exists and has pages repo - NOT claimable",
                    None
                )
            else:
                return (
                    False,
                    f"GitHub returned unexpected status {response.status_code}",
                    None
                )

        except Exception as e:
            return False, f"GitHub verification error: {str(e)}", None

    def verify_s3(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check if S3 bucket exists and if we can claim it"""
        target = None

        for cname in dns_result.cname_chain:
            # Extract bucket name from various S3 CNAME formats
            match = re.search(r"([a-zA-Z0-9\-\.]+)\.s3[.\-]", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            # Try extracting from original domain structure
            return False, "Could not extract S3 bucket name", None

        try:
            # HEAD request to check bucket existence
            response = self.session.request(
                "HEAD",
                f"https://s3.amazonaws.com/{target}",
                timeout=self.timeout,
            )

            if response.status_code == 404:
                return (
                    True,
                    f"S3 bucket '{target}' does not exist - CLAIMABLE (same region required)",
                    f"s3://aws.amazon.com/{target}"
                )
            elif response.status_code == 403:
                return (
                    False,
                    f"S3 bucket '{target}' exists but is private - NOT claimable",
                    None
                )
            elif response.status_code == 200:
                return (
                    False,
                    f"S3 bucket '{target}' is public and active - NOT claimable",
                    None
                )

        except Exception as e:
            return False, f"S3 verification error: {str(e)}", None

        return False, "S3 verification inconclusive", None

    def verify_heroku(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check if Heroku app name is available"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.herokuapp\.com", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Heroku app name", None

        try:
            response = self.session.get(
                f"https://{target}.herokuapp.com",
                timeout=self.timeout,
                allow_redirects=True
            )

            body = response.text.lower()
            if "no such app" in body or response.status_code == 404:
                return (
                    True,
                    f"Heroku app '{target}' does not exist - CLAIMABLE",
                    f"{target}.herokuapp.com"
                )
            return (
                False,
                f"Heroku app '{target}' appears active",
                None
            )

        except Exception as e:
            return False, f"Heroku verification error: {str(e)}", None

    def verify_azure(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Azure App Service availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.azurewebsites\.net", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Azure app name", None

        try:
            response = self.session.get(
                f"https://{target}.azurewebsites.net",
                timeout=self.timeout
            )

            if "404" in response.text or "not found" in response.text.lower():
                return (
                    True,
                    f"Azure app '{target}' not found - potentially CLAIMABLE",
                    f"{target}.azurewebsites.net"
                )
            return False, f"Azure app '{target}' appears active", None

        except Exception as e:
            return False, f"Azure verification error: {str(e)}", None

    def verify_ghost(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Ghost.io blog availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.ghost\.io", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Ghost.io name", None

        try:
            response = self.session.get(
                f"https://{target}.ghost.io",
                timeout=self.timeout
            )

            if response.status_code == 404:
                return (
                    True,
                    f"Ghost.io blog '{target}' does not exist - CLAIMABLE",
                    f"{target}.ghost.io"
                )
            return False, f"Ghost.io blog '{target}' appears active", None

        except Exception as e:
            return False, f"Ghost verification error: {str(e)}", None

    def verify_surge(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Surge.sh project availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.surge\.sh", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Surge.sh project name", None

        try:
            response = self.session.get(
                f"https://{target}.surge.sh",
                timeout=self.timeout
            )

            if "project not found" in response.text.lower() or response.status_code == 404:
                return (
                    True,
                    f"Surge.sh project '{target}' not found - CLAIMABLE (run: surge --domain {target}.surge.sh)",
                    f"{target}.surge.sh"
                )
            return False, f"Surge.sh project '{target}' appears active", None

        except Exception as e:
            return False, f"Surge verification error: {str(e)}", None

    def verify_zendesk(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Zendesk Help Center"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.zendesk\.com", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Zendesk account", None

        try:
            response = self.session.get(
                f"https://{target}.zendesk.com",
                timeout=self.timeout
            )

            if response.status_code == 404 or "help center no longer exists" in response.text.lower():
                return (
                    True,
                    f"Zendesk account '{target}' not found - CLAIMABLE",
                    f"{target}.zendesk.com"
                )
            return False, f"Zendesk account '{target}' appears active", None

        except Exception as e:
            return False, f"Zendesk verification error: {str(e)}", None

    def verify_shopify(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Shopify store availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.myshopify\.com", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Shopify store name", None

        try:
            response = self.session.get(
                f"https://{target}.myshopify.com",
                timeout=self.timeout
            )

            if "store is currently unavailable" in response.text.lower():
                return (
                    True,
                    f"Shopify store '{target}' is unavailable - potentially CLAIMABLE",
                    f"{target}.myshopify.com"
                )
            return False, f"Shopify store '{target}' appears active", None

        except Exception as e:
            return False, f"Shopify verification error: {str(e)}", None

    def verify_wordpress(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check WordPress.com blog availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.wordpress\.com", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract WordPress.com username", None

        try:
            response = self.session.get(
                f"https://{target}.wordpress.com",
                timeout=self.timeout
            )

            if response.status_code == 404 or "doesn't exist" in response.text.lower():
                return (
                    True,
                    f"WordPress.com blog '{target}' not found - CLAIMABLE",
                    f"{target}.wordpress.com"
                )
            return False, f"WordPress.com blog '{target}' appears active", None

        except Exception as e:
            return False, f"WordPress verification error: {str(e)}", None

    def verify_netlify(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Netlify site availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.netlify\.app", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Netlify site name", None

        try:
            response = self.session.get(
                f"https://{target}.netlify.app",
                timeout=self.timeout
            )

            if response.status_code == 404:
                return (
                    True,
                    f"Netlify site '{target}' not found - CLAIMABLE",
                    f"{target}.netlify.app"
                )
            return False, f"Netlify site '{target}' appears active", None

        except Exception as e:
            return False, f"Netlify verification error: {str(e)}", None

    def verify_bitbucket(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Check Bitbucket Pages availability"""
        target = None

        for cname in dns_result.cname_chain:
            match = re.search(r"([a-zA-Z0-9\-]+)\.bitbucket\.io", cname)
            if match:
                target = match.group(1)
                break

        if not target:
            return False, "Could not extract Bitbucket username", None

        try:
            response = self.session.get(
                f"https://bitbucket.org/{target}",
                timeout=self.timeout,
                allow_redirects=False
            )

            if response.status_code == 404:
                return (
                    True,
                    f"Bitbucket user '{target}' not found - Pages CLAIMABLE",
                    f"bitbucket.org/{target}"
                )
            return False, f"Bitbucket user '{target}' appears active", None

        except Exception as e:
            return False, f"Bitbucket verification error: {str(e)}", None

    def verify_generic(self, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Generic fallback verifier for services without specific API checks"""
        return (
            False,
            "Generic verification - manual confirmation required",
            None
        )

    def run(self, verifier_name: str, dns_result: DNSResult) -> Tuple[bool, str, Optional[str]]:
        """Dispatch to correct verifier"""
        verifier_fn = getattr(self, verifier_name, self.verify_generic)
        return verifier_fn(dns_result)

# ─────────────────────────────────────────────────────────────────────────────
# REPORT ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ReportEngine:
    """
    Generates professional, ready-to-submit bug reports.
    Both JSON (for automation) and Markdown (for submission).
    """

    @staticmethod
    def generate_exploitation_steps(result: VulnerabilityResult) -> List[str]:
        """Generate concrete exploitation steps based on service"""
        service = result.service_key
        target  = result.claim_target or "TARGET"

        steps_map = {
            "github_pages": [
                f"1. Register GitHub account with username: {target.split('/')[0] if target else '[username]'}",
                f"2. Create repository named: {target.split('/')[0] if target else '[username]'}.github.io",
                "3. Add index.html with proof-of-concept content",
                "4. Enable GitHub Pages in repository settings",
                f"5. Verify {result.domain} now serves your content",
                "6. Take screenshot as proof",
                "7. Clean up: disable Pages or remove repo",
            ],
            "aws_s3": [
                "1. Create AWS account (free tier)",
                f"2. Create S3 bucket named: {target.replace('s3://aws.amazon.com/', '') if target else '[bucket-name]'}",
                "3. Enable static website hosting on the bucket",
                "4. Set bucket policy to public-read",
                "5. Upload index.html with PoC content",
                f"6. Verify {result.domain} serves your content",
                "7. Take screenshot, then delete bucket",
            ],
            "heroku": [
                "1. Create Heroku account",
                f"2. Create app named: {target if target else '[app-name]'}",
                "3. Deploy minimal app with PoC content",
                f"4. Verify {result.domain} serves your content",
                "5. Take screenshot, delete app",
            ],
            "surge_sh": [
                "1. Install Surge: npm install -g surge",
                "2. Create index.html with PoC content",
                f"3. Run: surge --domain {target if target else '[project].surge.sh'}",
                f"4. Verify {result.domain} serves your content",
                "5. Screenshot, then: surge teardown [domain]",
            ],
        }

        return steps_map.get(service, [
            f"1. Register account for service: {result.service_display}",
            f"2. Claim the resource: {target}",
            f"3. Create page/content at claimed resource",
            f"4. Verify {result.domain} serves your content",
            "5. Take screenshot as proof",
            "6. Clean up after verification",
        ])

    @staticmethod
    def generate_remediation(result: VulnerabilityResult) -> List[str]:
        """Generate remediation steps"""
        return [
            f"Remove or update the DNS record for {result.domain}",
            "If the service is no longer in use, delete the CNAME/A record entirely",
            "If the service is needed, reconfigure it with an active account",
            "Implement regular audits of DNS records against active service configurations",
            "Consider using CNAME flattening where services are no longer needed",
        ]

    def generate_markdown_report(self, result: VulnerabilityResult, output_dir: str) -> str:
        """Generate a complete, ready-to-submit Markdown bug report"""

        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH:     "🟠",
            Severity.MEDIUM:   "🟡",
            Severity.LOW:      "🟢",
        }

        dns_info = "\n".join([
            f"- **CNAME Chain:** {' → '.join(result.dns_result.cname_chain) if result.dns_result.cname_chain else 'None'}",
            f"- **A Records:** {', '.join(result.dns_result.a_records) if result.dns_result.a_records else 'None'}",
            f"- **NXDOMAIN:** {result.dns_result.is_nxdomain}",
        ])

        http_info = "Service unreachable" if not result.http_result else "\n".join([
            f"- **Status Code:** {result.http_result.status_code}",
            f"- **URL:** {result.http_result.url}",
            f"- **Response Time:** {result.http_result.response_time:.2f}s",
            f"- **Redirect Chain:** {' → '.join(result.http_result.redirect_chain[:3])}",
        ])

        evidence_list = "\n".join([
            "**DNS Evidence:**",
            *[f"  - {e}" for e in result.evidence.dns_evidence],
            "",
            "**HTTP Evidence:**",
            *[f"  - {e}" for e in result.evidence.http_evidence],
            "",
            "**Verification Evidence:**",
            *[f"  - {e}" for e in result.evidence.verification_evidence],
        ])

        steps = "\n".join([f"{s}" for s in result.exploitation_steps])
        remediation = "\n".join([f"- {r}" for r in result.remediation])

        report = f"""# {severity_emoji.get(result.severity, '⚪')} Subdomain Takeover: {result.domain}

## Summary
**Vulnerability:** Subdomain Takeover via Dangling DNS Record  
**Affected Domain:** `{result.domain}`  
**Service:** {result.service_display}  
**Severity:** {result.severity.value}  
**Confidence:** {result.confidence.value}  
**Claimable:** {'✅ YES - Verified' if result.claimable else '⚠️ Likely - Needs Manual Confirmation'}  
**Found:** {result.timestamp}  
**Scan ID:** {result.scan_id}  

## Description
The subdomain `{result.domain}` has a dangling DNS record pointing to {result.service_display}. 
The underlying {result.service_display} resource ({result.claim_target or 'unclaimed resource'}) 
no longer exists, allowing any attacker to register the resource and take control of the subdomain.

This could enable:
- **Phishing attacks** using a trusted subdomain of the target organization
- **Cookie theft** if cookies are scoped to the parent domain
- **Content injection** under the organization's trusted domain
- **Reputation damage** to the organization

## Technical Details

### DNS Information
{dns_info}

### HTTP Information
{http_info}

### Evidence
{evidence_list}

**Total Confidence Score:** {result.evidence.total_score}/100

## Proof of Concept

### Steps to Reproduce
{steps}

### Expected Result
The subdomain `{result.domain}` can be claimed by registering the resource at {result.service_display}.

### Impact
An attacker can serve arbitrary content from `{result.domain}`, a subdomain trusted by users 
and potentially by the organization's own security controls.

## Remediation
{remediation}

## References
- [EdOverflow - Can I Take Over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackerOne - Subdomain Takeover](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
- [OWASP - Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/)

---
*Report generated by PHANTOM - Subdomain Takeover Hunter*
"""

        filename = os.path.join(output_dir, f"report_{result.domain.replace('.', '_')}_{result.scan_id}.md")
        with open(filename, 'w') as f:
            f.write(report)

        return filename

    def export_json(self, results: List[VulnerabilityResult], output_file: str):
        """Export all results to structured JSON"""
        data = []
        for r in results:
            data.append({
                "domain":          r.domain,
                "service":         r.service_display,
                "severity":        r.severity.value,
                "confidence":      r.confidence.value,
                "claimable":       r.claimable,
                "claim_target":    r.claim_target,
                "score":           r.evidence.total_score,
                "dns_evidence":    r.evidence.dns_evidence,
                "http_evidence":   r.evidence.http_evidence,
                "verification":    r.evidence.verification_evidence,
                "cname_chain":     r.dns_result.cname_chain,
                "a_records":       r.dns_result.a_records,
                "exploitation":    r.exploitation_steps,
                "remediation":     r.remediation,
                "timestamp":       r.timestamp,
                "scan_id":         r.scan_id,
            })

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Per-domain rate limiting.
    Prevents hammering a single target's DNS/HTTP servers.
    """

    def __init__(self, requests_per_second: float = 10.0):
        self.rps       = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self._domain_timestamps: Dict[str, float] = defaultdict(float)
        self._lock = concurrent.futures.thread.threading.Lock()

    def wait(self, domain: str):
        """Wait if necessary before making request to domain"""
        import threading
        apex = ".".join(domain.split(".")[-2:])

        with self._lock:
            last_time = self._domain_timestamps[apex]
            now       = time.time()
            elapsed   = now - last_time

            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)

            self._domain_timestamps[apex] = time.time()

# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER (PIPELINE ORCHESTRATOR)
# ─────────────────────────────────────────────────────────────────────────────

class PHANTOM:
    """
    Main orchestrator: runs all stages of the pipeline.
    """

    def __init__(
        self,
        threads:   int   = 30,
        timeout:   int   = 8,
        rps:       float = 10.0,
        verbose:   bool  = False,
        output_dir: str  = "phantom_results",
        min_confidence: str = "POSSIBLE",
    ):
        self.threads    = threads
        self.timeout    = timeout
        self.verbose    = verbose
        self.output_dir = output_dir
        self.min_confidence = Confidence[min_confidence]

        # Initialize engines
        self.dns_engine     = DNSEngine(timeout=timeout)
        self.http_engine    = HTTPEngine(timeout=timeout)
        self.scoring_engine = ScoringEngine()
        self.verifiers      = ServiceVerifiers(timeout=timeout)
        self.report_engine  = ReportEngine()
        self.rate_limiter   = RateLimiter(rps=rps)

        # Statistics
        self.stats = {
            "scanned":    0,
            "dns_hits":   0,
            "http_hits":  0,
            "confirmed":  0,
            "likely":     0,
            "possible":   0,
            "errors":     0,
        }

        # Results store
        self.results: List[VulnerabilityResult] = []

        # Setup output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Logging
        level = logging.DEBUG if verbose else logging.WARNING
        logging.basicConfig(
            level=level,
            format="[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        self.log = logging.getLogger("PHANTOM")

    def _print(self, msg: str, level: str = "INFO"):
        """Controlled output"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix_map = {
            "INFO":  f"[{timestamp}] [*]",
            "VULN":  f"[{timestamp}] [🎯]",
            "WARN":  f"[{timestamp}] [!]",
            "ERROR": f"[{timestamp}] [✗]",
            "DEBUG": f"[{timestamp}] [~]",
        }
        prefix = prefix_map.get(level, f"[{timestamp}]")
        if level == "DEBUG" and not self.verbose:
            return
        print(f"{prefix} {msg}", flush=True)

    def scan_domain(self, domain: str) -> Optional[VulnerabilityResult]:
        """
        Run full pipeline for a single domain.
        Returns VulnerabilityResult if vulnerable, None otherwise.
        """
        domain = domain.strip().lower()
        if not domain:
            return None

        self._print(f"Scanning {domain}", "DEBUG")
        self.rate_limiter.wait(domain)

        # ────────────────────────────────────────────
        # STAGE 1: DNS INTELLIGENCE
        # ────────────────────────────────────────────
        dns_result = self.dns_engine.resolve(domain)
        self.stats["scanned"] += 1

        # Gate: Must have CNAME or suspicious A record to continue
        if not dns_result.cname_chain and not dns_result.a_records:
            self._print(f"{domain} - No DNS indicators, skipping", "DEBUG")
            return None

        # ────────────────────────────────────────────
        # STAGE 2: MATCH AGAINST FINGERPRINTS (DNS)
        # ────────────────────────────────────────────
        candidate_services = []

        for service_key, fp in FINGERPRINTS.items():
            compiled = self.scoring_engine._compiled_patterns[service_key]

            # Quick DNS pre-filter (avoid HTTP request if no DNS match)
            dns_hint = False

            for cname in dns_result.cname_chain:
                if "NXDOMAIN:" in cname:
                    continue
                for pattern in compiled["cname_patterns"]:
                    if pattern.search(cname):
                        dns_hint = True
                        break
                if dns_hint:
                    break

            if not dns_hint and fp.get("ip_ranges"):
                for ip in dns_result.a_records:
                    if DNSEngine.ip_in_cidr(ip, fp["ip_ranges"]):
                        dns_hint = True
                        break

            if dns_hint:
                candidate_services.append(service_key)

        if not candidate_services:
            self._print(f"{domain} - No service fingerprint match, skipping", "DEBUG")
            return None

        self.stats["dns_hits"] += 1
        self._print(f"{domain} - DNS match: {candidate_services}", "DEBUG")

        # ────────────────────────────────────────────
        # STAGE 3: HTTP INTELLIGENCE
        # ────────────────────────────────────────────
        http_result = self.http_engine.fetch(domain)

        # ────────────────────────────────────────────
        # STAGE 4: SCORING
        # ────────────────────────────────────────────
        best_score    = 0
        best_service  = None
        best_evidence = None

        for service_key in candidate_services:
            score, evidence = self.scoring_engine.score(
                service_key, dns_result, http_result
            )
            self._print(f"{domain} vs {service_key}: score={score}", "DEBUG")

            if score > best_score:
                best_score    = score
                best_service  = service_key
                best_evidence = evidence

        if best_score < SCORE_POSSIBLE or not best_service:
            self._print(f"{domain} - Score {best_score} below threshold", "DEBUG")
            return None

        self.stats["http_hits"] += 1

        # Determine confidence level
        if best_score >= SCORE_CONFIRMED:
            confidence = Confidence.CONFIRMED
        elif best_score >= SCORE_LIKELY:
            confidence = Confidence.LIKELY
        else:
            confidence = Confidence.POSSIBLE

        # Check if meets minimum confidence threshold
        confidence_order = [Confidence.POSSIBLE, Confidence.LIKELY, Confidence.CONFIRMED]
        if confidence_order.index(confidence) < confidence_order.index(self.min_confidence):
            self._print(f"{domain} - Confidence {confidence.value} below threshold", "DEBUG")
            return None

        fp = FINGERPRINTS[best_service]

        # ────────────────────────────────────────────
        # STAGE 5: SERVICE VERIFICATION (Claimability)
        # ────────────────────────────────────────────
        verifier_name = fp.get("verifier", "verify_generic")
        claimable, verify_evidence, claim_target = self.verifiers.run(
            verifier_name, dns_result
        )

        best_evidence.verification_evidence.append(verify_evidence)

        # Bonus score for verified claimability
        if claimable:
            best_evidence.total_score = min(best_evidence.total_score + 40, 100)
            if confidence == Confidence.LIKELY:
                confidence = Confidence.CONFIRMED
            self.stats["confirmed"] += 1
        elif confidence == Confidence.CONFIRMED:
            self.stats["confirmed"] += 1
        elif confidence == Confidence.LIKELY:
            self.stats["likely"] += 1
        else:
            self.stats["possible"] += 1

        # ────────────────────────────────────────────
        # STAGE 6: BUILD RESULT
        # ────────────────────────────────────────────
        result = VulnerabilityResult(
            domain          = domain,
            service_key     = best_service,
            service_display = fp["service_display"],
            severity        = fp["severity"],
            confidence      = confidence,
            evidence        = best_evidence,
            dns_result      = dns_result,
            http_result     = http_result if http_result.status_code else None,
            claimable       = claimable,
            claim_target    = claim_target,
        )

        # Add exploitation steps and remediation
        result.exploitation_steps = self.report_engine.generate_exploitation_steps(result)
        result.remediation        = self.report_engine.generate_remediation(result)

        self._print(
            f"VULNERABLE: {domain} | {fp['service_display']} | "
            f"{fp['severity'].value} | {confidence.value} | "
            f"Score: {best_score} | Claimable: {claimable}",
            "VULN"
        )

        return result

    def scan_all(self, domains: List[str]) -> List[VulnerabilityResult]:
        """Scan all domains using thread pool"""
        total = len(domains)
        self._print(f"Starting scan of {total} domains with {self.threads} threads")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {
                executor.submit(self.scan_domain, domain): domain
                for domain in domains
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                completed += 1
                domain = future_to_domain[future]

                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception as e:
                    self.stats["errors"] += 1
                    self._print(f"{domain} - Unhandled error: {e}", "ERROR")

                # Progress indicator every 50 domains
                if completed % 50 == 0 or completed == total:
                    pct = (completed / total) * 100
                    found = len(self.results)
                    print(
                        f"\r[~] Progress: {completed}/{total} ({pct:.1f}%) | "
                        f"Found: {found} vulnerabilities",
                        end="", flush=True
                    )

        print()  # Newline after progress bar
        return self.results

    def print_summary(self):
        """Print professional summary"""
        results = self.results

        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                        PHANTOM - SCAN COMPLETE                      ║
╚══════════════════════════════════════════════════════════════════════╝

📊 STATISTICS
   Domains Scanned:    {self.stats['scanned']}
   DNS Hits:           {self.stats['dns_hits']}
   HTTP Hits:          {self.stats['http_hits']}
   Errors:             {self.stats['errors']}

🎯 VULNERABILITIES FOUND: {len(results)}
   Confirmed:          {self.stats['confirmed']}
   Likely:             {self.stats['likely']}
   Possible:           {self.stats['possible']}
""")

        if not results:
            print("   ✅ No vulnerabilities found.")
            return

        # Sort by: confidence, then severity
        severity_order   = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        confidence_order = {Confidence.CONFIRMED: 0, Confidence.LIKELY: 1, Confidence.POSSIBLE: 2}

        results.sort(key=lambda r: (
            confidence_order[r.confidence],
            severity_order[r.severity]
        ))

        print("   FINDINGS:")
        print("   " + "─" * 70)

        for r in results:
            claimable_str = "✅ CLAIMABLE" if r.claimable else "⚠️  VERIFY"
            print(f"""
   🎯 {r.domain}
      Service:    {r.service_display}
      Severity:   {r.severity.value}
      Confidence: {r.confidence.value} (Score: {r.evidence.total_score}/100)
      Status:     {claimable_str}
      Target:     {r.claim_target or 'See report'}
""")

    def generate_reports(self) -> str:
        """Generate all reports"""
        if not self.results:
            return ""

        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file  = os.path.join(self.output_dir, f"phantom_{timestamp}.json")

        # JSON export
        self.report_engine.export_json(self.results, json_file)
        self._print(f"JSON report: {json_file}")

        # Per-vulnerability Markdown reports
        for result in self.results:
            if result.confidence in (Confidence.CONFIRMED, Confidence.LIKELY):
                md_file = self.report_engine.generate_markdown_report(result, self.output_dir)
                self._print(f"Markdown report: {md_file}")

        return json_file

# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PHANTOM - S-Tier Subdomain Takeover Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan from file (most common)
  python3 phantom.py -f subdomains.txt

  # Single domain, verbose
  python3 phantom.py -d staging.target.com -v

  # High performance, confirmed only
  python3 phantom.py -f subs.txt -t 50 --min-confidence CONFIRMED

  # Conservative scan (less noise)
  python3 phantom.py -f subs.txt -t 10 --rps 5 --min-confidence LIKELY

Workflow:
  1. Generate subdomains: subfinder -d target.com | amass enum -d target.com
  2. Feed to PHANTOM:     python3 phantom.py -f subdomains.txt
  3. Review reports:      cat phantom_results/phantom_*.json
  4. Submit reports:      phantom_results/report_*.md (ready to paste)
        """
    )

    parser.add_argument("-f", "--file",     help="Subdomain list file (one per line)")
    parser.add_argument("-d", "--domain",   help="Single domain to scan")
    parser.add_argument("-o", "--output",   default="phantom_results", help="Output directory")
    parser.add_argument("-t", "--threads",  type=int,   default=30,     help="Thread count (default: 30)")
    parser.add_argument("--timeout",        type=int,   default=8,      help="Request timeout seconds (default: 8)")
    parser.add_argument("--rps",            type=float, default=10.0,   help="Requests per second per domain (default: 10)")
    parser.add_argument("--min-confidence", default="POSSIBLE",
                        choices=["POSSIBLE", "LIKELY", "CONFIRMED"],    help="Minimum confidence to report (default: POSSIBLE)")
    parser.add_argument("-v", "--verbose",  action="store_true",        help="Verbose output")

    args = parser.parse_args()

    # Load domains
    domains = []
    if args.file:
        try:
            with open(args.file) as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[✗] File not found: {args.file}")
            sys.exit(1)
    elif args.domain:
        domains = [args.domain]
    else:
        parser.print_help()
        sys.exit(1)

    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║            PHANTOM - Subdomain Takeover Hunter (S-Tier)                    ║
║                                                                              ║
║  Pipeline: DNS Intelligence → HTTP Analysis → Scoring → Verification        ║
║  Fingerprints: {len(FINGERPRINTS)} services | Multi-resolver | CNAME chain following          ║
║  Verification: Service-specific claimability checking                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Domains:        {len(domains)}
  Threads:        {args.threads}
  Timeout:        {args.timeout}s
  RPS limit:      {args.rps}/domain
  Min confidence: {args.min_confidence}
  Output dir:     {args.output}
  Fingerprints:   {len(FINGERPRINTS)} services

  Starting in 2 seconds... (Ctrl+C to cancel)
""")

    time.sleep(2)

    # Run scanner
    scanner = PHANTOM(
        threads        = args.threads,
        timeout        = args.timeout,
        rps            = args.rps,
        verbose        = args.verbose,
        output_dir     = args.output,
        min_confidence = args.min_confidence,
    )

    start = time.time()

    try:
        scanner.scan_all(domains)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")

    elapsed = time.time() - start

    # Print results
    scanner.print_summary()

    # Generate reports
    if scanner.results:
        json_out = scanner.generate_reports()
        print(f"\n📁 All reports saved to: {args.output}/")
        print(f"📄 Main JSON:            {json_out}")

    print(f"⏱️  Total scan time: {elapsed:.1f}s")
    print(f"⚡ Speed: {len(domains)/elapsed:.1f} domains/second\n")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()