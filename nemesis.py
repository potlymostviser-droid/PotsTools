#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    NEMESIS - Subdomain Takeover Hunter                      ║
║                         S-Tier Bug Bounty Tool                              ║
║                                                                              ║
║  Architecture:                                                               ║
║  Stage 1: DNS Intelligence    (CNAME chains, A/AAAA, NS, IP ranges)         ║
║  Stage 2: HTTP Analysis       (Smart fingerprinting, header analysis)        ║
║  Stage 3: Service Validation  (Provider-specific API verification)           ║
║  Stage 4: Proof Generation    (Evidence package for bug report)              ║
║                                                                              ║
║  IMPORTANT: Only use on authorized targets. Bug bounty programs only.       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import dns.resolver
import dns.exception
import dns.rdatatype
import requests
import concurrent.futures
import threading
import json
import sys
import re
import time
import socket
import ipaddress
import hashlib
import random
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
import argparse

# ─────────────────────────────────────────────────────────────────────────────
# SUPPRESS SSL WARNINGS (we handle SSL ourselves)
# ─────────────────────────────────────────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────────────────────────
class NemesisLogger:
    """Custom logger with colored output"""
    
    COLORS = {
        'RED':     '\033[91m',
        'GREEN':   '\033[92m',
        'YELLOW':  '\033[93m',
        'BLUE':    '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN':    '\033[96m',
        'WHITE':   '\033[97m',
        'BOLD':    '\033[1m',
        'RESET':   '\033[0m',
    }

    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.lock = threading.Lock()
        self.log_file = log_file
        self._file_handler = None
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.DEBUG,
                format='%(asctime)s [%(levelname)s] %(message)s'
            )
            self._file_handler = logging.getLogger('nemesis')

    def _print(self, level, message, color='WHITE'):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colored = (
            f"{self.COLORS[color]}"
            f"[{timestamp}] [{level}] {message}"
            f"{self.COLORS['RESET']}"
        )
        with self.lock:
            print(colored)
            if self._file_handler:
                self._file_handler.info(f"[{level}] {message}")

    def vuln(self, msg):    self._print("VULN",    msg, 'RED')
    def success(self, msg): self._print("OK",      msg, 'GREEN')
    def info(self, msg):    self._print("INFO",    msg, 'CYAN')
    def warn(self, msg):    self._print("WARN",    msg, 'YELLOW')
    def debug(self, msg):
        if self.verbose:    self._print("DEBUG",   msg, 'MAGENTA')
    def error(self, msg):   self._print("ERROR",   msg, 'RED')
    def stage(self, msg):   self._print("STAGE",   msg, 'BOLD')


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT DATABASE
#
# CONFIDENCE LEVELS (be honest about hallucination risk):
#   VERIFIED   - Cross-referenced with can-i-take-over-xyz + manual testing
#   PROBABLE   - Based on known service behavior, may need re-verification
#   UNCERTAIN  - Pattern exists but may be outdated - validate before reporting
#
# Source: https://github.com/EdOverflow/can-i-take-over-xyz
# YOU SHOULD ALWAYS RE-VERIFY THESE AGAINST THAT REPO BEFORE A CAMPAIGN
# ─────────────────────────────────────────────────────────────────────────────

FINGERPRINT_DB = {

    # ── GitHub Pages ──────────────────────────────────────────────────────────
    "github_pages": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"github\.io$",
            r"github\.com$",
        ],
        "http_patterns": [
            r"There isn't a GitHub Pages site here\.",
            r"For root URLs \(like http://example\.com/\) you must provide an index\.html",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,

        # Service-specific validator function name (implemented below)
        "validator":    "validate_github_pages",

        # What a researcher needs to do to prove/claim
        "claim_instructions": (
            "Create a GitHub Pages repo at <username>.github.io "
            "and add the custom domain in repo Settings → Pages."
        ),
        "docs": "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site",
        "notes": "Extract username from CNAME: <user>.github.io — check if user exists.",
    },

    # ── Heroku ────────────────────────────────────────────────────────────────
    "heroku": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.herokuapp\.com$",
            r"\.herokussl\.com$",
            r"\.herokudns\.com$",
        ],
        "http_patterns": [
            r"No such app",
            r"there is no app configured at that hostname",
            r"herokucdn\.com/error-pages/no-such-app\.html",
        ],
        "headers": {},
        "status_codes": [404, 503],
        "claimable": True,
        "validator":    "validate_heroku",
        "claim_instructions": (
            "Register a Heroku app with the same name and add the custom domain."
        ),
        "docs": "https://devcenter.heroku.com/articles/custom-domains",
        "notes": "App name extracted from CNAME: <appname>.herokuapp.com",
    },

    # ── AWS S3 ────────────────────────────────────────────────────────────────
    "aws_s3": {
        "confidence":   "VERIFIED",
        "severity":     "CRITICAL",
        "cname_patterns": [
            r"\.s3\.amazonaws\.com$",
            r"\.s3-website[\.-]",
            r"s3-website\.amazonaws\.com$",
            r"\.s3\.[a-z0-9-]+\.amazonaws\.com$",
        ],
        "http_patterns": [
            r"<Code>NoSuchBucket</Code>",
            r"The specified bucket does not exist",
            r"NoSuchBucket",
        ],
        "headers": {
            "x-amz-request-id": r".*",   # Presence confirms AWS S3
        },
        "status_codes": [404],
        "claimable": True,
        "validator":    "validate_aws_s3",
        "claim_instructions": (
            "Create an S3 bucket with the exact subdomain name "
            "and enable static website hosting."
        ),
        "docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
        "notes": "Bucket name must exactly match subdomain.",
    },

    # ── AWS CloudFront ────────────────────────────────────────────────────────
    "aws_cloudfront": {
        "confidence":   "PROBABLE",
        "severity":     "CRITICAL",
        "cname_patterns": [
            r"\.cloudfront\.net$",
        ],
        "http_patterns": [
            r"Bad request\.",
            r"ERROR: The request could not be satisfied",
            r"Generated by cloudfront \(CloudFront\)",
        ],
        "headers": {
            "x-cache": r"Error from cloudfront",
            "via":     r"cloudfront",
        },
        "status_codes": [403, 404],
        "claimable": True,
        "validator":    "validate_cloudfront",
        "claim_instructions": (
            "Create a CloudFront distribution and add the subdomain as an alternate domain name (CNAME)."
        ),
        "docs": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html",
        "notes": "UNCERTAIN - CloudFront takeover is complex; manual verification essential.",
    },

    # ── Azure App Service ─────────────────────────────────────────────────────
    "azure_app_service": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.azure-mobile\.net$",
            r"\.cloudapp\.net$",
        ],
        "http_patterns": [
            r"404 Web Site not found",
            r"Error 404 - Web app not found\.",
            r"The resource you are looking for has been removed",
            r"Microsoft Azure App Service",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    "validate_azure",
        "claim_instructions": (
            "Create an Azure App Service with the same name and add custom domain."
        ),
        "docs": "https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain",
        "notes": "",
    },

    # ── Azure Traffic Manager ─────────────────────────────────────────────────
    "azure_traffic_manager": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.trafficmanager\.net$",
        ],
        "http_patterns": [
            r"404 Not Found: Specified endpoint is not found",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": (
            "Register a Traffic Manager profile with the same endpoint name."
        ),
        "docs": "https://docs.microsoft.com/en-us/azure/traffic-manager/traffic-manager-faqs",
        "notes": "UNCERTAIN - needs manual verification of current behavior.",
    },

    # ── Shopify ───────────────────────────────────────────────────────────────
    "shopify": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.myshopify\.com$",
            r"shops\.myshopify\.com$",
        ],
        "http_patterns": [
            r"Sorry, this shop is currently unavailable\.",
            r"Only one step left",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    "validate_shopify",
        "claim_instructions": (
            "Create a Shopify store and add the subdomain as a custom domain."
        ),
        "docs": "https://help.shopify.com/en/manual/domains/add-a-domain/using-existing-domains",
        "notes": "",
    },

    # ── Fastly ────────────────────────────────────────────────────────────────
    "fastly": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.fastly\.net$",
            r"\.fastlylb\.net$",
        ],
        "http_patterns": [
            r"Fastly error: unknown domain:",
            r"Please check that this domain has been added to a service",
        ],
        "headers": {
            "x-served-by": r"cache-",
            "via":         r"1\.1 varnish",
        },
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": (
            "Create a Fastly service and add the domain."
        ),
        "docs": "https://developer.fastly.com/reference/api/",
        "notes": "",
    },

    # ── Zendesk ───────────────────────────────────────────────────────────────
    "zendesk": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.zendesk\.com$",
        ],
        "http_patterns": [
            r"Help Center Closed",
            r"Oops, this help center no longer exists",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": (
            "Create a Zendesk account and add the custom domain."
        ),
        "docs": "https://support.zendesk.com/hc/en-us/articles/203664356",
        "notes": "",
    },

    # ── Webflow ───────────────────────────────────────────────────────────────
    "webflow": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"proxy\.webflow\.com$",
            r"proxy-ssl\.webflow\.com$",
        ],
        "http_patterns": [
            r"The page you are looking for doesn't exist or has been moved\.",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": (
            "Create a Webflow project and publish to the subdomain."
        ),
        "docs": "https://university.webflow.com/lesson/custom-domains",
        "notes": "UNCERTAIN - verify current Webflow error page content.",
    },

    # ── Tumblr ────────────────────────────────────────────────────────────────
    "tumblr": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"domains\.tumblr\.com$",
        ],
        "http_patterns": [
            r"Whatever you were looking for doesn't currently exist at this address",
            r"There's nothing here\.",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Tumblr blog and add custom domain.",
        "docs": "https://tumblr.zendesk.com/hc/en-us/articles/231256548",
        "notes": "",
    },

    # ── Squarespace ───────────────────────────────────────────────────────────
    "squarespace": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.squarespace\.com$",
            r"ext-cust\.squarespace\.com$",
        ],
        "http_patterns": [
            r"No Such Account",
            r"You must configure your DNS settings",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Squarespace site and connect custom domain.",
        "docs": "https://support.squarespace.com/hc/en-us/articles/205812378",
        "notes": "UNCERTAIN - may require manual re-verification.",
    },

    # ── Ghost ─────────────────────────────────────────────────────────────────
    "ghost": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.ghost\.io$",
        ],
        "http_patterns": [
            r"The thing you were looking for is no longer here",
            r"404",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Ghost blog and add custom domain.",
        "docs": "https://ghost.org/integrations/custom-domains/",
        "notes": "UNCERTAIN - re-verify current fingerprint.",
    },

    # ── Netlify ───────────────────────────────────────────────────────────────
    "netlify": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.netlify\.app$",
            r"\.netlify\.com$",
        ],
        "http_patterns": [
            r"Not Found - Request ID:",
            r"netlify",
        ],
        "headers": {
            "x-nf-request-id": r".*",
        },
        "status_codes": [404],
        "claimable": True,
        "validator":    "validate_netlify",
        "claim_instructions": "Deploy a Netlify site and set custom domain.",
        "docs": "https://docs.netlify.com/domains-https/custom-domains/",
        "notes": "",
    },

    # ── Pantheon ──────────────────────────────────────────────────────────────
    "pantheon": {
        "confidence":   "VERIFIED",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.pantheonsite\.io$",
            r"\.panth\.io$",
        ],
        "http_patterns": [
            r"404 error unknown site!",
            r"The gods are wise",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Pantheon site and add the custom domain.",
        "docs": "https://pantheon.io/docs/domains",
        "notes": "",
    },

    # ── Surge.sh ──────────────────────────────────────────────────────────────
    "surge": {
        "confidence":   "VERIFIED",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.surge\.sh$",
        ],
        "http_patterns": [
            r"project not found",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    "validate_surge",
        "claim_instructions": (
            "Run: surge --domain <subdomain> in any local directory."
        ),
        "docs": "https://surge.sh/help/adding-a-custom-domain",
        "notes": "Surge is easily claimable - one command proof.",
    },

    # ── Bitbucket ─────────────────────────────────────────────────────────────
    "bitbucket": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.bitbucket\.io$",
        ],
        "http_patterns": [
            r"Repository not found",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Bitbucket Pages repo with same username/reponame.",
        "docs": "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/",
        "notes": "UNCERTAIN - Bitbucket Pages may be deprecated; re-verify.",
    },

    # ── Cargo Collective ─────────────────────────────────────────────────────
    "cargo": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"cargocollective\.com$",
        ],
        "http_patterns": [
            r"If you're moving your domain away from Cargo",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": False,
        "validator":    None,
        "claim_instructions": "Create a Cargo Collective account and link domain.",
        "docs": "https://support.cargo.site/",
        "notes": "UNCERTAIN.",
    },

    # ── Unbounce ──────────────────────────────────────────────────────────────
    "unbounce": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.unbouncepages\.com$",
        ],
        "http_patterns": [
            r"The requested URL was not found on this server",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create an Unbounce account and publish to the custom domain.",
        "docs": "https://documentation.unbounce.com/hc/en-us/articles/203661044",
        "notes": "",
    },

    # ── Statuspage.io ─────────────────────────────────────────────────────────
    "statuspage": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.statuspage\.io$",
        ],
        "http_patterns": [
            r"Status page doesn't exist",
            r"You are being.*redirected.*statuspage\.io",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a Statuspage and add the custom domain.",
        "docs": "https://support.atlassian.com/statuspage/",
        "notes": "",
    },

    # ── HelpJuice ─────────────────────────────────────────────────────────────
    "helpjuice": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.helpjuice\.com$",
        ],
        "http_patterns": [
            r"We could not find what you're looking for",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a HelpJuice account and map domain.",
        "docs": "https://helpjuice.com/",
        "notes": "UNCERTAIN.",
    },

    # ── HelpScout ─────────────────────────────────────────────────────────────
    "helpscout": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.helpscoutdocs\.com$",
        ],
        "http_patterns": [
            r"No settings were found for this company",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a HelpScout Docs site and add custom domain.",
        "docs": "https://www.helpscout.com/",
        "notes": "UNCERTAIN.",
    },

    # ── Intercom ──────────────────────────────────────────────────────────────
    "intercom": {
        "confidence":   "PROBABLE",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"custom\.intercom\.help$",
        ],
        "http_patterns": [
            r"This page is reserved for artistic dogs",
            r"Uh oh\. That page doesn't exist",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create an Intercom help center and add custom domain.",
        "docs": "https://www.intercom.com/help/",
        "notes": "",
    },

    # ── WP Engine ─────────────────────────────────────────────────────────────
    "wpengine": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.wpengine\.com$",
        ],
        "http_patterns": [
            r"The site you were looking for couldn't be found",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a WP Engine install and map custom domain.",
        "docs": "https://wpengine.com/support/add-domain/",
        "notes": "",
    },

    # ── Readme.io ─────────────────────────────────────────────────────────────
    "readme_io": {
        "confidence":   "PROBABLE",
        "severity":     "HIGH",
        "cname_patterns": [
            r"\.readme\.io$",
            r"\.readmessl\.com$",
        ],
        "http_patterns": [
            r"Project doesnt exist\.\.\. yet",
            r"project doesn't exist",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a ReadMe project and add custom domain.",
        "docs": "https://docs.readme.com/",
        "notes": "",
    },

    # ── Tilda ─────────────────────────────────────────────────────────────────
    "tilda": {
        "confidence":   "UNCERTAIN",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.tilda\.ws$",
        ],
        "http_patterns": [
            r"Please renew your subscription",
            r"Domain has been assigned",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": False,
        "validator":    None,
        "claim_instructions": "UNCERTAIN - manual investigation required.",
        "docs": "https://help-en.tilda.cc/domain",
        "notes": "UNCERTAIN - do not report without manual verification.",
    },

    # ── Getresponse ───────────────────────────────────────────────────────────
    "getresponse": {
        "confidence":   "UNCERTAIN",
        "severity":     "MEDIUM",
        "cname_patterns": [
            r"\.gr8\.com$",
        ],
        "http_patterns": [
            r"With GetResponse Landing Pages",
        ],
        "headers": {},
        "status_codes": [404],
        "claimable": True,
        "validator":    None,
        "claim_instructions": "Create a GetResponse landing page and add custom domain.",
        "docs": "https://www.getresponse.com/",
        "notes": "UNCERTAIN.",
    },

}


# ─────────────────────────────────────────────────────────────────────────────
# IP RANGE DATABASE FOR PROVIDER DETECTION VIA A RECORDS
#
# NOTE: IP ranges change. These are known ranges as of late 2023.
# Validate with: https://ip-ranges.amazonaws.com/ip-ranges.json
#                https://www.microsoft.com/en-us/download/details.aspx?id=56519
# ─────────────────────────────────────────────────────────────────────────────
IP_RANGE_PROVIDERS = {
    "github_pages": [
        "185.199.108.0/22",   # GitHub Pages IPs
    ],
    "fastly": [
        "151.101.0.0/16",
        "199.232.0.0/16",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DNSResult:
    """Comprehensive DNS resolution results"""
    domain: str
    cname_chain: List[str] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    resolves: bool = False
    nxdomain: bool = False
    error: Optional[str] = None


@dataclass
class HTTPResult:
    """HTTP probe results"""
    domain: str
    accessible: bool = False
    status_code: Optional[int] = None
    body_snippet: str = ""
    full_body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    ssl_valid: bool = False
    error: Optional[str] = None


@dataclass
class ValidationResult:
    """Result from service-specific validator"""
    validated: bool = False
    claimable: bool = False
    claim_evidence: str = ""
    validator_notes: str = ""


@dataclass
class TakeoverFinding:
    """A confirmed/suspected takeover finding"""
    domain: str
    service: str
    severity: str
    confidence_level: str     # HIGH / MEDIUM / LOW
    fingerprint_confidence: str  # VERIFIED / PROBABLE / UNCERTAIN

    # Evidence
    cname_chain: List[str] = field(default_factory=list)
    matched_cname_pattern: str = ""
    matched_http_patterns: List[str] = field(default_factory=list)
    matched_headers: Dict[str, str] = field(default_factory=dict)
    http_status_code: Optional[int] = None

    # Validation
    validation: Optional[ValidationResult] = None

    # Report data
    claim_instructions: str = ""
    documentation_url: str = ""
    notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Scoring
    score: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# DNS INTELLIGENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DNSEngine:
    """
    Multi-resolver DNS engine with:
    - CNAME chain following
    - A/AAAA/NS record collection
    - NXDOMAIN detection
    - Multiple resolver support for accuracy
    """

    # Public resolvers to cross-validate
    RESOLVERS = [
        "8.8.8.8",       # Google
        "1.1.1.1",       # Cloudflare
        "9.9.9.9",       # Quad9
        "208.67.222.222" # OpenDNS
    ]

    def __init__(self, timeout: float = 5.0, logger: NemesisLogger = None):
        self.timeout = timeout
        self.log = logger or NemesisLogger()
        self._lock = threading.Lock()

    def _make_resolver(self, nameserver: str) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def _resolve_record(self, domain: str, rtype: str, nameserver: str) -> List[str]:
        """Resolve a single record type from a single nameserver"""
        try:
            resolver = self._make_resolver(nameserver)
            answers = resolver.resolve(domain, rtype)
            if rtype == 'CNAME':
                return [str(r.target).rstrip('.') for r in answers]
            elif rtype in ('A', 'AAAA'):
                return [str(r.address) for r in answers]
            elif rtype == 'NS':
                return [str(r.target).rstrip('.') for r in answers]
        except dns.resolver.NXDOMAIN:
            raise
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []
        return []

    def _follow_cname_chain(self, domain: str, nameserver: str, depth: int = 0) -> List[str]:
        """Recursively follow CNAME chain up to depth 10"""
        if depth > 10:
            return []
        try:
            cnames = self._resolve_record(domain, 'CNAME', nameserver)
            if not cnames:
                return []
            chain = cnames[:]
            for cname in cnames:
                chain.extend(self._follow_cname_chain(cname, nameserver, depth + 1))
            return chain
        except dns.resolver.NXDOMAIN:
            return [f"NXDOMAIN:{domain}"]
        except Exception:
            return []

    def resolve(self, domain: str) -> DNSResult:
        """
        Comprehensive DNS resolution.
        Uses multiple resolvers and cross-validates.
        """
        result = DNSResult(domain=domain)

        # Try each resolver
        nxdomain_votes = 0
        cname_chains = []
        a_records_all = set()
        aaaa_records_all = set()
        ns_records_all = set()

        for ns in self.RESOLVERS:
            try:
                chain = self._follow_cname_chain(domain, ns)
                if chain:
                    # Filter NXDOMAIN markers
                    nxd = [c for c in chain if c.startswith("NXDOMAIN:")]
                    clean = [c for c in chain if not c.startswith("NXDOMAIN:")]
                    if nxd:
                        nxdomain_votes += 1
                    cname_chains.append(clean)

                a = self._resolve_record(domain, 'A', ns)
                a_records_all.update(a)

                aaaa = self._resolve_record(domain, 'AAAA', ns)
                aaaa_records_all.update(aaaa)

            except dns.resolver.NXDOMAIN:
                nxdomain_votes += 1
            except Exception as e:
                self.log.debug(f"DNS [{ns}] {domain}: {e}")

        # NS records (only need one resolver for this)
        try:
            ns_records = self._resolve_record(domain, 'NS', self.RESOLVERS[0])
            ns_records_all.update(ns_records)
        except Exception:
            pass

        # Consensus on CNAME chain
        if cname_chains:
            # Use longest chain (most complete)
            result.cname_chain = max(cname_chains, key=len)

        result.a_records = list(a_records_all)
        result.aaaa_records = list(aaaa_records_all)
        result.ns_records = list(ns_records_all)

        result.resolves = bool(
            result.cname_chain or result.a_records or result.aaaa_records
        )

        # NXDOMAIN if majority of resolvers say so
        result.nxdomain = nxdomain_votes >= 2

        self.log.debug(
            f"DNS {domain}: CNAME={result.cname_chain} "
            f"A={result.a_records} NXDOMAIN={result.nxdomain}"
        )

        return result


# ─────────────────────────────────────────────────────────────────────────────
# HTTP ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HTTPEngine:
    """
    Smart HTTP fingerprinting engine with:
    - HTTPS → HTTP fallback
    - Redirect chain tracking
    - Full body capture for analysis
    - Header analysis
    - Rate limiting
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(
        self,
        timeout: float = 8.0,
        logger: NemesisLogger = None,
        rate_limit: float = 0.0,
        proxies: Dict = None
    ):
        self.timeout = timeout
        self.log = logger or NemesisLogger()
        self.rate_limit = rate_limit
        self.proxies = proxies or {}
        self._lock = threading.Lock()
        self._last_request_time = 0.0

    def _make_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        if self.proxies:
            session.proxies = self.proxies
        return session

    def _rate_limit_sleep(self):
        if self.rate_limit <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self._last_request_time = time.time()

    def probe(self, domain: str) -> HTTPResult:
        """
        Probe domain over HTTPS then HTTP.
        Captures full body, headers, redirect chain.
        """
        result = HTTPResult(domain=domain)
        session = self._make_session()
        self._rate_limit_sleep()

        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            try:
                redirect_chain = []

                def response_hook(response, *args, **kwargs):
                    if response.is_redirect:
                        redirect_chain.append(response.headers.get("Location", ""))

                session.hooks["response"] = [response_hook]

                response = session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    stream=True,
                )

                # Read body intelligently (up to 500KB)
                body_chunks = []
                total = 0
                for chunk in response.iter_content(chunk_size=4096, decode_unicode=True):
                    if isinstance(chunk, bytes):
                        chunk = chunk.decode("utf-8", errors="replace")
                    body_chunks.append(chunk)
                    total += len(chunk)
                    if total >= 512_000:  # 500KB limit
                        break

                body = "".join(body_chunks)

                result.accessible     = True
                result.status_code    = response.status_code
                result.full_body      = body
                result.body_snippet   = body[:500]
                result.headers        = {k.lower(): v for k, v in response.headers.items()}
                result.final_url      = response.url
                result.redirect_chain = redirect_chain
                result.ssl_valid      = (scheme == "https")

                self.log.debug(f"HTTP {domain}: {scheme.upper()} {response.status_code}")
                return result

            except requests.exceptions.SSLError:
                self.log.debug(f"HTTP {domain}: SSL error on {scheme}, trying next")
                continue
            except requests.exceptions.ConnectionError as e:
                result.error = f"ConnectionError: {e}"
                self.log.debug(f"HTTP {domain}: {result.error}")
                continue
            except requests.exceptions.Timeout:
                result.error = "Timeout"
                self.log.debug(f"HTTP {domain}: Timeout on {scheme}")
                continue
            except Exception as e:
                result.error = str(e)
                self.log.debug(f"HTTP {domain}: {e}")
                continue

        return result


# ─────────────────────────────────────────────────────────────────────────────
# SERVICE-SPECIFIC VALIDATORS
#
# These do REAL verification beyond fingerprinting.
# They check whether the resource is actually claimable.
# ─────────────────────────────────────────────────────────────────────────────

class ServiceValidators:
    """
    Service-specific validators for high-confidence verification.
    Each validator checks if the resource is actually available to claim.
    """

    def __init__(self, timeout: float = 5.0, logger: NemesisLogger = None):
        self.timeout = timeout
        self.log = logger or NemesisLogger()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Security Research) NEMESIS-Validator/1.0"
        )

    def validate(self, service_name: str, domain: str, dns_result: DNSResult) -> ValidationResult:
        """Dispatch to correct validator"""
        validator_map = {
            "validate_github_pages":  self.validate_github_pages,
            "validate_heroku":        self.validate_heroku,
            "validate_aws_s3":        self.validate_aws_s3,
            "validate_cloudfront":    self.validate_cloudfront,
            "validate_azure":         self.validate_azure,
            "validate_shopify":       self.validate_shopify,
            "validate_netlify":       self.validate_netlify,
            "validate_surge":         self.validate_surge,
        }

        fp = FINGERPRINT_DB.get(service_name, {})
        validator_name = fp.get("validator")

        if not validator_name:
            return ValidationResult(validated=False, validator_notes="No validator implemented")

        validator_fn = validator_map.get(validator_name)
        if not validator_fn:
            return ValidationResult(validated=False, validator_notes=f"Validator {validator_name} not found")

        try:
            return validator_fn(domain, dns_result)
        except Exception as e:
            self.log.debug(f"Validator error [{service_name}] {domain}: {e}")
            return ValidationResult(validated=False, validator_notes=f"Validator exception: {e}")

    def validate_github_pages(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Check if GitHub username in CNAME is actually available.
        CNAME format: <username>.github.io
        If username doesn't exist on GitHub → domain is claimable.
        """
        username = None
        for cname in dns_result.cname_chain:
            match = re.match(r"^([a-zA-Z0-9_-]+)\.github\.io$", cname)
            if match:
                username = match.group(1)
                break

        if not username:
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Could not extract GitHub username from CNAME"
            )

        try:
            resp = self.session.get(
                f"https://github.com/{username}",
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
            if resp.status_code == 404:
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"GitHub user '{username}' does not exist (404)",
                    validator_notes=f"Account available: github.com/{username}"
                )
            else:
                # User exists — check if the repo exists
                repo_resp = self.session.get(
                    f"https://github.com/{username}/{username}.github.io",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True,
                )
                if repo_resp.status_code == 404:
                    return ValidationResult(
                        validated=True,
                        claimable=True,
                        claim_evidence=f"GitHub user '{username}' exists but Pages repo does not",
                        validator_notes=(
                            f"User exists but github.com/{username}/{username}.github.io "
                            f"returns 404 - Pages repo can be created"
                        )
                    )
                return ValidationResult(
                    validated=True,
                    claimable=False,
                    validator_notes=f"GitHub user '{username}' exists with Pages repo - not vulnerable"
                )
        except Exception as e:
            return ValidationResult(
                validated=False,
                validator_notes=f"GitHub API check failed: {e}"
            )

    def validate_heroku(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Check if Heroku app name from CNAME is available.
        CNAME: <appname>.herokuapp.com
        """
        app_name = None
        for cname in dns_result.cname_chain:
            match = re.match(r"^([a-zA-Z0-9_-]+)\.herokuapp\.com$", cname)
            if match:
                app_name = match.group(1)
                break

        if not app_name:
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Could not extract Heroku app name from CNAME"
            )

        try:
            resp = self.session.get(
                f"https://{app_name}.herokuapp.com",
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
            if resp.status_code == 404 and "no such app" in resp.text.lower():
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"Heroku app '{app_name}' does not exist",
                    validator_notes=f"App name available: {app_name}.herokuapp.com"
                )
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes=f"Heroku app '{app_name}' appears to exist"
            )
        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))

    def validate_aws_s3(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Try to access the S3 bucket and check if it exists.
        Bucket name = subdomain (or extracted from CNAME).
        """
        # Bucket name is usually the subdomain itself
        bucket_name = domain

        # Also try to extract from CNAME
        for cname in dns_result.cname_chain:
            match = re.match(r"^([^.]+)\.s3[.\-]", cname)
            if match:
                bucket_name = match.group(1)
                break

        try:
            # Check bucket existence via direct S3 URL
            resp = self.session.get(
                f"https://s3.amazonaws.com/{bucket_name}",
                timeout=self.timeout,
                verify=True,
            )

            if "NoSuchBucket" in resp.text or resp.status_code == 404:
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"S3 bucket '{bucket_name}' does not exist",
                    validator_notes=(
                        f"Bucket can be created: aws s3 mb s3://{bucket_name} "
                        f"then enable website hosting"
                    )
                )

            if resp.status_code == 403:
                return ValidationResult(
                    validated=True,
                    claimable=False,
                    validator_notes=f"Bucket '{bucket_name}' exists but is private (403)"
                )

            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes=f"Bucket '{bucket_name}' exists (status: {resp.status_code})"
            )

        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))

    def validate_cloudfront(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        CloudFront validation is complex.
        Flag for manual review - we can't safely test without an AWS account.
        """
        return ValidationResult(
            validated=False,
            claimable=False,
            validator_notes=(
                "CloudFront takeover requires manual verification. "
                "Need to create a CloudFront distribution with this CNAME. "
                "See: https://blog.detectify.com/2014/10/21/"
                "hostile-subdomain-takeover-using-herokugithubdesk-more/"
            )
        )

    def validate_azure(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Check if Azure App Service name is available.
        CNAME: <appname>.azurewebsites.net
        """
        app_name = None
        for cname in dns_result.cname_chain:
            match = re.match(r"^([a-zA-Z0-9_-]+)\.azurewebsites\.net$", cname)
            if match:
                app_name = match.group(1)
                break

        if not app_name:
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Could not extract Azure app name from CNAME"
            )

        try:
            resp = self.session.get(
                f"https://{app_name}.azurewebsites.net",
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 404 and (
                "web app not found" in resp.text.lower() or
                "404" in resp.text
            ):
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"Azure App Service '{app_name}' does not exist",
                    validator_notes=f"App name available: {app_name}.azurewebsites.net"
                )
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes=f"Azure App '{app_name}' appears to exist ({resp.status_code})"
            )
        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))

    def validate_shopify(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Shopify takeover requires an active store.
        We can verify the shop name is available via Shopify's check.
        """
        shop_name = None
        for cname in dns_result.cname_chain:
            match = re.match(r"^([a-zA-Z0-9_-]+)\.myshopify\.com$", cname)
            if match:
                shop_name = match.group(1)
                break

        if not shop_name:
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Could not extract Shopify shop name"
            )

        try:
            resp = self.session.get(
                f"https://{shop_name}.myshopify.com",
                timeout=self.timeout,
                verify=True,
            )
            if resp.status_code == 404 or "sorry, this shop is currently unavailable" in resp.text.lower():
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"Shopify shop '{shop_name}' is available",
                    validator_notes=f"Shop name available: {shop_name}.myshopify.com"
                )
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes=f"Shopify shop '{shop_name}' exists"
            )
        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))

    def validate_netlify(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Check if Netlify subdomain is unclaimed.
        """
        netlify_sub = None
        for cname in dns_result.cname_chain:
            match = re.match(r"^([a-zA-Z0-9_-]+)\.netlify\.app$", cname)
            if match:
                netlify_sub = match.group(1)
                break

        if not netlify_sub:
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Could not extract Netlify subdomain"
            )

        try:
            resp = self.session.get(
                f"https://{netlify_sub}.netlify.app",
                timeout=self.timeout,
                verify=True,
            )
            if resp.status_code == 404 and "not found" in resp.text.lower():
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence=f"Netlify subdomain '{netlify_sub}' is unclaimed",
                    validator_notes=f"Deploy any site to claim: {netlify_sub}.netlify.app"
                )
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes=f"Netlify subdomain '{netlify_sub}' is taken"
            )
        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))

    def validate_surge(self, domain: str, dns_result: DNSResult) -> ValidationResult:
        """
        Surge.sh - check if project is claimed.
        Surge subdomains can be claimed with one CLI command.
        """
        surge_sub = None
        for cname in dns_result.cname_chain:
            if "surge.sh" in cname:
                surge_sub = cname
                break

        try:
            resp = self.session.get(
                f"https://{domain}",
                timeout=self.timeout,
                verify=False,
            )
            if resp.status_code == 404 and "project not found" in resp.text.lower():
                return ValidationResult(
                    validated=True,
                    claimable=True,
                    claim_evidence="Surge project is unclaimed",
                    validator_notes=(
                        f"Claim with: mkdir /tmp/proof && "
                        f"cd /tmp/proof && echo 'proof' > index.html && "
                        f"surge --domain {domain}"
                    )
                )
            return ValidationResult(
                validated=True,
                claimable=False,
                validator_notes="Surge project appears active"
            )
        except Exception as e:
            return ValidationResult(validated=False, validator_notes=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT MATCHING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class FingerprintEngine:
    """
    Multi-layer fingerprint matching with confidence scoring.
    Uses regex for all pattern matching (not simple string contains).
    """

    def __init__(self, logger: NemesisLogger = None):
        self.log = logger or NemesisLogger()

        # Pre-compile all regex patterns for performance
        self._compiled_db = {}
        for service, fp in FINGERPRINT_DB.items():
            self._compiled_db[service] = {
                "cname_patterns": [
                    re.compile(p, re.IGNORECASE)
                    for p in fp.get("cname_patterns", [])
                ],
                "http_patterns": [
                    re.compile(p, re.IGNORECASE | re.DOTALL)
                    for p in fp.get("http_patterns", [])
                ],
                "header_patterns": {
                    h: re.compile(p, re.IGNORECASE)
                    for h, p in fp.get("headers", {}).items()
                },
            }

    def _score_finding(
        self,
        cname_match: bool,
        http_match: bool,
        header_match: bool,
        status_match: bool,
        nxdomain: bool,
        fingerprint_confidence: str,
        claimable: bool,
        validation: Optional[ValidationResult],
    ) -> Tuple[int, str]:
        """
        Score-based confidence calculation.
        Returns (score, confidence_level)

        Scoring rubric:
          CNAME match:              +40 pts  (primary indicator)
          HTTP body match:          +30 pts  (secondary indicator)
          Status code match:        +10 pts
          Header match:             +15 pts
          NXDOMAIN (dangling):      +10 pts  (DNS dangling)
          Validated claimable:      +30 pts  (PROOF it's vulnerable)
          Fingerprint UNCERTAIN:    -20 pts  (penalty for low confidence)
          Fingerprint PROBABLE:     -5 pts
        """
        score = 0

        if cname_match:    score += 40
        if http_match:     score += 30
        if status_match:   score += 10
        if header_match:   score += 15
        if nxdomain:       score += 10

        if validation and validation.validated and validation.claimable:
            score += 30

        # Confidence penalties
        if fingerprint_confidence == "UNCERTAIN":
            score -= 20
        elif fingerprint_confidence == "PROBABLE":
            score -= 5

        # Determine confidence level
        if score >= 80:
            confidence = "HIGH"
        elif score >= 50:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return score, confidence

    def analyze(
        self,
        domain: str,
        dns_result: DNSResult,
        http_result: HTTPResult,
    ) -> List[Tuple[str, Dict, int, str, List[str], Dict[str, str]]]:
        """
        Analyze DNS + HTTP results against all fingerprints.
        Returns list of (service_name, fingerprint, score, confidence, matched_http, matched_headers)
        """
        matches = []

        for service, fp in FINGERPRINT_DB.items():
            compiled = self._compiled_db[service]

            matched_cnames = []
            matched_http_patterns = []
            matched_headers = {}

            # ── CNAME chain analysis ────────────────────────────────────────
            cname_match = False
            for cname in dns_result.cname_chain:
                for pattern in compiled["cname_patterns"]:
                    if pattern.search(cname):
                        cname_match = True
                        matched_cnames.append(cname)
                        break

            # ── HTTP body analysis ──────────────────────────────────────────
            http_match = False
            if http_result.accessible and http_result.full_body:
                for pattern in compiled["http_patterns"]:
                    m = pattern.search(http_result.full_body)
                    if m:
                        http_match = True
                        matched_http_patterns.append(m.group(0)[:100])

            # ── Header analysis ─────────────────────────────────────────────
            header_match = False
            for header_name, header_pattern in compiled["header_patterns"].items():
                actual_val = http_result.headers.get(header_name, "")
                if actual_val and header_pattern.search(actual_val):
                    header_match = True
                    matched_headers[header_name] = actual_val

            # ── Status code check ───────────────────────────────────────────
            status_match = (
                http_result.status_code in fp.get("status_codes", [])
                if http_result.status_code is not None
                else False
            )

            # ── Minimum match requirement ───────────────────────────────────
            # Must have CNAME match OR (HTTP match AND status match)
            # Pure HTTP-only matches without CNAME → UNCERTAIN, flag for review
            if not cname_match and not (http_match and status_match):
                continue

            # ── Score ───────────────────────────────────────────────────────
            score, confidence = self._score_finding(
                cname_match=cname_match,
                http_match=http_match,
                header_match=header_match,
                status_match=status_match,
                nxdomain=dns_result.nxdomain,
                fingerprint_confidence=fp["confidence"],
                claimable=fp.get("claimable", False),
                validation=None,  # Not yet validated at this stage
            )

            if score < 30:
                continue  # Too low confidence, skip

            matches.append((
                service,
                fp,
                score,
                confidence,
                matched_http_patterns,
                matched_headers,
                cname_match,
                matched_cnames,
            ))
            self.log.debug(f"Fingerprint match: {domain} → {service} (score={score}, conf={confidence})")

        return matches


# ─────────────────────────────────────────────────────────────────────────────
# IP RANGE CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class IPRangeChecker:
    """
    Check if A records fall within known provider IP ranges.
    Catches cases where there's no CNAME but a dangling A record.
    """

    def __init__(self, logger: NemesisLogger = None):
        self.log = logger or NemesisLogger()
        self._networks = {}
        for provider, ranges in IP_RANGE_PROVIDERS.items():
            self._networks[provider] = [
                ipaddress.ip_network(r, strict=False) for r in ranges
            ]

    def identify_provider(self, ip_addresses: List[str]) -> Optional[str]:
        """Return provider name if IP is in known range"""
        for ip_str in ip_addresses:
            try:
                ip = ipaddress.ip_address(ip_str)
                for provider, networks in self._networks.items():
                    for network in networks:
                        if ip in network:
                            return provider
            except ValueError:
                continue
        return None


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate professional bug bounty ready reports"""

    SEVERITY_COLORS = {
        "CRITICAL": "\033[41m\033[97m",  # Red background
        "HIGH":     "\033[91m",           # Bright red
        "MEDIUM":   "\033[93m",           # Yellow
        "LOW":      "\033[96m",           # Cyan
    }
    RESET = "\033[0m"

    def __init__(self, logger: NemesisLogger = None):
        self.log = logger or NemesisLogger()

    def print_finding(self, finding: TakeoverFinding, index: int):
        """Print a single finding in a professional format"""
        sev_color = self.SEVERITY_COLORS.get(finding.severity, "")

        print(f"\n{'═' * 80}")
        print(f"  FINDING #{index}: {sev_color}{finding.severity}{self.RESET} | {finding.service.upper()}")
        print(f"{'═' * 80}")
        print(f"  Domain    : {finding.domain}")
        print(f"  Service   : {finding.service}")
        print(f"  Severity  : {sev_color}{finding.severity}{self.RESET}")
        print(f"  Confidence: {finding.confidence_level} (score: {finding.score})")
        print(f"  DB Confidence: {finding.fingerprint_confidence}")
        print(f"  Timestamp : {finding.timestamp}")

        if finding.cname_chain:
            print(f"\n  DNS Chain:")
            for i, cname in enumerate(finding.cname_chain):
                print(f"    {'└─' if i == len(finding.cname_chain)-1 else '├─'} {cname}")

        if finding.matched_http_patterns:
            print(f"\n  HTTP Evidence:")
            for p in finding.matched_http_patterns:
                print(f"    - \"{p}\"")

        if finding.matched_headers:
            print(f"\n  Matched Headers:")
            for h, v in finding.matched_headers.items():
                print(f"    {h}: {v}")

        if finding.http_status_code:
            print(f"\n  HTTP Status: {finding.http_status_code}")

        if finding.validation:
            print(f"\n  Validation:")
            print(f"    Validated : {finding.validation.validated}")
            print(f"    Claimable : {finding.validation.claimable}")
            if finding.validation.claim_evidence:
                print(f"    Evidence  : {finding.validation.claim_evidence}")
            if finding.validation.validator_notes:
                print(f"    Notes     : {finding.validation.validator_notes}")

        print(f"\n  How to Claim:")
        print(f"    {finding.claim_instructions}")

        if finding.notes:
            print(f"\n  ⚠ Notes: {finding.notes}")

        print(f"\n  Reference: {finding.documentation_url}")

    def print_summary(self, findings: List[TakeoverFinding], total_scanned: int, elapsed: float):
        """Print final summary"""
        print(f"\n{'═' * 80}")
        print(f"  NEMESIS SCAN COMPLETE")
        print(f"{'═' * 80}")
        print(f"  Scanned  : {total_scanned} subdomains")
        print(f"  Duration : {elapsed:.2f}s ({total_scanned/elapsed:.1f}/sec)")
        print(f"  Findings : {len(findings)}")

        if findings:
            by_severity = {}
            for f in findings:
                by_severity.setdefault(f.severity, []).append(f)

            print(f"\n  By Severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = len(by_severity.get(sev, []))
                if count:
                    color = self.SEVERITY_COLORS.get(sev, "")
                    print(f"    {color}{sev}{self.RESET}: {count}")

            print(f"\n  By Confidence:")
            high_conf   = [f for f in findings if f.confidence_level == "HIGH"]
            medium_conf = [f for f in findings if f.confidence_level == "MEDIUM"]
            low_conf    = [f for f in findings if f.confidence_level == "LOW"]
            print(f"    HIGH   : {len(high_conf)}")
            print(f"    MEDIUM : {len(medium_conf)}")
            print(f"    LOW    : {len(low_conf)}")
        print(f"{'═' * 80}\n")

    def export_json(self, findings: List[TakeoverFinding], output_path: str):
        """Export findings to structured JSON"""
        data = []
        for f in findings:
            entry = asdict(f)
            # Clean up validation
            if f.validation:
                entry["validation"] = {
                    "validated": f.validation.validated,
                    "claimable": f.validation.claimable,
                    "claim_evidence": f.validation.claim_evidence,
                    "validator_notes": f.validation.validator_notes,
                }
            data.append(entry)

        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2, default=str)

        self.log.success(f"Results exported → {output_path}")

    def export_markdown(self, findings: List[TakeoverFinding], output_path: str):
        """Export findings as a bug bounty ready Markdown report"""
        lines = [
            "# Subdomain Takeover Report",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Findings:** {len(findings)}",
            "",
        ]

        for i, f in enumerate(findings, 1):
            lines += [
                f"## Finding #{i}: {f.severity} — {f.domain}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Domain | `{f.domain}` |",
                f"| Service | {f.service} |",
                f"| Severity | **{f.severity}** |",
                f"| Confidence | {f.confidence_level} (score: {f.score}) |",
                f"| Timestamp | {f.timestamp} |",
                "",
                "### DNS Chain",
                "```",
            ]
            for cname in f.cname_chain:
                lines.append(f"  → {cname}")
            lines += ["```", ""]

            if f.matched_http_patterns:
                lines += ["### HTTP Evidence", "```"]
                for p in f.matched_http_patterns:
                    lines.append(f"  {p}")
                lines += ["```", ""]

            if f.validation and f.validation.claim_evidence:
                lines += [
                    "### Validation",
                    f"- **Claimable:** {f.validation.claimable}",
                    f"- **Evidence:** {f.validation.claim_evidence}",
                    f"- **Notes:** {f.validation.validator_notes}",
                    "",
                ]

            lines += [
                "### How to Claim",
                f"{f.claim_instructions}",
                "",
                f"**Reference:** {f.documentation_url}",
                "",
                "---",
                "",
            ]

        with open(output_path, "w") as fh:
            fh.write("\n".join(lines))

        self.log.success(f"Markdown report → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class NemesisScanner:
    """
    Main orchestrator.
    Pipeline: DNS → HTTP → Fingerprint → Validate → Report

    Designed for:
    - High accuracy (multi-stage verification)
    - Low false positives (scoring + validators)
    - Professional output (bug bounty ready)
    """

    def __init__(self, config: Dict):
        self.config = config
        self.log = NemesisLogger(
            verbose=config.get("verbose", False),
            log_file=config.get("log_file"),
        )

        self.dns_engine = DNSEngine(
            timeout=config.get("timeout", 5.0),
            logger=self.log,
        )
        self.http_engine = HTTPEngine(
            timeout=config.get("timeout", 5.0),
            logger=self.log,
            rate_limit=config.get("rate_limit", 0.0),
            proxies=config.get("proxies"),
        )
        self.fingerprint_engine = FingerprintEngine(logger=self.log)
        self.validators = ServiceValidators(
            timeout=config.get("timeout", 5.0),
            logger=self.log,
        )
        self.ip_checker = IPRangeChecker(logger=self.log)
        self.reporter = ReportGenerator(logger=self.log)

        self._findings: List[TakeoverFinding] = []
        self._findings_lock = threading.Lock()
        self._scanned = 0
        self._scanned_lock = threading.Lock()

    def _scan_one(self, domain: str) -> Optional[TakeoverFinding]:
        """
        Full pipeline for a single subdomain.

        Stage 1: DNS
        Stage 2: HTTP
        Stage 3: Fingerprint matching
        Stage 4: Service validation
        Stage 5: Return finding
        """
        domain = domain.strip().lower()
        if not domain:
            return None

        # ── Stage 1: DNS ─────────────────────────────────────────────────────
        dns_result = self.dns_engine.resolve(domain)

        # Skip if completely non-existent AND no interesting DNS
        if not dns_result.resolves and not dns_result.nxdomain:
            self.log.debug(f"[SKIP] {domain}: No DNS resolution")
            return None

        # ── Stage 2: HTTP ────────────────────────────────────────────────────
        # Only probe HTTP if we have DNS results (avoid dead connections)
        http_result = HTTPResult(domain=domain)
        if dns_result.resolves or dns_result.a_records:
            http_result = self.http_engine.probe(domain)

        # ── Stage 3: IP Range Check (for A record only cases) ────────────────
        provider_by_ip = self.ip_checker.identify_provider(dns_result.a_records)
        if provider_by_ip and not dns_result.cname_chain:
            self.log.info(f"IP range match: {domain} → {provider_by_ip}")
            # Add synthetic CNAME-like entry for fingerprinting
            dns_result.cname_chain.append(f"[IP-RANGE:{provider_by_ip}]")

        # ── Stage 4: Fingerprint Matching ────────────────────────────────────
        matches = self.fingerprint_engine.analyze(domain, dns_result, http_result)

        if not matches:
            return None

        # Take highest-scoring match
        best = max(matches, key=lambda x: x[2])
        (
            service_name, fp, score, confidence,
            matched_http, matched_headers,
            cname_match, matched_cnames
        ) = best

        # ── Stage 5: Service Validation ──────────────────────────────────────
        skip_uncertain = not self.config.get("include_uncertain", False)
        if skip_uncertain and fp["confidence"] == "UNCERTAIN" and confidence != "HIGH":
            self.log.debug(f"[SKIP] {domain}: UNCERTAIN fingerprint + not HIGH confidence")
            return None

        validation = None
        if self.config.get("validate", True):
            validation = self.validators.validate(service_name, domain, dns_result)

            # Recalculate score with validation data
            score, confidence = self.fingerprint_engine._score_finding(
                cname_match=cname_match,
                http_match=bool(matched_http),
                header_match=bool(matched_headers),
                status_match=(http_result.status_code in fp.get("status_codes", [])),
                nxdomain=dns_result.nxdomain,
                fingerprint_confidence=fp["confidence"],
                claimable=fp.get("claimable", False),
                validation=validation,
            )

        # ── Build Finding ────────────────────────────────────────────────────
        finding = TakeoverFinding(
            domain=domain,
            service=service_name,
            severity=fp["severity"],
            confidence_level=confidence,
            fingerprint_confidence=fp["confidence"],
            cname_chain=dns_result.cname_chain,
            matched_cname_pattern=matched_cnames[0] if matched_cnames else "",
            matched_http_patterns=matched_http,
            matched_headers=matched_headers,
            http_status_code=http_result.status_code,
            validation=validation,
            claim_instructions=fp["claim_instructions"],
            documentation_url=fp["docs"],
            notes=fp.get("notes", ""),
            score=score,
        )

        # Log the finding
        self.log.vuln(
            f"VULNERABLE: {domain} → {service_name} "
            f"[{confidence} / {fp['confidence']} / score={score}]"
        )

        return finding

    def scan(self, subdomains: List[str]) -> List[TakeoverFinding]:
        """
        Concurrent scan of all subdomains.
        Returns all findings sorted by score.
        """
        threads = self.config.get("threads", 30)
        findings = []

        self.log.stage(f"Starting scan: {len(subdomains)} targets | {threads} threads")
        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_domain = {
                executor.submit(self._scan_one, domain): domain
                for domain in subdomains
            }

            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                with self._scanned_lock:
                    self._scanned += 1

                try:
                    result = future.result()
                    if result:
                        with self._findings_lock:
                            findings.append(result)
                except Exception as e:
                    self.log.error(f"Scan failed [{domain}]: {e}")

        elapsed = time.time() - start

        # Sort by score descending
        findings.sort(key=lambda x: x.score, reverse=True)

        # Print all findings
        for i, f in enumerate(findings, 1):
            self.reporter.print_finding(f, i)

        # Print summary
        self.reporter.print_summary(findings, self._scanned, elapsed)

        # Export
        output_json = self.config.get("output_json", "nemesis_results.json")
        output_md   = self.config.get("output_md",   "nemesis_report.md")

        if findings:
            self.reporter.export_json(findings, output_json)
            self.reporter.export_markdown(findings, output_md)

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝

    S-Tier Subdomain Takeover Hunter | Bug Bounty Edition
    Fingerprints: {fp_count} | Validators: {val_count}
"""


def main():
    parser = argparse.ArgumentParser(
        description="NEMESIS - S-Tier Subdomain Takeover Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan from file
  python3 nemesis.py -f subdomains.txt

  # Scan single domain with full validation
  python3 nemesis.py -d staging.example.com -v --validate

  # Fast scan without validation (first pass)
  python3 nemesis.py -f subs.txt -t 50 --no-validate

  # Include uncertain fingerprints
  python3 nemesis.py -f subs.txt --include-uncertain

  # With proxy (Burp Suite)
  python3 nemesis.py -f subs.txt --proxy http://127.0.0.1:8080

Recommended Workflow:
  1. Get subdomains: subfinder -d target.com | amass enum -d target.com
  2. Fast first pass: python3 nemesis.py -f subs.txt -t 50 --no-validate
  3. Validate findings: python3 nemesis.py -f findings.txt --validate -v
  4. Review report: nemesis_report.md
  5. Manual verification before reporting
        """,
    )

    parser.add_argument("-f", "--file",    help="File with subdomains (one per line)")
    parser.add_argument("-d", "--domain",  help="Single domain to scan")
    parser.add_argument("-o", "--output",  default="nemesis_results.json", help="JSON output file")
    parser.add_argument("-m", "--markdown",default="nemesis_report.md",    help="Markdown report file")
    parser.add_argument("-t", "--threads", type=int, default=30,            help="Thread count (default: 30)")
    parser.add_argument("--timeout",       type=float, default=8.0,         help="Request timeout (default: 8s)")
    parser.add_argument("--rate-limit",    type=float, default=0.0,         help="Delay between requests (seconds)")
    parser.add_argument("--validate",      action="store_true", default=True,help="Run service validators (default: on)")
    parser.add_argument("--no-validate",   action="store_true",             help="Skip service validators")
    parser.add_argument("--include-uncertain", action="store_true",         help="Include UNCERTAIN fingerprints")
    parser.add_argument("--proxy",         help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true",             help="Verbose output")
    parser.add_argument("--log-file",      help="Write logs to file")

    args = parser.parse_args()

    # Load subdomains
    subdomains = []
    if args.file:
        try:
            with open(args.file) as fh:
                subdomains = [l.strip() for l in fh if l.strip()]
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)
    elif args.domain:
        subdomains = [args.domain]
    else:
        parser.print_help()
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    subdomains = [s for s in subdomains if not (s in seen or seen.add(s))]

    # Count validators
    val_count = len([
        fp for fp in FINGERPRINT_DB.values()
        if fp.get("validator")
    ])

    print(BANNER.format(fp_count=len(FINGERPRINT_DB), val_count=val_count))
    print(f"  Targets  : {len(subdomains)}")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  Validate : {not args.no_validate}")
    print(f"  Proxy    : {args.proxy or 'None'}")
    print()

    proxies = {}
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    config = {
        "threads":           args.threads,
        "timeout":           args.timeout,
        "rate_limit":        args.rate_limit,
        "validate":          not args.no_validate,
        "include_uncertain": args.include_uncertain,
        "verbose":           args.verbose,
        "log_file":          args.log_file,
        "output_json":       args.output,
        "output_md":         args.markdown,
        "proxies":           proxies,
    }

    scanner = NemesisScanner(config)
    findings = scanner.scan(subdomains)

    # Exit code useful for CI/CD pipelines
    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
