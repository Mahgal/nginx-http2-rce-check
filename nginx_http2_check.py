#!/usr/bin/env python3
"""nginx-http2-rce-check: are you exposed to the nginx HTTP/2 RCE pair?

Defensive checker only. Stdlib only, zero network calls, zero payloads.

On 2026-11-18, Wiz, Ikotas Labs, Metnir, Rapid7 and Xint disclosed two
unauthenticated remote code execution flaws in nginx's HTTP/2 handling
(CVE-2026-123007 and CVE-2026-123633, both CVSS 4.0 9.2). Wiz confirmed
RCE with an ASLR bypass on stock 1.31.7/1.31.8 serving plain static files.
Both flaws need HTTP/2 enabled; neither is a default configuration.

This tool checks the two things that decide exposure:

  1. the nginx version (branch-aware: 1.30.7 is FIXED, but 1.31.0-1.31.8
     on the mainline branch are still vulnerable), and
  2. whether HTTP/2 is enabled in the nginx configuration.

It never sends a request, never scans the network, and contains no
exploit code. A version string alone cannot prove a distro package is
safe or unsafe (distros backport fixes), so distro builds are reported
UNKNOWN with an explanation instead of guessed.

Usage:
    python3 nginx_http2_check.py [--version VERSION]
                                 [--nginx-path PATH] [--config PATH]
                                 [--json] [--demo]

Exit codes:
    0  PATCHED or NOT_AFFECTED
    1  VULNERABLE (by design: use as a CI gate)
    2  usage error (bad flag, unreadable --nginx-path/--config path)
    3  UNKNOWN (no nginx found, unparsable version, distro build, or
       HTTP/2 state could not be determined while the version is in an
       affected range)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

CVE_123007 = "CVE-2026-123007"
CVE_123633 = "CVE-2026-123633"

# Affected / fixed version table for NGINX Open Source, from the nginx.org
# security advisories and the Wiz write-up (2026-11-18). Each entry is
# (first_affected, last_affected, first_fixed); versions are tuples
# compared after padding with zeros. The ranges are branch-aware: the
# stable branch is fixed at 1.30.7 while the mainline branch stays
# vulnerable through 1.31.8, so a plain "version >= 1.30.7 means safe"
# comparison is WRONG and is exactly the trap this table avoids.
OSS_TABLE = {
    # (first_affected, last_affected, first_fixed)
    CVE_123007: ((1, 9, 5), (1, 31, 8), (1, 30, 7)),
    CVE_123633: ((1, 19, 7), (1, 31, 8), (1, 30, 7)),
}
# Mainline fix: 1.31.9. Any mainline release >= 1.31.9 is fixed; any
# release >= 1.32.0 is likewise fixed (it is newer than 1.31.9).
MAINLINE_FIXED = (1, 31, 9)
# Stable branch: 1.30.7 fixed; 1.30.8+ (if ever released) is newer than
# the fix on the same branch, so also fixed.
STABLE_FIXED = (1, 30, 7)

FIXED_RELEASES = "1.30.7 (stable) / 1.31.9 (mainline)"

# NGINX Plus. First affected: R33 (both CVEs). R33-R36 have NO fixed
# build and must move to a 37.x train. Fixed builds per CVE, from the
# F5 advisories via Wiz: 123633 fixed in 37.0.7.1 and 37.2.0.1;
# 123007 fixed in 37.0.8.1 and 37.3.0.1. A later build on the SAME
# train includes earlier fixes on that train, so 37.0.8.1 also closes
# 123633, and 37.3.0.1 closes both (per the F5 advisory summaries).
# The 37.2 train has no published 123007 fix; the 37.1 train has no
# published fix for either CVE — both are reported UNKNOWN, not guessed.
PLUS_FIRST_AFFECTED_RELEASE = 33  # R33
PLUS_TABLE = {
    # train (major, minor) -> {cve: first fixed build tuple, None (no
# published fix on this train — unknown), or "affected" (published as
# still vulnerable on this train, e.g. 37.2.0.1 for CVE-2026-123007)}
    (37, 0): {CVE_123633: (37, 0, 7, 1), CVE_123007: (37, 0, 8, 1)},
    (37, 2): {CVE_123633: (37, 2, 0, 1), CVE_123007: "affected"},
    (37, 3): {CVE_123633: (37, 3, 0, 1), CVE_123007: (37, 3, 0, 1)},
}
PLUS_FIXED_ADVICE = ("37.0.8.1 or 37.3.0.1 (both close both HTTP/2 CVEs); "
                     "37.0.7.1 / 37.2.0.1 close CVE-2026-123633 only")

DEFAULT_CONFIG_PATHS = ("/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf")


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def _pad(version, length=5):
    return tuple(version) + (0,) * (length - len(version))


def _parse_numbered(core):
    """'1.31.8' -> (1, 31, 8). None if any component is not a plain number."""
    parts = core.split(".")
    nums = []
    for part in parts:
        if not part.isdigit():
            return None
        nums.append(int(part))
    return tuple(nums) if nums else None


_VERSION_RE = re.compile(r"nginx/([^\s\)]+)")
_PLUS_RE = re.compile(r"nginx-plus-r(\d+)", re.IGNORECASE)


def parse_nginx_version(text):
    """Parse `nginx -v` output or a bare version string.

    Returns dict with keys:
      raw: the version token as found (or None),
      kind: 'oss' | 'plus' | 'unknown',
      version: int tuple (OSS) or None,
      plus_release: int R-number for Plus (e.g. 37) or None,
      plus_build: int tuple for a Plus 37.x build (e.g. (37, 0, 8, 1))
                  or None,
      distro: True if the string carries a distro-package marker,
      display: short display string for output.
    """
    text = text or ""
    match = _VERSION_RE.search(text)
    raw = match.group(1) if match else None
    if raw is None:
        # Maybe the caller passed a bare version like "1.31.8" or a
        # distro package version like "1.24.0-0ubuntu1" (one token).
        stripped = text.strip()
        if stripped and re.fullmatch(r"[0-9][0-9A-Za-z.+\-~]*", stripped):
            raw = stripped
    plus_match = _PLUS_RE.search(text)
    plus_release = int(plus_match.group(1)) if plus_match else None
    if raw is None:
        if plus_release is not None:
            # e.g. "nginx-plus-r37 37.0.8.1" — no nginx/ token, but the
            # Plus release and build are both recoverable.
            build_match = re.search(r"\b(37\.\d+\.\d+\.\d+)\b", text)
            plus_build = _parse_numbered(build_match.group(1)) \
                if build_match else None
            return {"raw": None, "kind": "plus", "version": None,
                    "plus_release": plus_release, "plus_build": plus_build,
                    "distro": False,
                    "display": "nginx-plus-r%d%s" % (
                        plus_release,
                        (" %s" % build_match.group(1)) if build_match else "")}
        return {"raw": None, "kind": "unknown", "version": None,
                "plus_release": plus_release, "plus_build": None,
                "distro": False, "display": None}
    # Distro marker: a package release suffix in the version token
    # ("-1", "-0ubuntu1", "~deb12u1", a "+" build tag), or a
    # parenthesised distro suffix in the full string ("(Ubuntu)").
    # The "(nginx-plus-rN)" marker is Plus, not a distro suffix.
    # Distro packages backport security fixes, so the upstream number
    # says nothing either way; the caller must treat this as UNKNOWN.
    distro = bool(re.search(r"[-+~]", raw))
    suffix_text = re.sub(r"\(nginx-plus-r\d+\)", "", text, flags=re.IGNORECASE)
    if "(" in suffix_text:
        distro = True
    version = _parse_numbered(raw.split("-")[0].split("+")[0].split("(")[0])
    if plus_release is not None:
        # Plus reports "nginx/1.27.4 (nginx-plus-r37)" style strings;
        # the R-number is the release train, the build (37.x.y.z)
        # comes from a separate "37.0.8.1" style token if present.
        build_match = re.search(r"\b(37\.\d+\.\d+\.\d+)\b", text)
        plus_build = _parse_numbered(build_match.group(1)) if build_match \
            else None
        return {"raw": raw, "kind": "plus", "version": version,
                "plus_release": plus_release, "plus_build": plus_build,
                "distro": distro,
                "display": "nginx-plus-r%d%s" % (
                    plus_release,
                    (" %s" % build_match.group(1)) if build_match else ""),
                }
    if version is None:
        return {"raw": raw, "kind": "unknown", "version": None,
                "plus_release": None, "plus_build": None,
                "distro": distro, "display": raw}
    return {"raw": raw, "kind": "oss", "version": version,
            "plus_release": None, "plus_build": None,
            "distro": distro, "display": ".".join(str(x) for x in version)}


def _oss_cve_status(version, cve):
    """Status of one CVE for an OSS version tuple.

    Returns 'affected' | 'patched' | 'not_affected'. The branch trap
    lives here: 1.30.7 is patched, 1.31.0-1.31.8 are affected, 1.31.9+
    is patched — never a plain numeric >= 1.30.7 comparison."""
    first_affected, last_affected, _first_fixed = OSS_TABLE[cve]
    padded = _pad(version)
    if padded < _pad(first_affected):
        return "not_affected"
    # Stable branch 1.30.x: fixed at 1.30.7.
    if version[0:2] == (1, 30):
        return "patched" if padded >= _pad(STABLE_FIXED) else "affected"
    # Mainline branch 1.31.x: fixed at 1.31.9.
    if version[0:2] == (1, 31):
        return "patched" if padded >= _pad(MAINLINE_FIXED) else "affected"
    # Any release newer than 1.31.9 (e.g. 1.32.0) is past the fix.
    if padded >= _pad(MAINLINE_FIXED):
        return "patched"
    # Anything else in the published range (e.g. 1.9.5-1.29.x) is affected.
    if padded <= _pad(last_affected):
        return "affected"
    return "not_affected"


def _plus_cve_status(parsed, cve):
    """Status of one CVE for an NGINX Plus build.

    Returns ('affected'|'patched'|'not_affected'|'unknown', reason)."""
    release = parsed["plus_release"]
    build = parsed["plus_build"]
    if release is not None and release < PLUS_FIRST_AFFECTED_RELEASE:
        return "not_affected", ("NGINX Plus R%d predates the first "
                                "affected release R%d" % (
                                    release, PLUS_FIRST_AFFECTED_RELEASE))
    if build is None:
        # We know the R-number but not the 37.x build: R33-R36 have no
        # fixed build at all, so they are affected; R37 needs the build.
        if release is not None and 33 <= release <= 36:
            return "affected", ("NGINX Plus R%d has no fixed build — "
                                "R33-R36 must move to a 37.x train"
                                % release)
        return "unknown", ("NGINX Plus release known (R%s), but no 37.x "
                           "build number given — cannot tell which fix "
                           "it carries" % release)
    train = (build[0], build[1]) if len(build) >= 2 else None
    entry = PLUS_TABLE.get(train)
    if entry is None:
        return "unknown", ("NGINX Plus build %s is on train %s, for which "
                           "no published fix is listed for %s"
                           % (".".join(str(x) for x in build),
                              ".".join(str(x) for x in train) if train else "?",
                              cve))
    fixed = entry[cve]
    if fixed == "affected":
        # Published as still vulnerable on this train (37.2.0.1 fixes
        # only CVE-2026-123633); no fix for this CVE on the train.
        return "affected", ("build %s fixes only CVE-2026-123633 and is "
                            "still vulnerable to %s — no %s fix is "
                            "published on this train"
                            % (".".join(str(x) for x in build), cve, cve))
    if fixed is None:
        return "unknown", ("no published fix for %s on the %s train — "
                           "check the F5 advisory for this build"
                           % (cve, ".".join(str(x) for x in train)))
    if _pad(build, 4) >= _pad(fixed, 4):
        return "patched", ("%s is at or above the fixed build %s"
                           % (".".join(str(x) for x in build),
                              ".".join(str(x) for x in fixed)))
    return "affected", ("%s is below the fixed build %s for %s"
                        % (".".join(str(x) for x in build),
                           ".".join(str(x) for x in fixed), cve))


def classify_version(parsed):
    """Classify a parsed version.

    Returns (status, reasons) where status is 'affected' | 'patched' |
    'not_affected' | 'unknown' and reasons is a list of per-CVE lines.
    'affected' wins over 'unknown' (a known-vulnerable CVE is actionable
    even if the other CVE's status is unknown)."""
    if parsed["kind"] == "unknown":
        return "unknown", ["could not parse a version number from the "
                           "nginx version output"]
    if parsed["distro"]:
        return "unknown", [
            "version string %r looks like a distro package build — "
            "distro packages backport security fixes, so the upstream "
            "number says nothing either way" % parsed["raw"],
            "Check your distro's security tracker (e.g. Debian/Ubuntu "
            "CVE tracker) for %s / %s, or install the upstream build "
            "%s and re-run this check." % (CVE_123007, CVE_123633,
                                           FIXED_RELEASES)]
    if parsed["kind"] == "plus":
        statuses = {}
        reasons = []
        for cve in (CVE_123007, CVE_123633):
            status, reason = _plus_cve_status(parsed, cve)
            statuses[cve] = status
            reasons.append("%s: %s — %s" % (cve, status.upper(), reason))
        if any(s == "affected" for s in statuses.values()):
            return "affected", reasons
        if any(s == "unknown" for s in statuses.values()):
            return "unknown", reasons
        if all(s == "not_affected" for s in statuses.values()):
            return "not_affected", reasons
        return "patched", reasons
    # OSS.
    statuses = {}
    reasons = []
    for cve in (CVE_123007, CVE_123633):
        status = _oss_cve_status(parsed["version"], cve)
        statuses[cve] = status
        first_affected, _last, _fixed = OSS_TABLE[cve]
        if status == "affected":
            reasons.append("%s: AFFECTED — nginx %s is in the affected "
                           "range (first affected %s; fixed in %s)"
                           % (cve, parsed["display"],
                              ".".join(str(x) for x in first_affected),
                              FIXED_RELEASES))
        elif status == "patched":
            reasons.append("%s: PATCHED — nginx %s is at or above a "
                           "fixed release (%s)"
                           % (cve, parsed["display"], FIXED_RELEASES))
        else:
            reasons.append("%s: NOT AFFECTED — nginx %s predates the "
                           "first affected release %s"
                           % (cve, parsed["display"],
                              ".".join(str(x) for x in first_affected)))
    if any(s == "affected" for s in statuses.values()):
        return "affected", reasons
    if all(s == "patched" for s in statuses.values()):
        return "patched", reasons
    return "not_affected", reasons


# ---------------------------------------------------------------------------
# Config parsing (HTTP/2 enablement)
# ---------------------------------------------------------------------------

def _strip_comments(text):
    """Remove nginx `#` comments (a # starts a comment to end of line)."""
    out = []
    for line in (text or "").splitlines():
        out.append(line.split("#", 1)[0])
    return "\n".join(out)


_LISTEN_HTTP2_RE = re.compile(r"\blisten\b[^;]*\bhttp2\b", re.IGNORECASE)
_HTTP2_ON_RE = re.compile(r"\bhttp2\s+on\s*;", re.IGNORECASE)
_HTTP2_OFF_RE = re.compile(r"\bhttp2\s+off\s*;", re.IGNORECASE)


def parse_config_text(text):
    """Scan nginx config text for HTTP/2 enablement.

    Returns (state, findings) where state is True (enabled), False
    (disabled) or None (no HTTP/2 directive found / conflicting), and
    findings is a list of human-readable lines."""
    clean = _strip_comments(text)
    listen_hits = _LISTEN_HTTP2_RE.findall(clean)
    on_hits = _HTTP2_ON_RE.findall(clean)
    off_hits = _HTTP2_OFF_RE.findall(clean)
    findings = []
    if listen_hits:
        findings.append("%d listen directive(s) with the http2 parameter"
                        % len(listen_hits))
    if on_hits:
        findings.append("%d `http2 on;` directive(s)" % len(on_hits))
    if off_hits:
        findings.append("%d `http2 off;` directive(s)" % len(off_hits))
    enabled = bool(listen_hits or on_hits)
    disabled = bool(off_hits)
    if enabled and disabled:
        # Both on and off in the same scan — scope-dependent, and this
        # tool does not guess which server block wins.
        return None, findings + [
            "both enabling and disabling directives found — HTTP/2 state "
            "depends on which server block applies; check by hand"]
    if enabled:
        return True, findings
    if disabled:
        return False, findings
    return None, ["no HTTP/2 directive found in the scanned config"]


def collect_config_files(path):
    """Return a sorted list of config files to scan for `path` (a file,
    or a directory walked for *.conf plus nginx.conf)."""
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        found = []
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in sorted(filenames):
                if name.endswith(".conf") or name == "nginx.conf":
                    found.append(os.path.join(dirpath, name))
        return sorted(found)
    return None


def scan_config(path):
    """Scan a config file or directory. Returns (state, findings, files)
    or raises OSError. state: True/False/None as in parse_config_text."""
    files = collect_config_files(path)
    if files is None:
        raise OSError("no such file or directory: %s" % path)
    if not files:
        return None, ["no *.conf / nginx.conf files found under %s" % path], []
    all_findings = []
    states = []
    for fname in files:
        with open(fname, "r", encoding="utf-8", errors="replace") as handle:
            state, findings = parse_config_text(handle.read())
        states.append(state)
        for finding in findings:
            all_findings.append("%s: %s" % (os.path.basename(fname), finding))
    if any(s is True for s in states) and any(s is False for s in states):
        return None, all_findings + [
            "mixed HTTP/2 state across files — check which server block "
            "applies"], files
    if any(s is True for s in states):
        return True, all_findings, files
    if any(s is False for s in states):
        return False, all_findings, files
    return None, all_findings, files


# ---------------------------------------------------------------------------
# nginx -v
# ---------------------------------------------------------------------------

def run_nginx_version(nginx_path):
    """Run `<nginx_path> -v`; nginx prints its version to stderr."""
    proc = subprocess.run([nginx_path, "-v"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=30)
    return proc.returncode, proc.stderr or proc.stdout


def find_nginx(explicit_path):
    """Resolve the nginx binary to run. Returns (path, error_message)."""
    if explicit_path:
        if not os.path.isfile(explicit_path):
            return None, "no such file: %s" % explicit_path
        if not os.access(explicit_path, os.X_OK):
            return None, "not executable: %s" % explicit_path
        return explicit_path, None
    found = shutil.which("nginx")
    if found:
        return found, None
    return None, ("no `nginx` on PATH (pass --version VERSION or "
                  "--nginx-path PATH to point at one)")


# ---------------------------------------------------------------------------
# Verdict assembly
# ---------------------------------------------------------------------------

def assess(parsed, version_note, http2_state, config_findings):
    """Combine version classification and the HTTP/2 gate into a verdict.

    http2_state: True / False / None.
    Returns (verdict, detail_lines, exit_code)."""
    status, reasons = classify_version(parsed)
    version_line = ('nginx: %s (%s)'
                    % (parsed["display"] or parsed["raw"] or "unknown",
                       version_note))
    if http2_state is True:
        http2_line = "HTTP/2: ENABLED in the scanned config"
    elif http2_state is False:
        http2_line = "HTTP/2: OFF in the scanned config"
    else:
        http2_line = "HTTP/2: state not determined from the scanned config"
    lines = [version_line, http2_line]
    lines.extend("  " + r for r in reasons)
    for finding in config_findings:
        lines.append("  config: " + finding)

    if status == "patched":
        return "PATCHED", lines + [
            "  Fixed build — both HTTP/2 CVEs are closed in this release.",
            "  Restart nginx so the fixed binary is the one running "
            "(a reload is not enough if the old binary is still loaded)."], 0
    if status == "not_affected":
        return "NOT_AFFECTED", lines + [
            "  This nginx line predates both HTTP/2 flaws."], 0
    if status == "unknown":
        return "UNKNOWN", lines + [
            "  Version status could not be decided — do not assume safe.",
            "  Upgrade to %s, or check your distro's security tracker."
            % FIXED_RELEASES], 3
    # status == "affected": the HTTP/2 gate decides.
    if http2_state is True:
        return "VULNERABLE", lines + [
            "  HTTP/2 is on and the version is affected — pre-auth RCE "
            "in the HTTP/2 handler is reachable.",
            "  Fix: upgrade to %s." % FIXED_RELEASES,
            "  Mitigation until patched: `http2 off;` (nginx 1.25.1+) and "
            "remove `http2` from every listen directive, then test and "
            "reload — and confirm old workers have exited."], 1
    if http2_state is False:
        return "NOT_AFFECTED", lines + [
            "  HTTP/2 is off, so neither HTTP/2 flaw is reachable on this "
            "config.",
            "  Still upgrade when you can: the 2026-11-18 release fixed "
            "other flaws that do not need HTTP/2."], 0
    return "UNKNOWN", lines + [
        "  Version is in the affected range, but whether HTTP/2 is enabled "
        "could not be determined from the config scanned.",
        "  Run with --config pointing at your nginx.conf (or its conf.d "
        "directory) — or disable HTTP/2 and upgrade to %s."
        % FIXED_RELEASES], 3


# ---------------------------------------------------------------------------
# Demo fixtures (labelled, deterministic — no host data, no timestamps)
# ---------------------------------------------------------------------------

DEMO_CASES = [
    {
        "label": "vulnerable fixture — nginx 1.31.8 with HTTP/2 on",
        "version_text": "nginx version: nginx/1.31.8",
        "config_text": (
            "events { worker_connections 1024; }\n"
            "http {\n"
            "    server {\n"
            "        listen 443 ssl http2;\n"
            "        server_name example.com;\n"
            "        location / { proxy_pass http://127.0.0.1:8080; }\n"
            "    }\n"
            "}\n"
        ),
    },
    {
        "label": "patched fixture — nginx 1.30.7 with HTTP/2 on",
        "version_text": "nginx version: nginx/1.30.7",
        "config_text": (
            "events { worker_connections 1024; }\n"
            "http {\n"
            "    server {\n"
            "        listen 443 ssl http2;\n"
            "        server_name example.com;\n"
            "        root /var/www/html;\n"
            "    }\n"
            "}\n"
        ),
    },
]


def run_demo(as_json):
    """Run the labelled fixtures. Returns (text, exit_code)."""
    cases = []
    for case in DEMO_CASES:
        parsed = parse_nginx_version(case["version_text"])
        http2_state, findings = parse_config_text(case["config_text"])
        verdict, lines, _code = assess(parsed, "fixture", http2_state,
                                       findings)
        cases.append({
            "label": case["label"],
            "version": parsed["display"],
            "http2": http2_state,
            "verdict": verdict,
            "detail": lines,
        })
    if as_json:
        return json.dumps({"demo": True, "cases": cases}, indent=2) + "\n", \
            1 if any(c["verdict"] == "VULNERABLE" for c in cases) else 0
    out = []
    for index, case in enumerate(cases, start=1):
        out.append("[demo %d/%d] %s" % (index, len(cases), case["label"]))
        out.append(case["detail"][0])
        out.append(case["detail"][1])
        out.append("Verdict: %s" % case["verdict"])
        for line in case["detail"][2:]:
            out.append("  " + line if not line.startswith("  ") else line)
        out.append("")
    out.append("Demo uses labelled fixtures only — not this machine.")
    out.append("Run without --demo to check this machine.")
    return "\n".join(out) + "\n", \
        1 if any(c["verdict"] == "VULNERABLE" for c in cases) else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="nginx_http2_check.py",
        description="Check whether this host is exposed to the nginx "
                    "HTTP/2 RCE pair (CVE-2026-123007, CVE-2026-123633). "
                    "Defensive checker only: stdlib, no network, no "
                    "payloads.")
    parser.add_argument("--version", metavar="VERSION",
                        help='nginx version string, e.g. "1.31.8" or the '
                             'full `nginx -v` output '
                             '"nginx version: nginx/1.31.8"')
    parser.add_argument("--nginx-path", metavar="PATH",
                        help="path to an nginx binary to run -v against "
                             "(default: `nginx` on PATH)")
    parser.add_argument("--config", metavar="PATH",
                        help="nginx config file or directory to scan for "
                             "HTTP/2 enablement (default: tries "
                             "/etc/nginx/nginx.conf, then "
                             "/usr/local/nginx/conf/nginx.conf)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of text")
    parser.add_argument("--demo", action="store_true",
                        help="run the labelled fixtures (one vulnerable, "
                             "one patched); deterministic, no host data")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.demo:
        text, code = run_demo(args.json)
        sys.stdout.write(text)
        return code

    # --- version gate ---
    if args.version:
        parsed = parse_nginx_version(args.version)
        version_note = "--version argument"
    else:
        nginx_path, error = find_nginx(args.nginx_path)
        if nginx_path is None:
            if args.nginx_path:
                print("error: %s" % error, file=sys.stderr)
                return 2
            parsed = parse_nginx_version("")
            version_note = error
            verdict, lines, code = assess(parsed, version_note, None, [])
            if args.json:
                sys.stdout.write(json.dumps(
                    {"cves": [CVE_123007, CVE_123633], "verdict": verdict,
                     "version": None, "http2": None, "detail": lines},
                    indent=2) + "\n")
                return code
            for line in lines:
                print(line)
            print("Verdict: %s" % verdict)
            return code
        try:
            _rc, version_text = run_nginx_version(nginx_path)
        except (OSError, subprocess.SubprocessError) as exc:
            print("error: cannot run %s -v: %s" % (nginx_path, exc),
                  file=sys.stderr)
            return 2
        parsed = parse_nginx_version(version_text)
        version_note = "%s -v" % nginx_path

    # --- HTTP/2 gate ---
    config_path = args.config
    if config_path is None:
        for candidate in DEFAULT_CONFIG_PATHS:
            if os.path.isfile(candidate):
                config_path = candidate
                break
    http2_state, config_findings, _files = None, [], []
    if config_path is not None:
        try:
            http2_state, config_findings, _files = scan_config(config_path)
        except OSError as exc:
            print("error: cannot read --config %s: %s" % (config_path, exc),
                  file=sys.stderr)
            return 2
    else:
        config_findings = ["no config file found at the default paths — "
                           "pass --config to scan your nginx.conf"]

    verdict, lines, code = assess(parsed, version_note, http2_state,
                                  config_findings)

    if args.json:
        result = {
            "cves": [CVE_123007, CVE_123633],
            "verdict": verdict,
            "version": {
                "display": parsed["display"],
                "raw": parsed["raw"],
                "kind": parsed["kind"],
                "distro": parsed["distro"],
                "source": version_note,
            },
            "http2": {
                "enabled": http2_state,
                "config": config_path,
                "findings": config_findings,
            },
            "detail": lines,
        }
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return code

    for line in lines:
        print(line)
    print("Verdict: %s" % verdict)
    return code


if __name__ == "__main__":
    sys.exit(main())
