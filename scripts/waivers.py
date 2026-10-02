#!/usr/bin/env python3
"""Waiver validation and merge gate for the security scanners (threat-model.md T1, T2, T4).

  waivers.py validate                  check waivers/waivers.yaml: schema, scope, expiry
  waivers.py gate --reports reports    apply the blocking thresholds and waivers to scanner reports

Exit codes: 0 pass, 1 blocking findings, 2 invalid waiver file.
"""
import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

import yaml

MAX_WAIVER_DAYS = 30
MAX_BREAK_GLASS_HOURS = 24
EXPIRY_WARNING_DAYS = 7

SCANNERS = ("gitleaks", "semgrep", "trivy-vuln", "trivy-config")
WAIVER_REQUIRED = {"id", "scanner", "rule", "path", "reason", "reference",
                   "requested_by", "approved_by", "created_at", "expires_at"}
WAIVER_OPTIONAL = {"resource"}
BREAK_GLASS_REQUIRED = {"id", "incident", "reason", "invoked_by", "approved_by",
                        "invoked_at", "expires_at"}

HANDLE = re.compile(r"^@[A-Za-z0-9][A-Za-z0-9-]*$")
TICKET = re.compile(r"^([A-Z][A-Z0-9]+-\d+|https://\S+)$")
WILDCARD = re.compile(r"[*?\[\]{}]")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


# ---------------------------------------------------------------- validation

def _keys(entry, required, optional=frozenset()):
    if not isinstance(entry, dict):
        return ["entry must be a mapping"]
    errs = [f"missing field '{k}'" for k in sorted(required - entry.keys())]
    errs += [f"unknown field '{k}'" for k in sorted(entry.keys() - required - optional)]
    return errs


def _strings(entry, keys):
    return [f"'{k}' must be a non-empty string" for k in keys
            if not isinstance(entry[k], str) or not entry[k].strip()]


def _people(entry, requester_key):
    errs = [f"'{k}' must be a GitHub handle such as @alice" for k in (requester_key, "approved_by")
            if not HANDLE.match(entry[k])]
    if entry[requester_key].lower() == entry["approved_by"].lower():
        errs.append(f"'approved_by' must be a different person from '{requester_key}'")
    return errs


def _too_broad(field, value):
    if WILDCARD.search(value) or value.lower() in ("all", "any", "none", ".", "/"):
        return [f"'{field}' is too broad: wildcards and catch-all values are not allowed"]
    return []


def validate_waiver(w, today):
    errs = _keys(w, WAIVER_REQUIRED, WAIVER_OPTIONAL)
    if errs:
        return errs
    text = WAIVER_REQUIRED - {"created_at", "expires_at"} | (WAIVER_OPTIONAL & w.keys())
    errs = _strings(w, sorted(text))
    if errs:
        return errs

    if not re.match(r"^W-\d{4}-\d{3}$", w["id"]):
        errs.append("'id' must look like W-2026-001")
    if w["scanner"] not in SCANNERS:
        errs.append(f"'scanner' must be one of {', '.join(SCANNERS)}")
    if len(w["reason"].strip()) < 20:
        errs.append("'reason' must explain the exception (at least 20 characters)")
    if not TICKET.match(w["reference"]):
        errs.append("'reference' must be a ticket key such as SEC-123 or an https URL")
    errs += _people(w, "requested_by")

    # Scope: a waiver names one rule on one file (and one resource where the scanner has one).
    errs += _too_broad("rule", w["rule"])
    if re.search(r"\s", w["rule"]):
        errs.append("'rule' must be a single rule or CVE identifier")
    path = w["path"]
    errs += _too_broad("path", path)
    if path.startswith("/") or ".." in path.split("/") or path.endswith("/") or os.path.isdir(path):
        errs.append("'path' must be one file, relative to the repository root, not a directory")
    resource = w.get("resource")
    if resource is not None:
        errs += _too_broad("resource", resource)
    if w["scanner"] == "trivy-vuln" and resource is None:
        errs.append("'resource' is required for trivy-vuln: the package name")
    if w["scanner"] == "gitleaks" and not COMMIT_SHA.match(resource or ""):
        errs.append("'resource' is required for gitleaks: the full 40-character commit SHA")
    if w["scanner"] == "semgrep" and resource is not None:
        errs.append("'resource' is not used for semgrep; a waiver covers one rule in one file")

    created, expires = w["created_at"], w["expires_at"]
    if type(created) is not date or type(expires) is not date:
        return errs + ["'created_at' and 'expires_at' must be unquoted dates, YYYY-MM-DD"]
    if created > today:
        errs.append("'created_at' is in the future")
    if expires <= created:
        errs.append("'expires_at' must be after 'created_at'")
    elif (expires - created).days > MAX_WAIVER_DAYS:
        errs.append(f"waiver lasts longer than {MAX_WAIVER_DAYS} days; permanent suppressions are not allowed")
    if today >= expires:
        errs.append(f"EXPIRED on {expires}: fix the finding, or raise a new waiver with fresh approval")
    return errs


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def validate_break_glass(b, now):
    errs = _keys(b, BREAK_GLASS_REQUIRED)
    if errs:
        return errs
    errs = _strings(b, sorted(BREAK_GLASS_REQUIRED - {"invoked_at", "expires_at"}))
    if errs:
        return errs

    if not re.match(r"^BG-\d{4}-\d{3}$", b["id"]):
        errs.append("'id' must look like BG-2026-001")
    if not TICKET.match(b["incident"]):
        errs.append("'incident' must be an incident key such as INC-123 or an https URL")
    if len(b["reason"].strip()) < 20:
        errs.append("'reason' must describe the emergency (at least 20 characters)")
    errs += _people(b, "invoked_by")

    if not isinstance(b["invoked_at"], datetime) or not isinstance(b["expires_at"], datetime):
        return errs + ["'invoked_at' and 'expires_at' must be UTC timestamps, e.g. 2026-10-02T14:00:00Z"]
    invoked, expires = _utc(b["invoked_at"]), _utc(b["expires_at"])
    if invoked > now + timedelta(minutes=10):
        errs.append("'invoked_at' is in the future")
    if expires <= invoked:
        errs.append("'expires_at' must be after 'invoked_at'")
    elif expires - invoked > timedelta(hours=MAX_BREAK_GLASS_HOURS):
        errs.append(f"break-glass lasts longer than {MAX_BREAK_GLASS_HOURS} hours")
    if now >= expires:
        errs.append(f"EXPIRED at {expires:%Y-%m-%d %H:%M}Z: remove the entry and link the remediation")
    return errs


def target(w):
    """The exact finding a waiver applies to."""
    return (w["scanner"], w["rule"], w["path"], w.get("resource", ""))


def load(path, now):
    """Return (waivers, break_glass, errors). Any error makes the whole file invalid."""
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        return [], [], [f"{path}: cannot be read: {e}"]
    if not isinstance(doc, dict) or set(doc) != {"waivers", "break_glass"}:
        return [], [], [f"{path}: top level must have exactly the keys 'waivers' and 'break_glass'"]
    waivers, break_glass = doc["waivers"], doc["break_glass"]
    if not isinstance(waivers, list) or not isinstance(break_glass, list):
        return [], [], [f"{path}: 'waivers' and 'break_glass' must be lists (use [] when empty)"]

    errors, seen_ids, seen_targets = [], set(), set()

    def label(entry, i, kind):
        ident = entry.get("id") if isinstance(entry, dict) else None
        return ident if isinstance(ident, str) else f"{kind}[{i}]"

    for i, w in enumerate(waivers):
        name = label(w, i, "waivers")
        errs = validate_waiver(w, now.date())
        if not errs:
            if w["id"] in seen_ids:
                errs.append("duplicate id")
            if target(w) in seen_targets:
                errs.append("another waiver already covers this exact finding")
            seen_ids.add(w["id"])
            seen_targets.add(target(w))
        errors += [f"{name}: {e}" for e in errs]

    for i, b in enumerate(break_glass):
        errors += [f"{label(b, i, 'break_glass')}: {e}" for e in validate_break_glass(b, now)]
    if len(break_glass) > 1:
        errors.append("break_glass: only one entry may exist at a time")

    return waivers, break_glass, errors


# ------------------------------------------------- findings and thresholds
# Each parser yields only findings at or above the blocking threshold, as
# (rule, path, resource, detail).

def _gitleaks(data):
    # Any detected secret blocks. The report is produced with --redact.
    for f in data or []:
        yield f["RuleID"], f["File"], f["Commit"], f"line {f.get('StartLine', '?')}"


def _semgrep(data):
    # High-confidence findings of severity ERROR/HIGH/CRITICAL block.
    for r in data["results"]:
        extra = r.get("extra", {})
        severity = str(extra.get("severity", "")).upper()
        confidence = str(extra.get("metadata", {}).get("confidence", "")).upper()
        if severity in ("ERROR", "HIGH", "CRITICAL") and confidence == "HIGH":
            yield r["check_id"], r["path"], "", f"{severity}, line {r['start']['line']}"


def _trivy_vuln(data):
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            if v.get("Severity") in ("HIGH", "CRITICAL"):
                fixed = v.get("FixedVersion") or "no fix yet"
                yield (v["VulnerabilityID"], result["Target"], v["PkgName"],
                       f"{v['Severity']}, {v.get('InstalledVersion', '?')} -> {fixed}")


def _trivy_config(data):
    for result in data.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") == "FAIL" and m.get("Severity") in ("HIGH", "CRITICAL"):
                resource = (m.get("CauseMetadata") or {}).get("Resource") or ""
                yield m["ID"], result["Target"], resource, f"{m['Severity']}, {m.get('Title', '')}"


# (scanner, report file, required, parser). A missing required report blocks: fail closed.
REPORTS = (
    ("gitleaks", "gitleaks.json", True, _gitleaks),
    ("semgrep", "semgrep.json", True, _semgrep),
    ("trivy-vuln", "trivy-vuln.json", True, _trivy_vuln),
    ("trivy-config", "trivy-config.json", True, _trivy_config),
    ("trivy-vuln", "trivy-image.json", False, _trivy_vuln),  # only when a Dockerfile exists
)


def load_findings(reports_dir):
    """Return ({finding key: detail}, [(scanner, problem)])."""
    findings, problems = {}, []
    for scanner, filename, required, parser in REPORTS:
        try:
            with open(os.path.join(reports_dir, filename)) as f:
                parsed = list(parser(json.load(f)))
        except FileNotFoundError:
            if required:
                problems.append((scanner, f"{filename} not found: the scanner did not run"))
            continue
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            problems.append((scanner, f"{filename} could not be read: {e!r}"))
            continue
        for rule, path, resource, detail in parsed:
            findings.setdefault((scanner, rule, path, resource), detail)
    return findings, problems


def decide(waivers, break_glass, findings, problems):
    """Return (lines, blocked, bypassed, unused waivers)."""
    by_target = {target(w): w for w in waivers}
    bg = break_glass[0] if break_glass else None
    lines, blocked, bypassed, used = [], 0, 0, set()

    def unwaived(scanner):
        # Break-glass never bypasses the secret gate.
        nonlocal blocked, bypassed
        if bg and scanner != "gitleaks":
            bypassed += 1
            return f"BYPASS by {bg['id']} ({bg['incident']})"
        blocked += 1
        return "BLOCK"

    for key in sorted(findings):
        scanner, rule, path, resource = key
        waiver = by_target.get(key)
        if waiver:
            used.add(waiver["id"])
            status = f"WAIVED by {waiver['id']} until {waiver['expires_at']}"
        else:
            status = unwaived(scanner)
        lines.append(f"{status}: scanner={scanner} rule={rule} path={path} "
                     f"resource={resource or '-'} ({findings[key]})")
    # A scanner that failed, or a missing or unreadable report, always blocks. Break-glass
    # bypasses findings, never the absence of a scan.
    for scanner, problem in problems:
        blocked += 1
        lines.append(f"BLOCK: scanner={scanner} {problem}")

    unused = [w for w in waivers if w["id"] not in used]
    return lines, blocked, bypassed, unused


# ----------------------------------------------------------------------- CLI

def _annotate(level, message):
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level}::{message}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("validate", "gate"))
    parser.add_argument("--file", default="waivers/waivers.yaml")
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--now", help="override the current UTC time (ISO 8601), for tests")
    args = parser.parse_args(argv)
    now = _utc(datetime.fromisoformat(args.now)) if args.now else datetime.now(timezone.utc)

    waivers, break_glass, errors = load(args.file, now)
    if errors:
        print(f"Waiver file is invalid ({len(errors)} problem(s)):")
        for e in errors:
            print(f"  {e}")
            _annotate("error", e)
        return 2

    for w in waivers:
        days_left = (w["expires_at"] - now.date()).days
        if days_left <= EXPIRY_WARNING_DAYS:
            message = f"{w['id']} expires in {days_left} day(s), on {w['expires_at']}; CI will fail from that date"
            print(f"WARNING: {message}")
            _annotate("warning", message)
    for b in break_glass:
        message = (f"BREAK-GLASS ACTIVE: {b['id']} for {b['incident']}, invoked by {b['invoked_by']}, "
                   f"approved by {b['approved_by']}, expires {_utc(b['expires_at']):%Y-%m-%d %H:%M}Z")
        print(message)
        _annotate("warning", message)

    if args.command == "validate":
        print(f"Waiver file is valid: {len(waivers)} waiver(s), {len(break_glass)} break-glass entry(ies).")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                out.write(f"active={len(waivers) + len(break_glass)}\n")
        return 0

    findings, problems = load_findings(args.reports)
    lines, blocked, bypassed, unused = decide(waivers, break_glass, findings, problems)
    for line in lines:
        print(line)
        if line.startswith("BLOCK"):
            _annotate("error", line)
        elif line.startswith("BYPASS"):
            _annotate("warning", line)
    for w in unused:
        print(f"NOTE: {w['id']} matches no current finding; remove it")

    waived = len(lines) - blocked - bypassed
    result = "FAIL" if blocked else "PASS"
    summary = f"Security gate: {result}. {blocked} blocking, {waived} waived, {bypassed} bypassed by break-glass."
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as out:
            out.write(f"### {summary}\n\n" + "".join(f"- `{line}`\n" for line in lines))
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
