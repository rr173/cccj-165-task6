"""Offline privacy-budget verifier.

This module deliberately has no database dependency: it never imports a
database driver and can run on a disconnected host with only a signed export
directory. It verifies package hashes and the Ed25519 manifest signature,
recomputes each daily balance, and decides whether a numbered caller request
was within that tenant's budget.

The verifier accepts tenant identifiers, UTC time windows, deduction ordinals
and counts. It intentionally has no parameter for a prefix, suffix, full
fingerprint or raw secret, so its command line and export package cannot
disclose corpus query material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from . import ed25519

EXPORT_FORMAT = "pwncorpus-budget-export/1"
AUDIT_DATA_FORMAT = "pwncorpus-budget-audit-data/1"
CAPACITY_DATA_FORMAT = "pwncorpus-budget-capacity-data/1"

MANIFEST_FIELDS = (
    "format", "budget_id", "genesis_pub", "created_at", "window_start",
    "window_end", "initial_daily_quota", "policy_revision", "head_seq",
    "head_hash", "audit_sha256", "capacity_sha256", "tenant_count",
    "deducted_count", "denied_count",
)
AUDIT_FAILURE_REASONS = ("frozen", "budget_exhausted")


class BudgetVerifyError(Exception):
    """Malformed, tampered, untrusted or incomplete offline export."""


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise BudgetVerifyError(f"missing export file: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BudgetVerifyError(f"unreadable JSON export file: {path}: {exc}") from exc


def manifest_self_hash(manifest: dict) -> str:
    return hashlib.sha256(
        canonical({f: manifest[f] for f in MANIFEST_FIELDS}).encode("utf-8")
    ).hexdigest()


def parse_window(value: str) -> str:
    if not isinstance(value, str):
        raise BudgetVerifyError("time window must be a string")
    text = value.strip()
    try:
        if len(text) == 10:
            parsed = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise BudgetVerifyError("invalid UTC time window") from exc
    return parsed.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def _is_nonneg_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_pos_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def load_export(export_dir: str) -> dict:
    if not os.path.isdir(export_dir):
        raise BudgetVerifyError(f"export directory not found: {export_dir}")
    manifest = _read_json(os.path.join(export_dir, "manifest.json"))
    audit = _read_json(os.path.join(export_dir, "audit_data.json"))
    capacity = _read_json(os.path.join(export_dir, "capacity_data.json"))
    return {"manifest": manifest, "audit": audit, "capacity": capacity}


def verify_package(package: dict, *, trusted_genesis_pub: str | None = None,
                   now: str | datetime | None = None) -> dict:
    """Validate signatures/hashes and independently rebuild all balances."""
    manifest, audit, capacity = package["manifest"], package["audit"], package["capacity"]
    if not isinstance(manifest, dict) or not isinstance(audit, dict) \
            or not isinstance(capacity, dict):
        raise BudgetVerifyError("export sections must be JSON objects")
    missing = [f for f in MANIFEST_FIELDS + ("manifest_sha256", "signature")
               if f not in manifest]
    if missing:
        raise BudgetVerifyError("manifest missing fields: " + ", ".join(missing))
    if manifest["format"] != EXPORT_FORMAT:
        raise BudgetVerifyError("unsupported export format")
    if audit.get("format") != AUDIT_DATA_FORMAT:
        raise BudgetVerifyError("unsupported audit data format")
    if capacity.get("format") != CAPACITY_DATA_FORMAT:
        raise BudgetVerifyError("unsupported capacity data format")
    if not all(isinstance(manifest.get(k), str) for k in
               ("budget_id", "genesis_pub", "created_at", "window_start",
                "window_end", "head_hash", "audit_sha256",
                "capacity_sha256", "manifest_sha256", "signature")):
        raise BudgetVerifyError("manifest has a malformed string field")
    if len(manifest["genesis_pub"]) != 64 or len(manifest["signature"]) != 128:
        raise BudgetVerifyError("manifest has invalid key/signature length")
    for name in ("genesis_pub", "audit_sha256", "capacity_sha256",
                 "manifest_sha256", "head_hash", "signature", "budget_id"):
        try:
            bytes.fromhex(manifest[name])
        except ValueError as exc:
            raise BudgetVerifyError(f"manifest field {name} is not hexadecimal") from exc
    if trusted_genesis_pub is not None and \
            manifest["genesis_pub"] != trusted_genesis_pub:
        raise BudgetVerifyError("export genesis public key is not pinned/trustworthy")
    try:
        ed25519.verify(bytes.fromhex(manifest["genesis_pub"]),
                       bytes.fromhex(manifest["manifest_sha256"]),
                       bytes.fromhex(manifest["signature"]))
    except ed25519.BadSignature as exc:
        raise BudgetVerifyError("invalid budget genesis signature") from exc
    if manifest_self_hash(manifest) != manifest["manifest_sha256"]:
        raise BudgetVerifyError("manifest digest does not match its contents")

    # Hash the canonical sections rather than the file formatting. The signed
    # digest was computed over exact file bytes, so callers load those bytes.
    # This function receives parsed objects; file hash validation is added by
    # verify_export() where paths are available.
    window = parse_window(manifest["window_start"])
    if manifest["window_start"] != window:
        raise BudgetVerifyError("manifest window is not a UTC calendar day")
    if audit.get("window_start") != window or capacity.get("window_start") != window:
        raise BudgetVerifyError("section windows do not match manifest")
    expected_end = _next_window(window)
    if manifest.get("window_end") != expected_end or \
            audit.get("window_end") != expected_end or \
            capacity.get("window_end") != expected_end:
        raise BudgetVerifyError("export window end is inconsistent")
    if not _is_nonneg_int(manifest["head_seq"]) or \
            not _is_nonneg_int(manifest["policy_revision"]) or \
            not _is_nonneg_int(manifest["initial_daily_quota"]) or \
            not _is_nonneg_int(manifest["tenant_count"]) or \
            not _is_nonneg_int(manifest["deducted_count"]) or \
            not _is_nonneg_int(manifest["denied_count"]):
        raise BudgetVerifyError("manifest has a malformed numeric field")
    if capacity.get("initial_daily_quota") != manifest["initial_daily_quota"]:
        raise BudgetVerifyError("initial quota differs between signed sections")

    audit_rows = audit.get("rows")
    cap_rows = capacity.get("rows")
    if not isinstance(audit_rows, list) or not isinstance(cap_rows, list):
        raise BudgetVerifyError("export rows must be lists")
    if len(audit_rows) != len(cap_rows) or \
            len(audit_rows) != manifest["tenant_count"]:
        raise BudgetVerifyError("tenant count does not match signed sections")

    by_tenant = {}
    audit_tenant_ids, cap_tenant_ids = [], []
    total_deducted = 0
    total_denied = 0
    for row in audit_rows:
        self_check_audit_row(row, window)
        tenant = row["tenant_id"]
        if tenant in audit_tenant_ids:
            raise BudgetVerifyError("duplicate audit tenant row")
        audit_tenant_ids.append(tenant)
        total_deducted += row["deducted_count"]
        total_denied += sum(f["count"] for f in row["failure_reasons"])
        by_tenant[tenant] = {
            "tenant_id": tenant, "window_start": window,
            "deducted_count": row["deducted_count"],
            "failure_reasons": {f["reason"]: f["count"]
                                for f in row["failure_reasons"]},
        }
    for row in cap_rows:
        self_check_capacity_row(row, window)
        tenant = row["tenant_id"]
        if tenant in cap_tenant_ids:
            raise BudgetVerifyError("duplicate capacity tenant row")
        cap_tenant_ids.append(tenant)
        if tenant not in by_tenant:
            raise BudgetVerifyError("capacity row has no matching audit row")
        granted = row["capacity"] - manifest["initial_daily_quota"]
        if granted != row["granted_count"]:
            raise BudgetVerifyError(
                "capacity does not replay from initial quota plus grants")
        if granted < 0:
            raise BudgetVerifyError("capacity below the signed initial quota")
        spent = by_tenant[tenant]["deducted_count"]
        if spent > row["capacity"]:
            raise BudgetVerifyError("deductions exceed signed daily capacity")
        by_tenant[tenant].update({
            "capacity": row["capacity"],
            "granted_count": row["granted_count"],
            "remaining": row["capacity"] - spent,
            "frozen": bool(row["frozen"]),
            "policy_revision": row["policy_revision"],
        })
    if audit_tenant_ids != cap_tenant_ids:
        raise BudgetVerifyError("audit and capacity tenant rows differ")
    if total_deducted != manifest["deducted_count"]:
        raise BudgetVerifyError("manifest deducted_count does not match row sum")
    if total_denied != manifest["denied_count"]:
        raise BudgetVerifyError("manifest denied_count does not match row sum")
    revisions = [r["policy_revision"] for r in cap_rows]
    if revisions and max(revisions) > manifest["policy_revision"]:
        raise BudgetVerifyError("row policy revision is newer than export policy")

    created = parse_timestamp(manifest["created_at"])
    if now is not None:
        if isinstance(now, str):
            now = parse_timestamp(now)
        if now.astimezone(timezone.utc) < created:
            raise BudgetVerifyError("export was created after the supplied current time")
    return {"manifest": manifest, "rows": [by_tenant[t]
                                           for t in sorted(by_tenant)]}


def self_check_audit_row(row, window: str) -> None:
    if not isinstance(row, dict):
        raise BudgetVerifyError("audit row is not an object")
    if set(row) != {"tenant_id", "window_start", "deducted_count",
                    "failure_reasons"}:
        raise BudgetVerifyError("audit row has forbidden or missing fields")
    _check_tenant(row.get("tenant_id"))
    if row["window_start"] != window:
        raise BudgetVerifyError("audit row window does not match export")
    if not _is_nonneg_int(row.get("deducted_count")):
        raise BudgetVerifyError("deducted_count must be a non-negative integer")
    failures = row.get("failure_reasons")
    if not isinstance(failures, list):
        raise BudgetVerifyError("failure_reasons must be a list")
    seen = set()
    for failure in failures:
        if not isinstance(failure, dict) or \
                set(failure) != {"reason", "count"}:
            raise BudgetVerifyError("malformed failure reason entry")
        if failure["reason"] not in AUDIT_FAILURE_REASONS:
            raise BudgetVerifyError("export contains an unauthorized failure reason")
        if failure["reason"] in seen or not _is_pos_int(failure.get("count")):
            raise BudgetVerifyError("duplicate or invalid failure reason count")
        seen.add(failure["reason"])


def self_check_capacity_row(row, window: str) -> None:
    if not isinstance(row, dict):
        raise BudgetVerifyError("capacity row is not an object")
    if set(row) != {"tenant_id", "window_start", "capacity", "granted_count",
                    "frozen", "policy_revision"}:
        raise BudgetVerifyError("capacity row has forbidden or missing fields")
    _check_tenant(row.get("tenant_id"))
    if row["window_start"] != window:
        raise BudgetVerifyError("capacity row window does not match export")
    if not _is_nonneg_int(row.get("capacity")) or \
            not _is_nonneg_int(row.get("granted_count")) or \
            not isinstance(row.get("frozen"), bool) or \
            not _is_pos_int(row.get("policy_revision")):
        raise BudgetVerifyError("capacity row has a malformed field")


def _check_tenant(value) -> None:
    if not isinstance(value, str) or not value or len(value) > 128 or \
            any(c not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"
                for c in value):
        raise BudgetVerifyError("invalid tenant_id in export")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise BudgetVerifyError("invalid ISO timestamp in export") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _next_window(window: str) -> str:
    from datetime import timedelta
    return (datetime.fromisoformat(window) + timedelta(days=1)).isoformat()


def verify_export(export_dir: str, *,
                  trusted_genesis_pub: str | None = None,
                  now: str | datetime | None = None) -> dict:
    package = load_export(export_dir)
    expected = {
        "audit_data.json": package["manifest"]["audit_sha256"],
        "capacity_data.json": package["manifest"]["capacity_sha256"],
    }
    for name, digest in expected.items():
        path = os.path.join(export_dir, name)
        with open(path, "rb") as fh:
            if hash_bytes(fh.read()) != digest:
                raise BudgetVerifyError(f"{name} digest does not match manifest")
    # No unlisted files are trusted; a manifest cannot accidentally absorb one.
    allowed = {"audit_data.json", "capacity_data.json", "manifest.json"}
    actual = set(os.listdir(export_dir))
    if actual != allowed:
        raise BudgetVerifyError("export directory contains missing or extra files")
    return verify_package(package,
                          trusted_genesis_pub=trusted_genesis_pub, now=now)


def find_row(verified: dict, tenant_id: str, window: str | None = None) -> dict:
    window = parse_window(window or verified["manifest"]["window_start"])
    if window != verified["manifest"]["window_start"]:
        raise BudgetVerifyError("export does not cover the requested window")
    for row in verified["rows"]:
        if row["tenant_id"] == tenant_id:
            return row
    raise BudgetVerifyError("tenant has no signed row in this export window")


def check_request(verified: dict, tenant_id: str, ordinal: int, *,
                  window: str | None = None) -> dict:
    """Decide whether request ordinal 1..N was within the signed daily budget.

    A denial can have an ordinal capacity+1 (the first request that crossed
    the limit), but ordinals beyond that cannot be uniquely reconstructed from
    an aggregate export and are rejected as unverifiable rather than guessed.
    """
    if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
        raise BudgetVerifyError("request ordinal must be a positive integer")
    row = find_row(verified, tenant_id, window)
    capacity = row["capacity"]
    within = ordinal <= capacity
    if ordinal > capacity + 1:
        verdict = "unverifiable_ordinal"
    elif within:
        verdict = "within_budget"
    else:
        verdict = "over_budget"
    return {
        "verdict": verdict,
        "tenant_id": row["tenant_id"],
        "window_start": row["window_start"],
        "request_ordinal": ordinal,
        "daily_capacity": capacity,
        "deducted_count": row["deducted_count"],
        "remaining_balance": row["remaining"],
        "frozen": row["frozen"],
        "policy_revision": row["policy_revision"],
        "failure_reasons": row["failure_reasons"],
    }


def can_spend(verified: dict, tenant_id: str, count: int = 1, *,
              window: str | None = None) -> dict:
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise BudgetVerifyError("spend count must be a positive integer")
    row = find_row(verified, tenant_id, window)
    verdict = "within_budget" if count <= row["remaining"] else "over_budget"
    return {
        "verdict": verdict,
        "tenant_id": row["tenant_id"],
        "window_start": row["window_start"],
        "requested_count": count,
        "remaining_balance": row["remaining"],
        "daily_capacity": row["capacity"],
        "frozen": row["frozen"],
        "policy_revision": row["policy_revision"],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-budget-verify",
        description="offline privacy budget export verifier (no database)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify", help="verify export and print all balances")
    p.add_argument("export_dir")
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--now", default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("check", help="check whether a request was within budget")
    p.add_argument("export_dir")
    p.add_argument("--tenant", required=True)
    p.add_argument("--ordinal", type=int, required=True,
                   help="1-based request ordinal within the UTC day")
    p.add_argument("--window", default=None)
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--now", default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("can-spend", help="check remaining balance against N reads")
    p.add_argument("export_dir")
    p.add_argument("--tenant", required=True)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--window", default=None)
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--now", default=None)
    p.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    try:
        verified = verify_export(
            args.export_dir, trusted_genesis_pub=args.genesis_pub,
            now=args.now)
        if args.cmd == "verify":
            if args.json:
                print(json.dumps(verified, indent=2, sort_keys=True))
            else:
                m = verified["manifest"]
                print(f"OK: signed budget export {m['budget_id']},"
                      f" window {m['window_start']}, policy_revision"
                      f" {m['policy_revision']}")
                for row in verified["rows"]:
                    print(f"  {row['tenant_id']}: remaining={row['remaining']}"
                          f" deducted={row['deducted_count']}"
                          f" capacity={row['capacity']}"
                          f" frozen={str(row['frozen']).lower()}"
                          f" policy_revision={row['policy_revision']}")
            return 0
        if args.cmd == "check":
            verdict = check_request(
                verified, args.tenant, args.ordinal, window=args.window)
        else:
            verdict = can_spend(
                verified, args.tenant, args.count, window=args.window)
        if args.json:
            print(json.dumps(verdict, indent=2, sort_keys=True))
        else:
            print(json.dumps(verdict, sort_keys=True))
        return 0 if verdict["verdict"] == "within_budget" else 3
    except BudgetVerifyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
