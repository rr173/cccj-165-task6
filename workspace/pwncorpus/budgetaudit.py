"""Independent, read-only privacy-budget auditor.

This process verifies the SQLite budget state and event chain, then writes a
signed directory that can be checked on a machine without the database. The
audit data identifies tenants and UTC windows only; it never contains query
prefixes, suffixes, full fingerprints, tokens or raw passwords.

The signed package has two separately hashed sections:

* ``audit_data.json`` contains exactly tenant id, UTC window, deduction count
  and machine-readable failure reasons;
* ``capacity_data.json`` contains the auditor-recomputed daily capacity,
  including immutable per-tenant top-up history needed to recompute balance
  after the service database is unavailable.

The manifest binds both hashes and is signed by the budget genesis key. A new
policy cannot change bytes in an already exported package.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

from . import budget, budgetverify, ed25519

AUDIT_FORMAT = budgetverify.EXPORT_FORMAT


class BudgetAuditError(Exception):
    pass


def _connect_read_only(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise BudgetAuditError(f"database not found: {db_path}")
    uri = "file:" + os.path.abspath(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _event_rows(conn, window: str) -> list[dict]:
    rows = conn.execute(
        "SELECT seq, tenant_id, window_start, kind, count, reason,"
        " created_at, policy_revision, prev_hash, event_hash"
        " FROM budget_events WHERE window_start=? ORDER BY seq", (window,)
    ).fetchall()
    return [dict(r) for r in rows]


def verify_stored_budget(conn) -> dict:
    """Replay the hash chain and independently derive every stored window."""
    if not budget.is_initialised(conn):
        raise BudgetAuditError("privacy budget is not initialised")
    info = budget._policy_locked(conn)
    budget_id = conn.execute(
        "SELECT value FROM meta WHERE key=?", (budget.META_BUDGET_ID,)
    ).fetchone()["value"]
    genesis_pub = conn.execute(
        "SELECT value FROM meta WHERE key=?", (budget.META_GENESIS_PUB,)
    ).fetchone()["value"]
    head = conn.execute(
        "SELECT head_seq, head_hash FROM budget_head WHERE id=1").fetchone()

    events = [dict(r) for r in conn.execute(
        "SELECT seq, tenant_id, window_start, kind, count, reason,"
        " created_at, policy_revision, prev_hash, event_hash"
        " FROM budget_events ORDER BY seq").fetchall()]

    prev = "BUDGET-GENESIS:" + budget_id
    revisions = []
    derived: dict[tuple[str, str], dict] = {}
    expected_seq = 1
    for event in events:
        if event["seq"] != expected_seq:
            raise BudgetAuditError("budget event seq is not gapless")
        if event["prev_hash"] != prev:
            raise BudgetAuditError("budget event prev_hash linkage broken")
        recomputed = budget._hash_event(event)
        if recomputed != event["event_hash"]:
            raise BudgetAuditError(
                f"budget event {event['seq']}: stored hash mismatch")
        budget.validate_tenant(event["tenant_id"])
        budget.normalize_window(event["window_start"])
        if event["kind"] not in budget.EVENT_KINDS:
            raise BudgetAuditError("unknown budget event kind")
        if event["kind"] == "deny" and event["reason"] not in budget.DENY_REASONS:
            raise BudgetAuditError("budget denial has an invalid reason")
        if event["kind"] != "deny" and event["reason"]:
            raise BudgetAuditError("non-denial budget event must have no reason")
        revisions.append(event["policy_revision"])
        if revisions:
            pass
        key = (event["tenant_id"], event["window_start"])
        rec = derived.setdefault(key, {"spent": 0, "granted": 0,
                                      "failure_reasons": {},
                                      "frozen_admin": None,
                                      "policy_revision": 1})
        if event["kind"] == "consume":
            if event["count"] != 1:
                raise BudgetAuditError("consumption event must decrement once")
            rec["spent"] += 1
        elif event["kind"] == "grant":
            if event["count"] <= 0:
                raise BudgetAuditError("grant event must add positive quota")
            rec["granted"] += event["count"]
        elif event["kind"] == "deny":
            rec["failure_reasons"][event["reason"]] = \
                rec["failure_reasons"].get(event["reason"], 0) + 1
        elif event["kind"] == "freeze":
            rec["frozen_admin"] = True
        elif event["kind"] == "unfreeze":
            rec["frozen_admin"] = False
        # Freeze is tenant state that rolls forward into later UTC windows.
        # It is replayed from the ordered event stream below rather than only
        # trusting the value copied into each daily row.
        rec["policy_revision"] = event["policy_revision"]
        prev = event["event_hash"]
        expected_seq += 1

    if head["head_seq"] != len(events) or head["head_hash"] != prev:
        raise BudgetAuditError("budget head does not match replayed event chain")
    # Events from different tenants interleave in global serialization order.
    # A consumption carries ITS tenant row's policy revision, so revisions need
    # not be monotonic across tenants; each value only has to identify a
    # revision that existed at or before the current global policy revision.
    if revisions and (min(revisions) < 1 or max(revisions) > info["policy_revision"]):
        raise BudgetAuditError("budget event references an unknown policy revision")

    # Replay tenant freeze state across UTC days. Events are globally
    # gapless, while per-tenant lists preserve that serialization order.
    freeze_events: dict[str, list[tuple[str, bool]]] = {}
    for event in events:
        if event["kind"] in ("freeze", "unfreeze"):
            freeze_events.setdefault(event["tenant_id"], []).append(
                (event["window_start"], event["kind"] == "freeze"))
    def carried_frozen(tenant: str, window: str) -> bool:
        frozen = False
        for event_window, is_frozen in freeze_events.get(tenant, []):
            if event_window > window:
                break
            frozen = is_frozen
        return frozen

    windows = [dict(r) for r in conn.execute(
        "SELECT tenant_id, window_start, remaining, spent, frozen,"
        " policy_revision FROM budget_windows"
        " ORDER BY tenant_id, window_start").fetchall()]
    for row in windows:
        rec = derived.get((row["tenant_id"], row["window_start"]))
        if rec is None:
            # A freshly opened window is valid; no events means initial quota.
            rec = {"spent": 0, "granted": 0, "failure_reasons": {},
                   "frozen_admin": None, "policy_revision": 1}
            derived[(row["tenant_id"], row["window_start"])] = rec
        if row["spent"] != rec["spent"]:
            raise BudgetAuditError(
                f"stored spend for tenant {row['tenant_id']} does not replay"
                " from signed events")
        expected_remaining = info["initial_daily_quota"] + rec["granted"] - rec["spent"]
        if row["remaining"] != expected_remaining or expected_remaining < 0:
            raise BudgetAuditError(
                f"stored remaining balance for tenant {row['tenant_id']}"
                " does not replay from quota, grants and deductions")
        if row["policy_revision"] < 1 or \
                row["policy_revision"] > info["policy_revision"]:
            raise BudgetAuditError("stored window policy revision is invalid")
        expected_frozen = carried_frozen(row["tenant_id"],
                                         row["window_start"])
        if rec["frozen_admin"] is not None:
            expected_frozen = rec["frozen_admin"]
        if bool(row["frozen"]) != expected_frozen:
            raise BudgetAuditError("stored freeze state does not replay from events")
        rec["remaining"] = expected_remaining
        rec["frozen"] = expected_frozen
        rec["row_policy_revision"] = row["policy_revision"]

    return {"budget_id": budget_id, "genesis_pub": genesis_pub,
            "initial_daily_quota": info["initial_daily_quota"],
            "policy_revision": info["policy_revision"],
            "head_seq": len(events), "head_hash": prev,
            "windows": windows, "derived": derived}


def build_export_data(conn, window: str, *, created_at: str | None = None):
    verified = verify_stored_budget(conn)
    window = budget.normalize_window(window)
    end = budget.next_window_start(window)
    window_rows = [r for r in verified["windows"]
                   if r["window_start"] == window]
    audit_rows = []
    capacity_rows = []
    events_by_key = {}
    for e in _event_rows(conn, window):
        events_by_key.setdefault((e["tenant_id"], e["window_start"]), []).append(e)

    for row in sorted(window_rows, key=lambda r: r["tenant_id"]):
        rec = verified["derived"][(row["tenant_id"], window)]
        failures = []
        for reason in budget.DENY_REASONS:
            count = rec["failure_reasons"].get(reason, 0)
            if count:
                failures.append({"reason": reason, "count": count})
        audit_rows.append({
            "tenant_id": row["tenant_id"],
            "window_start": window,
            "deducted_count": int(rec["spent"]),
            "failure_reasons": failures,
        })
        capacity_rows.append({
            "tenant_id": row["tenant_id"],
            "window_start": window,
            "capacity": int(rec["remaining"] + rec["spent"]),
            "granted_count": int(rec["granted"]),
            "frozen": bool(row["frozen"]),
            "policy_revision": int(row["policy_revision"]),
        })

    audit = {"format": budgetverify.AUDIT_DATA_FORMAT, "window_start": window,
             "window_end": end, "rows": audit_rows}
    capacity = {"format": budgetverify.CAPACITY_DATA_FORMAT,
                "window_start": window, "window_end": end,
                "initial_daily_quota": verified["initial_daily_quota"],
                "rows": capacity_rows}
    return audit, capacity, verified


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def export_budget(db_path: str, key_path: str, out_dir: str,
                  window: str | None = None, *,
                  created_at: str | None = None,
                  genesis_pub_pin: str | None = None) -> dict:
    window = budget.normalize_window(window)
    conn = _connect_read_only(db_path)
    try:
        audit_data, capacity_data, verified = build_export_data(conn, window)
    finally:
        conn.close()

    key = budget.read_genesis_key(key_path, verified["budget_id"])
    if key["_pub"].hex() != verified["genesis_pub"]:
        raise BudgetAuditError("genesis key does not match the database public key")
    if genesis_pub_pin is not None and key["_pub"].hex() != genesis_pub_pin:
        raise BudgetAuditError("pinned genesis public key does not match")

    created = created_at or budget.utcnow_ts()
    audit_bytes = _json_bytes(audit_data)
    capacity_bytes = _json_bytes(capacity_data)
    manifest = {
        "format": budgetverify.EXPORT_FORMAT,
        "budget_id": verified["budget_id"],
        "genesis_pub": verified["genesis_pub"],
        "created_at": created,
        "window_start": window,
        "window_end": budget.next_window_start(window),
        "initial_daily_quota": verified["initial_daily_quota"],
        "policy_revision": verified["policy_revision"],
        "head_seq": verified["head_seq"],
        "head_hash": verified["head_hash"],
        "audit_sha256": budgetverify.hash_bytes(audit_bytes),
        "capacity_sha256": budgetverify.hash_bytes(capacity_bytes),
        "tenant_count": len(audit_data["rows"]),
        "deducted_count": sum(r["deducted_count"] for r in audit_data["rows"]),
        "denied_count": sum(f["count"] for r in audit_data["rows"]
                            for f in r["failure_reasons"]),
    }
    manifest["manifest_sha256"] = budgetverify.manifest_self_hash(manifest)
    manifest["signature"] = ed25519.sign(
        key["_seed"], bytes.fromhex(manifest["manifest_sha256"])).hex()

    if os.path.exists(out_dir):
        if os.listdir(out_dir):
            raise BudgetAuditError(
                f"refusing to overwrite non-empty historical export: {out_dir}")
    parent = os.path.dirname(os.path.abspath(out_dir)) or "."
    tmp = tempfile.mkdtemp(prefix=".budget-export-", dir=parent)
    try:
        with open(os.path.join(tmp, "audit_data.json"), "wb") as fh:
            fh.write(audit_bytes)
        with open(os.path.join(tmp, "capacity_data.json"), "wb") as fh:
            fh.write(capacity_bytes)
        with open(os.path.join(tmp, "manifest.json"), "wb") as fh:
            fh.write(_json_bytes(manifest))
        os.chmod(tmp, 0o700)
        os.replace(tmp, out_dir)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return manifest


def verify(db_path: str) -> dict:
    conn = _connect_read_only(db_path)
    try:
        return verify_stored_budget(conn)
    finally:
        conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-budget-audit",
        description="read-only privacy budget auditor and signed exporter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify", help="verify stored budget state and event chain")
    p.add_argument("--db", required=True)
    p = sub.add_parser("export", help="write an offline-verifiable budget export")
    p.add_argument("--db", required=True)
    p.add_argument("--key", required=True, help="budget genesis private key")
    p.add_argument("--out", required=True)
    p.add_argument("--window", default=None,
                   help="UTC date YYYY-MM-DD (default: today's UTC day)")
    p.add_argument("--now", default=None)
    p.add_argument("--genesis-pub", default=None)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "verify":
            r = verify(args.db)
            print(f"OK: budget {r['budget_id']} verified to event"
                  f" {r['head_seq']}, policy_revision {r['policy_revision']}")
            return 0
        manifest = export_budget(
            args.db, args.key, args.out, args.window,
            created_at=args.now, genesis_pub_pin=args.genesis_pub)
        print(f"exported budget audit: {manifest['budget_id']} window"
              f" {manifest['window_start']} tenants={manifest['tenant_count']}"
              f" deducted={manifest['deducted_count']}"
              f" denied={manifest['denied_count']}")
        print(f"  {args.out}  manifest {manifest['manifest_sha256'][:16]}...")
        return 0
    except (BudgetAuditError, budget.BudgetError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
