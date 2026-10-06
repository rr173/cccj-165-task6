"""Per-caller daily privacy budgets for anonymous prefix queries.

The durable state for one tenant/day is deliberately limited to::

    tenant_id, window_start, remaining, spent, frozen, policy_revision

A successful prefix read and its quota decrement happen in one SQLite
``BEGIN IMMEDIATE`` transaction.  The append-only ``budget_events`` hash chain
gives the independent auditor a complete, tamper-evident record while storing
neither prefixes, suffixes, full fingerprints nor raw passwords.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from . import db, ed25519

DEFAULT_DAILY_QUOTA = 100
PREFIX_LEN = 5

META_BUDGET_ID = "budget_id"
META_GENESIS_PUB = "budget_genesis_pub"

REASON_FROZEN = "frozen"
REASON_EXHAUSTED = "budget_exhausted"
DENY_REASONS = (REASON_FROZEN, REASON_EXHAUSTED)
EVENT_KINDS = ("consume", "deny", "grant", "freeze", "unfreeze")

_TENANT_RE = re.compile(r"\A[A-Za-z0-9_.:-]{1,128}\Z")
_EVENT_FIELDS = ("seq", "tenant_id", "window_start", "kind", "count",
                "reason", "created_at", "policy_revision", "prev_hash")


class BudgetError(Exception):
    """Malformed administrative input. Messages never contain query data."""


class BudgetNotInitialised(BudgetError):
    pass


class BudgetAuth(BudgetError):
    pass


class BudgetDenied(BudgetError):
    def __init__(self, reason: str, *, status: int, state: dict):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.state = state


class StaleBudget(Exception):
    pass


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_ts() -> str:
    return utcnow().isoformat(timespec="seconds")


def window_start_for(when: datetime | None = None) -> str:
    """Return the UTC calendar-day boundary, never the host local date."""
    when = (when or utcnow()).astimezone(timezone.utc)
    return when.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def normalize_window(value: str | None) -> str:
    if value is None:
        return window_start_for()
    if not isinstance(value, str):
        raise BudgetError("window must be an ISO-8601 UTC timestamp or YYYY-MM-DD")
    text = value.strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            parsed = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise BudgetError("invalid UTC time window") from exc
    return parsed.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def next_window_start(window_start: str) -> str:
    parsed = datetime.fromisoformat(window_start)
    return (parsed + timedelta(days=1)).isoformat()


def validate_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not _TENANT_RE.fullmatch(tenant_id):
        raise BudgetError(
            "tenant_id must be 1-128 letters, digits or _ . : - characters")
    return tenant_id


def _hash_event(event: dict) -> str:
    return hashlib.sha256(
        canonical({f: event[f] for f in _EVENT_FIELDS}).encode("utf-8")
    ).hexdigest()


# --------------------------------------------------------------------------
# Initialisation and tenant tokens
# --------------------------------------------------------------------------

def is_initialised(conn) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='budget_policy'"
    ).fetchone()
    return row is not None and conn.execute(
        "SELECT 1 FROM meta WHERE key=?", (META_BUDGET_ID,)
    ).fetchone() is not None


def _require_init(conn) -> None:
    if not is_initialised(conn):
        raise BudgetNotInitialised("privacy budget is not initialised")


def write_genesis_key(path: str, seed: bytes, pub: bytes, budget_id: str) -> None:
    data = {"kind": "budget-genesis", "budget_id": budget_id,
            "seed_hex": seed.hex(), "pubkey_hex": pub.hex()}
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except BaseException:
        os.unlink(path)
        raise


def read_genesis_key(path: str, budget_id: str | None = None) -> dict:
    try:
        with open(path, "r", encoding="ascii") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise BudgetError(f"budget key file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BudgetError(f"unreadable budget key file: {exc}") from exc
    if data.get("kind") != "budget-genesis":
        raise BudgetError("supplied key is not a budget genesis key")
    try:
        seed = bytes.fromhex(data["seed_hex"])
        pub = bytes.fromhex(data["pubkey_hex"])
    except (KeyError, ValueError, TypeError) as exc:
        raise BudgetError("budget key contains invalid hexadecimal key material") from exc
    if ed25519.public_from_seed(seed) != pub:
        raise BudgetError("budget key seed does not match its public key")
    if budget_id is not None and data.get("budget_id") != budget_id:
        raise BudgetError("budget key belongs to a different budget")
    data["_seed"] = seed
    data["_pub"] = pub
    return data


def initialise(conn, daily_quota: int, key_path: str) -> dict:
    """Create budget tables, fixed daily quota policy, and genesis signing key."""
    if not isinstance(daily_quota, int) or isinstance(daily_quota, bool) \
            or daily_quota < 0:
        raise BudgetError("daily_quota must be a non-negative integer")
    conn.executescript(db.BUDGET_SCHEMA)
    if is_initialised(conn):
        raise BudgetError("privacy budget is already initialised")
    if os.path.exists(key_path):
        raise BudgetError(f"budget key file already exists: {key_path}")

    budget_id = os.urandom(8).hex()
    seed, pub = ed25519.generate_key()
    now = utcnow_ts()
    with db.write_tx(conn):
        conn.execute("INSERT INTO meta(key,value) VALUES (?,?)",
                     (META_BUDGET_ID, budget_id))
        conn.execute("INSERT INTO meta(key,value) VALUES (?,?)",
                     (META_GENESIS_PUB, pub.hex()))
        conn.execute(
            "INSERT INTO budget_policy(id, initial_daily_quota,"
            " policy_revision, created_at) VALUES (1,?,1,?)",
            (daily_quota, now))
        conn.execute(
            "INSERT INTO budget_head(id, head_seq, head_hash) VALUES (1,0,?)",
            ("BUDGET-GENESIS:" + budget_id,))
    write_genesis_key(key_path, seed, pub, budget_id)
    return {"budget_id": budget_id, "genesis_pub": pub.hex(),
            "daily_quota": daily_quota, "policy_revision": 1,
            "key_file": key_path}


def _policy_locked(conn) -> dict:
    row = conn.execute(
        "SELECT initial_daily_quota, policy_revision FROM budget_policy"
        " WHERE id=1").fetchone()
    if row is None:
        raise BudgetNotInitialised("privacy budget is not initialised")
    return {"initial_daily_quota": row["initial_daily_quota"],
            "policy_revision": row["policy_revision"]}


def policy(conn) -> dict:
    _require_init(conn)
    return _policy_locked(conn)


def _head_locked(conn) -> dict:
    row = conn.execute(
        "SELECT head_seq, head_hash FROM budget_head WHERE id=1").fetchone()
    if row is None:
        budget_id = conn.execute(
            "SELECT value FROM meta WHERE key=?", (META_BUDGET_ID,)).fetchone()
        return {"seq": 0,
                "hash": "BUDGET-GENESIS:" + (budget_id["value"] if budget_id else "")}
    return {"seq": row["head_seq"], "hash": row["head_hash"]}


def _append_event_locked(conn, *, tenant_id, window, kind, count=0,
                         reason="", policy_revision=None, created_at=None):
    """Append while caller already holds a BEGIN IMMEDIATE transaction."""
    tip = _head_locked(conn)
    pol = _policy_locked(conn)
    revision = policy_revision if policy_revision is not None else pol["policy_revision"]
    event = {
        "seq": tip["seq"] + 1,
        "tenant_id": tenant_id,
        "window_start": window,
        "kind": kind,
        "count": int(count),
        "reason": reason or "",
        "created_at": created_at or utcnow_ts(),
        "policy_revision": int(revision),
        "prev_hash": tip["hash"],
    }
    event["event_hash"] = _hash_event(event)
    conn.execute(
        "INSERT INTO budget_events(seq, tenant_id, window_start, kind, count,"
        " reason, created_at, policy_revision, prev_hash, event_hash)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (event["seq"], event["tenant_id"], event["window_start"], event["kind"],
         event["count"], event["reason"], event["created_at"],
         event["policy_revision"], event["prev_hash"], event["event_hash"]))
    cas = conn.execute(
        "UPDATE budget_head SET head_seq=?, head_hash=?"
        " WHERE id=1 AND head_seq=? AND head_hash=?",
        (event["seq"], event["event_hash"], tip["seq"], tip["hash"]))
    if cas.rowcount != 1:
        raise StaleBudget("budget event chain advanced during this transaction")
    return event


def _bump_policy_locked(conn) -> int:
    cas = conn.execute(
        "UPDATE budget_policy SET policy_revision = policy_revision + 1"
        " WHERE id=1")
    if cas.rowcount != 1:
        raise BudgetNotInitialised("privacy budget is not initialised")
    return _policy_locked(conn)["policy_revision"]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(conn, tenant_id: str, label: str = "") -> str:
    """Issue a caller token. Only its SHA-256 hash is persisted."""
    _require_init(conn)
    tenant_id = validate_tenant(tenant_id)
    if not isinstance(label, str) or len(label) > 200:
        raise BudgetError("label must be a string of at most 200 characters")
    token = "pwb_" + secrets.token_urlsafe(32)
    now = utcnow_ts()
    with db.write_tx(conn):
        _ensure_window_locked(conn, tenant_id, window_start_for(), now=now)
        conn.execute(
            "INSERT INTO budget_tokens(token_sha256, tenant_id, label,"
            " revoked, created_at) VALUES (?,?,?,0,?)",
            (_hash_token(token), tenant_id, label, now))
    return token


def revoke_token(conn, token: str) -> dict:
    """Revoke a token before it can start a new budget transaction."""
    _require_init(conn)
    if not isinstance(token, str) or not token:
        raise BudgetError("token is required")
    now = utcnow_ts()
    with db.write_tx(conn):
        cur = conn.execute(
            "UPDATE budget_tokens SET revoked=1, revoked_at=?"
            " WHERE token_sha256=? AND revoked=0",
            (now, _hash_token(token)))
        if cur.rowcount == 0:
            row = conn.execute(
                "SELECT 1 FROM budget_tokens WHERE token_sha256=?",
                (_hash_token(token),)).fetchone()
            if row is None:
                raise BudgetAuth("missing or invalid token")
            return {"revoked": False, "note": "token was already revoked"}
    return {"revoked": True, "revoked_at": now}


def _active_tokens_locked(conn, tokens: list[str]) -> dict[str, str]:
    if not tokens:
        raise BudgetAuth("missing budget token")
    if len(tokens) > 2:
        raise BudgetAuth("at most two budget tokens are accepted")
    hashes = [_hash_token(t) for t in tokens]
    placeholders = ",".join("?" for _ in hashes)
    rows = conn.execute(
        f"SELECT token_sha256, tenant_id FROM budget_tokens"
        f" WHERE revoked=0 AND token_sha256 IN ({placeholders})",
        hashes).fetchall()
    found = {r["token_sha256"]: r["tenant_id"] for r in rows}
    if len(found) != len(set(hashes)):
        # Identical generic response for unknown and revoked credentials.
        raise BudgetAuth("missing or invalid token")
    return {h: found[h] for h in hashes}


# --------------------------------------------------------------------------
# Daily windows and administrative operations
# --------------------------------------------------------------------------

def _ensure_window_locked(conn, tenant_id: str, window: str, *,
                          now: str | None = None) -> dict:
    """Get a row, opening a UTC day if needed.

    A freeze is tenant state and therefore follows the tenant into the next
    UTC day. Spending and top-ups never cross a calendar-day boundary.
    """
    row = conn.execute(
        "SELECT tenant_id, window_start, remaining, spent, frozen,"
        " policy_revision FROM budget_windows"
        " WHERE tenant_id=? AND window_start=?",
        (tenant_id, window)).fetchone()
    if row is not None:
        return dict(row)

    previous = conn.execute(
        "SELECT frozen FROM budget_windows WHERE tenant_id=?"
        " ORDER BY window_start DESC LIMIT 1", (tenant_id,)).fetchone()
    policy = _policy_locked(conn)
    frozen = 1 if previous and previous["frozen"] else 0
    conn.execute(
        "INSERT INTO budget_windows(tenant_id, window_start, remaining, spent,"
        " frozen, policy_revision) VALUES (?,?,?,0,?,?)",
        (tenant_id, window, policy["initial_daily_quota"], frozen,
         policy["policy_revision"]))
    return {"tenant_id": tenant_id, "window_start": window,
            "remaining": policy["initial_daily_quota"], "spent": 0,
            "frozen": frozen, "policy_revision": policy["policy_revision"]}


def grant(conn, tenant_id: str, amount: int, *,
          window: str | None = None) -> dict:
    """Atomically add quota to one tenant's current UTC day and record it."""
    _require_init(conn)
    tenant_id = validate_tenant(tenant_id)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise BudgetError("grant amount must be a positive integer")
    window = normalize_window(window)
    now = utcnow_ts()
    if window != normalize_window(now):
        raise BudgetError("quota can only be appended to the current UTC window")

    with db.write_tx(conn):
        row = _ensure_window_locked(conn, tenant_id, window, now=now)
        revision = _bump_policy_locked(conn)
        updated = conn.execute(
            "UPDATE budget_windows SET remaining=remaining+?,"
            " policy_revision=? WHERE tenant_id=? AND window_start=?",
            (amount, revision, tenant_id, window))
        if updated.rowcount != 1:
            raise StaleBudget("budget window changed during grant")
        _append_event_locked(conn, tenant_id=tenant_id, window=window,
                             kind="grant", count=amount,
                             policy_revision=revision, created_at=now)
        return get_window_locked(conn, tenant_id, window)


def _set_frozen(conn, tenant_id: str, frozen: bool) -> dict:
    _require_init(conn)
    tenant_id = validate_tenant(tenant_id)
    window = window_start_for()
    kind = "freeze" if frozen else "unfreeze"
    now = utcnow_ts()
    with db.write_tx(conn):
        row = _ensure_window_locked(conn, tenant_id, window, now=now)
        if bool(row["frozen"]) == frozen:
            return {**get_window_locked(conn, tenant_id, window),
                    "changed": False}
        revision = _bump_policy_locked(conn)
        updated = conn.execute(
            "UPDATE budget_windows SET frozen=?, policy_revision=?"
            " WHERE tenant_id=? AND window_start=?",
            (1 if frozen else 0, revision, tenant_id, window))
        if updated.rowcount != 1:
            raise StaleBudget("budget window changed during freeze operation")
        _append_event_locked(conn, tenant_id=tenant_id, window=window,
                             kind=kind, count=0, policy_revision=revision,
                             created_at=now)
        result = get_window_locked(conn, tenant_id, window)
        result["changed"] = True
        return result


def freeze(conn, tenant_id: str) -> dict:
    return _set_frozen(conn, tenant_id, True)


def unfreeze(conn, tenant_id: str) -> dict:
    return _set_frozen(conn, tenant_id, False)


def get_window_locked(conn, tenant_id: str, window: str) -> dict:
    row = conn.execute(
        "SELECT tenant_id, window_start, remaining, spent, frozen,"
        " policy_revision FROM budget_windows"
        " WHERE tenant_id=? AND window_start=?",
        (tenant_id, window)).fetchone()
    if row is None:
        raise BudgetError("no budget window exists for that tenant and day")
    aggregates = event_totals_locked(conn, tenant_id, window)
    result = dict(row)
    result["frozen"] = bool(result["frozen"])
    result.update(aggregates)
    return result


def event_totals_locked(conn, tenant_id: str, window: str) -> dict:
    rows = conn.execute(
        "SELECT kind, reason, COUNT(*) AS events, COALESCE(SUM(count),0) AS total"
        " FROM budget_events WHERE tenant_id=? AND window_start=?"
        " GROUP BY kind, reason", (tenant_id, window)).fetchall()
    out = {"granted": 0, "deductions": 0, "failure_reasons": {}}
    for r in rows:
        if r["kind"] == "grant":
            out["granted"] = int(r["total"])
        elif r["kind"] == "consume":
            out["deductions"] = int(r["total"])
        elif r["kind"] == "deny":
            out["failure_reasons"][r["reason"]] = int(r["events"])
    return out


def get_window(conn, tenant_id: str, window: str | None = None) -> dict:
    _require_init(conn)
    tenant_id = validate_tenant(tenant_id)
    window = normalize_window(window)
    conn.execute("BEGIN")
    try:
        return get_window_locked(conn, tenant_id, window)
    finally:
        conn.execute("ROLLBACK")


def list_windows(conn, window: str | None = None) -> list[dict]:
    _require_init(conn)
    window = normalize_window(window)
    conn.execute("BEGIN")
    try:
        rows = conn.execute(
            "SELECT tenant_id, window_start, remaining, spent, frozen,"
            " policy_revision FROM budget_windows WHERE window_start=?"
            " ORDER BY tenant_id", (window,)).fetchall()
        return [get_window_locked(conn, r["tenant_id"], r["window_start"])
                for r in rows]
    finally:
        conn.execute("ROLLBACK")


# --------------------------------------------------------------------------
# Atomic quota-consuming range query
# --------------------------------------------------------------------------

def _bucket_body_locked(conn, version: int, prefix: str) -> str | None:
    rows = conn.execute(
        "SELECT suffix, cnt FROM pub_buckets WHERE version=? AND prefix=?"
        " ORDER BY suffix", (version, prefix)).fetchall()
    if not rows:
        return None
    return "".join(f"{r['suffix']}:{r['cnt']}\n" for r in rows)


def _state_dict(row: dict, policy_revision: int) -> dict:
    return {
        "tenant_id": row["tenant_id"],
        "window_start": row["window_start"],
        "remaining": row["remaining"],
        "spent": row["spent"],
        "frozen": bool(row["frozen"]),
        "policy_revision": row["policy_revision"],
        "current_policy_revision": policy_revision,
        "reset_at": next_window_start(row["window_start"]),
    }


def consume_query(conn, tokens: list[str], prefix: str, *,
                 retries: int = 60) -> dict:
    """Consume one quota and read the active bucket atomically.

    With two tokens, tenant rows are compared under the same write lock. A
    frozen tenant is stricter than an unfrozen one; otherwise the tenant with
    less remaining quota is selected. Ties resolve by tenant id, giving a
    total, first-write-wins serial order under concurrency.
    """
    _require_init(conn)
    # The active publication owns its prefix length (5 in production). It is
    # read inside the atomic transaction so test/version differences cannot
    # mix bucket schemas.
    if not isinstance(prefix, str) or not prefix or \
            any(c not in "0123456789ABCDEFabcdef" for c in prefix):
        raise BudgetError("prefix must contain hex characters only")
    prefix = prefix.upper()
    if not isinstance(tokens, list) or not tokens or \
            not all(isinstance(t, str) and t for t in tokens):
        raise BudgetAuth("missing budget token")

    for attempt in range(retries):
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                result = _consume_query_locked(conn, tokens, prefix)
                if result.get("status") == 503:
                    conn.execute("ROLLBACK")
                return result
            except BudgetDenied:
                # The denial audit row and quota state were already committed.
                raise
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        except StaleBudget:
            time.sleep(0.005 * (attempt + 1))
            continue
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() and attempt < retries - 1:
                time.sleep(0.01 * (attempt + 1))
                continue
            raise
    raise BudgetError("budget transaction repeatedly lost serialization")


def _consume_query_locked(conn, tokens, prefix) -> dict:
    version_row = conn.execute(
        "SELECT version, prefix_len FROM publications WHERE version=("
        "SELECT value FROM meta WHERE key='current_version')").fetchone()
    if version_row is None:
        # No publication can be returned; do not charge for service downtime.
        return {"allowed": False, "status": 503, "reason": "no_active_publication"}
    version = version_row["version"]
    if len(prefix) != version_row["prefix_len"]:
        raise BudgetError(
            f"prefix must be exactly {version_row['prefix_len']} hex characters")

    token_tenants = _active_tokens_locked(conn, tokens)
    window = window_start_for()
    now = utcnow_ts()
    tenant_rows = {}
    for tenant in sorted(set(token_tenants.values())):
        tenant_rows[tenant] = _ensure_window_locked(conn, tenant, window, now=now)

    chosen_id = min(
        tenant_rows,
        key=lambda t: (
            # A frozen caller cannot receive content regardless of remaining.
            0 if tenant_rows[t]["frozen"] else 1,
            # Smaller remaining is the stricter quota.
            tenant_rows[t]["remaining"],
            # Deterministic tie-break; SQLite lock order supplies arrival order.
            t,
        ))
    chosen = tenant_rows[chosen_id]
    policy_revision = _policy_locked(conn)["policy_revision"]
    state = _state_dict(chosen, policy_revision)

    if chosen["frozen"]:
        event = _append_event_locked(
            conn, tenant_id=chosen_id, window=window, kind="deny", count=0,
            reason=REASON_FROZEN, policy_revision=chosen["policy_revision"],
            created_at=now)
        conn.execute("COMMIT")
        denied = {**state, "allowed": False, "status": 403,
                  "reason": REASON_FROZEN, "event_seq": event["seq"]}
        raise BudgetDenied(REASON_FROZEN, status=403, state=denied)

    if chosen["remaining"] <= 0:
        event = _append_event_locked(
            conn, tenant_id=chosen_id, window=window, kind="deny", count=0,
            reason=REASON_EXHAUSTED, policy_revision=chosen["policy_revision"],
            created_at=now)
        conn.execute("COMMIT")
        denied = {**state, "allowed": False, "status": 429,
                  "reason": REASON_EXHAUSTED, "event_seq": event["seq"]}
        raise BudgetDenied(REASON_EXHAUSTED, status=429, state=denied)

    updated = conn.execute(
        "UPDATE budget_windows SET remaining=remaining-1, spent=spent+1"
        " WHERE tenant_id=? AND window_start=? AND remaining>0 AND frozen=0",
        (chosen_id, window))
    if updated.rowcount != 1:
        raise StaleBudget("selected budget changed before its conditional update")

    # Read only after the quota has been durably claimed in this same txn.
    body = _bucket_body_locked(conn, version, prefix)
    event = _append_event_locked(
        conn, tenant_id=chosen_id, window=window, kind="consume", count=1,
        reason="", policy_revision=chosen["policy_revision"], created_at=now)

    # Re-read the exact post-update values included with the committed result.
    after = _ensure_window_locked(conn, chosen_id, window, now=now)
    # The re-read above finds existing row; SQLite's CHECK guarantees no
    # negative balance. The assertion protects future schema changes.
    if after["remaining"] < 0 or after["spent"] <= 0:
        raise AssertionError("privacy budget invariant violated")
    conn.execute("COMMIT")
    state = _state_dict(after, policy_revision)
    return {**state, "allowed": True, "status": 200 if body is not None else 404,
            "version": version, "body": body, "event_seq": event["seq"]}
