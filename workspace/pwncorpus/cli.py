"""Admin CLI for pwncorpus.

  python -m pwncorpus.cli init --db corpus.db
  python -m pwncorpus.cli token --db corpus.db --label ingestor --scopes ingest
  python -m pwncorpus.cli ingest --db corpus.db --source breach-2026Q3 --file leaks.txt
  python -m pwncorpus.cli build --db corpus.db --k 50
  python -m pwncorpus.cli refresh --db corpus.db --version 3
  python -m pwncorpus.cli activate --db corpus.db --version 3
  python -m pwncorpus.cli retract --db corpus.db --batch <id>
  python -m pwncorpus.cli export --db corpus.db --version 3 --out export-v3/
  python -m pwncorpus.cli delta-generate --db corpus.db \
      --from-version 2 --to-version 3 --out delta-v2-v3/
  python -m pwncorpus.delta check delta-v2-v3/ [--baseline mirror/]
  python -m pwncorpus.delta apply delta-v2-v3/ mirror/
  python -m pwncorpus.cli serve --db corpus.db --host 127.0.0.1 --port 8080
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import audit, attest, core, db, delta, ledger, verifier
from . import budget, budgetaudit, budgetverify
from . import ed25519
import hashlib as _hashlib


def _conn(args):
    return db.connect(args.db)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pwncorpus")
    ap.add_argument("--db", default="corpus.db", help="SQLite database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database schema")

    p = sub.add_parser("token", help="create an API token (shown once)")
    p.add_argument("--label", required=True)
    p.add_argument("--scopes", required=True,
                   help="comma separated: ingest,retract,publish,budget_admin")

    # ---- per-caller privacy budget --------------------------------------
    p = sub.add_parser("budget-init",
                       help="initialise per-tenant daily privacy budgets")
    p.add_argument("--daily-quota", dest="daily_quota", type=int,
                   default=budget.DEFAULT_DAILY_QUOTA)
    p.add_argument("--key", required=True, help="budget genesis private key (0600)")

    p = sub.add_parser("budget-token",
                       help="issue a token for one privacy-budget tenant")
    p.add_argument("--tenant", required=True)
    p.add_argument("--label", default="")

    p = sub.add_parser("budget-revoke", help="revoke one caller budget token")
    p.add_argument("--token", required=True)

    p = sub.add_parser("budget-grant", help="append quota to a tenant's UTC day")
    p.add_argument("--tenant", required=True)
    p.add_argument("--amount", type=int, required=True)
    p.add_argument("--window", default=None, help="must be the current UTC date")

    p = sub.add_parser("budget-freeze", help="freeze a tenant's budget token access")
    p.add_argument("--tenant", required=True)

    p = sub.add_parser("budget-unfreeze", help="unfreeze a tenant")
    p.add_argument("--tenant", required=True)

    p = sub.add_parser("budget-get", help="show one tenant/window budget state")
    p.add_argument("--tenant", required=True)
    p.add_argument("--window", default=None)

    p = sub.add_parser("budget-list", help="list budget states for one UTC window")
    p.add_argument("--window", default=None)

    p = sub.add_parser("budget-export",
                       help="independent read-only audit export for a UTC day")
    p.add_argument("--key", required=True, help="budget genesis private key")
    p.add_argument("--out", required=True)
    p.add_argument("--window", default=None)
    p.add_argument("--now", default=None)
    p.add_argument("--genesis-pub", default=None)

    p = sub.add_parser("budget-verify-db",
                       help="verify stored budget chain without exporting")
    p.add_argument("--window", default=None)

    p = sub.add_parser("budget-verify",
                       help="offline verify a detached budget export (no DB)")
    p.add_argument("export_dir")
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("budget-check",
                       help="offline decide whether request ordinal was in budget")
    p.add_argument("export_dir")
    p.add_argument("--tenant", required=True)
    p.add_argument("--ordinal", type=int, required=True)
    p.add_argument("--window", default=None)
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("ingest", help="ingest a batch file (one password or "
                       "'sha1:<hex>' per line)")
    p.add_argument("--source", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--idempotency-key", default=None)

    p = sub.add_parser("build", help="build a candidate publication")
    p.add_argument("--k", type=int, default=core.DEFAULT_THRESHOLD_K,
                   help="minimum bucket set size")

    p = sub.add_parser("activate", help="atomically activate a candidate "
                       "(fails with a conflict if the candidate is stale)")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("refresh", help="rebuild a stale candidate from current "
                       "source data, keeping its version and threshold k")
    p.add_argument("--version", type=int, required=True)

    p = sub.add_parser("retract", help="retract a batch (effective next build)")
    p.add_argument("--batch", required=True)

    p = sub.add_parser("correct", help="exclude fingerprints of a batch "
                       "(false positives), effective next build")
    p.add_argument("--batch", required=True)
    p.add_argument("--file", required=True,
                   help="file with one password or 'sha1:<hex>' per line")

    p = sub.add_parser("export", help="export a version for offline verification")
    p.add_argument("--version", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("delta-generate",
                       help="build a verifiable incremental package between two"
                       " stored releases (offline hosts can also use"
                       " 'python -m pwncorpus.delta build' on two exports)")
    p.add_argument("--from-version", type=int, required=True,
                   help="baseline release already present in the mirror")
    p.add_argument("--to-version", type=int, required=True,
                   help="target release")
    p.add_argument("--out", required=True, help="output delta package directory")

    p = sub.add_parser("status", help="show publications and batch stats")

    # ---- provenance responsibility ledger (additive; existing commands
    #      above are unchanged) -------------------------------------------
    p = sub.add_parser("ledger-init",
                       help="initialise the append-only provenance ledger and"
                            " create its genesis signing key")
    p.add_argument("--key", required=True, help="where to write the genesis"
                                                " private key file (mode 0600)")
    p.add_argument("--prefix-len", dest="prefix_len", type=int,
                   default=ledger.LEDGER_PREFIX_LEN)

    p = sub.add_parser("ledger-keygen",
                       help="generate a source Ed25519 key file (offline)")
    p.add_argument("--key", required=True)
    p.add_argument("--source", required=True)

    p = sub.add_parser("ledger-register", help="register a source public key")
    p.add_argument("--source", required=True)
    p.add_argument("--key", required=True, help="the source's private key file")
    p.add_argument("--created-at", dest="created_at", default=None)
    p.add_argument("--expect-head", dest="expect_head", type=int, default=None)

    p = sub.add_parser("ledger-submit",
                       help="append a signed submission claim for a batch file")
    p.add_argument("--source", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--file", required=True, help="the ingested batch file"
                       " (passwords / sha1: lines, as for 'ingest')")
    p.add_argument("--reason", default="", help="optional provenance note")
    p.add_argument("--created-at", dest="created_at", default=None)
    p.add_argument("--idempotency-key", dest="idempotency_key", default=None)
    p.add_argument("--expect-head", dest="expect_head", type=int, default=None)

    p = sub.add_parser("ledger-retract",
                       help="append a signed retraction for an earlier submit")
    p.add_argument("--source", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--claim-seq", dest="claim_seq", type=int, required=True,
                   help="seq of the submit chain item being retracted")
    p.add_argument("--file", required=True,
                   help="the original input file (digest must match)")
    p.add_argument("--reason", required=True, help="mandatory retraction reason")
    p.add_argument("--created-at", dest="created_at", default=None)
    p.add_argument("--expect-head", dest="expect_head", type=int, default=None)

    p = sub.add_parser("ledger-correct",
                       help="append a signed false-positive correction")
    p.add_argument("--source", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--claim-seq", dest="claim_seq", type=int, required=True)
    p.add_argument("--file", required=True,
                   help="file with one password or 'sha1:<hex>' per line")
    p.add_argument("--created-at", dest="created_at", default=None)
    p.add_argument("--expect-head", dest="expect_head", type=int, default=None)

    p = sub.add_parser("ledger-replay",
                       help="resume/append a batch of signed intents from a"
                            " JSONL file; claims already on the chain are"
                            " skipped (replayable after interruption)")
    p.add_argument("--intents", required=True)
    p.add_argument("--expect-head", dest="expect_head", type=int, default=None)

    p = sub.add_parser("ledger-head", help="show the current chain head")

    p = sub.add_parser("serve", help="run the HTTP server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    args = ap.parse_args(argv)

    if args.cmd == "init":
        db.init(args.db)
        print(f"initialised {args.db}")
        return 0

    if args.cmd == "serve":
        from .server import make_server
        srv = make_server(args.db, args.host, args.port)
        print(f"serving on http://{args.host}:{args.port}  (db={args.db})")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    conn = _conn(args)
    try:
        if args.cmd == "token":
            token = core.create_token(conn, args.label, args.scopes.split(","))
            print(f"token (store it now, it is not recoverable): {token}")
            return 0

        # ---- privacy budget handlers ------------------------------------
        if args.cmd == "budget-init":
            info = budget.initialise(conn, args.daily_quota, args.key)
            print(json.dumps(info, indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-token":
            print(budget.create_token(conn, args.tenant, args.label))
            return 0

        if args.cmd == "budget-revoke":
            print(json.dumps(budget.revoke_token(conn, args.token), indent=2,
                             sort_keys=True))
            return 0

        if args.cmd == "budget-grant":
            print(json.dumps(budget.grant(conn, args.tenant, args.amount,
                                          window=args.window),
                             indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-freeze":
            print(json.dumps(budget.freeze(conn, args.tenant), indent=2,
                             sort_keys=True))
            return 0

        if args.cmd == "budget-unfreeze":
            print(json.dumps(budget.unfreeze(conn, args.tenant), indent=2,
                             sort_keys=True))
            return 0

        if args.cmd == "budget-get":
            print(json.dumps(budget.get_window(conn, args.tenant, args.window),
                             indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-list":
            print(json.dumps(budget.list_windows(conn, args.window),
                             indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-verify-db":
            result = budgetaudit.verify(args.db)
            print(json.dumps({
                "budget_id": result["budget_id"],
                "head_seq": result["head_seq"],
                "head_hash": result["head_hash"],
                "initial_daily_quota": result["initial_daily_quota"],
                "policy_revision": result["policy_revision"],
                "windows": len(result["windows"]),
            }, indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-export":
            manifest = budgetaudit.export_budget(
                args.db, args.key, args.out, args.window,
                created_at=args.now, genesis_pub_pin=args.genesis_pub)
            print(json.dumps(manifest, indent=2, sort_keys=True))
            return 0

        if args.cmd == "budget-verify":
            verified = budgetverify.verify_export(
                args.export_dir, trusted_genesis_pub=args.genesis_pub)
            if args.json:
                print(json.dumps(verified, indent=2, sort_keys=True))
            else:
                print(f"OK: budget export {verified['manifest']['budget_id']},"
                      f" {len(verified['rows'])} tenant rows, window"
                      f" {verified['manifest']['window_start']}")
            return 0

        if args.cmd == "budget-check":
            verified = budgetverify.verify_export(
                args.export_dir, trusted_genesis_pub=args.genesis_pub)
            verdict = budgetverify.check_request(
                verified, args.tenant, args.ordinal, window=args.window)
            print(json.dumps(verdict, indent=2, sort_keys=True))
            return 0 if verdict["verdict"] == "within_budget" else 3

        if args.cmd == "ingest":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            result = core.ingest_batch(conn, args.source, items,
                                       args.idempotency_key)
            items.clear()
            print(json.dumps(result, indent=2))
            return 0

        if args.cmd == "build":
            print(json.dumps(core.build_candidate(conn, args.k), indent=2))
            return 0

        if args.cmd == "activate":
            print(json.dumps(core.activate(conn, args.version), indent=2))
            return 0

        if args.cmd == "refresh":
            print(json.dumps(core.refresh_candidate(conn, args.version), indent=2))
            return 0

        if args.cmd == "retract":
            print(json.dumps(core.retract_batch(conn, args.batch), indent=2))
            return 0

        if args.cmd == "correct":
            items = []
            with open(args.file, "r", encoding="utf-8", errors="surrogateescape") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if not line:
                        continue
                    if line.lower().startswith("sha1:"):
                        items.append({"sha1": line[5:]})
                    else:
                        items.append(line)
            print(json.dumps(core.add_corrections(conn, args.batch, items), indent=2))
            return 0

        if args.cmd == "export":
            manifest = core.export_version(conn, args.version, args.out)
            print(f"exported v{args.version} to {args.out} "
                  f"({len(manifest['files'])} buckets, "
                  f"manifest {manifest['manifest_sha256'][:16]}...)")
            return 0

        if args.cmd == "delta-generate":
            import tempfile
            with tempfile.TemporaryDirectory(prefix="pwncorpus-delta-") as tmp:
                fdir = os.path.join(tmp, "from")
                tdir = os.path.join(tmp, "to")
                core.export_version(conn, args.from_version, fdir)
                core.export_version(conn, args.to_version, tdir)
                if verifier.verify_export(fdir) or verifier.verify_export(tdir):
                    raise core.CorpusError(
                        "internal export failed verification; aborting delta build")
                meta = delta.build_delta(fdir, tdir, args.out)
            s = delta.delta_summary(meta)
            print(f"built delta v{s['from_version']} -> v{s['to_version']} "
                  f"in {args.out} "
                  f"(added {s['buckets_added']}, modified {s['buckets_modified']},"
                  f" deleted {s['buckets_deleted']}, unchanged "
                  f"{s['buckets_unchanged']} buckets)")
            return 0

        if args.cmd == "status":
            state = core.review_state(conn)
            print(json.dumps({
                "active_version": core.current_version(conn),
                "corpus_state": state["corpus_state"],
                "publications": state["publications"],
                "stats": state["stats"],
            }, indent=2))
            return 0

        # ---- provenance ledger handlers --------------------------------
        if args.cmd == "ledger-init":
            info = ledger.initialise(conn, args.key,
                                     prefix_len=args.prefix_len)
            print(f"ledger initialised: id {info['ledger_id']}, prefix_len"
                  f" {info['prefix_len']}")
            print(f"genesis public key: {info['genesis_pub']}")
            print(f"genesis private key written (0600) to {info['key_file']}")
            return 0

        if args.cmd == "ledger-keygen":
            seed, pub = ed25519.generate_key()
            ledger.write_key_file(args.key, seed, pub, kind="source",
                                  source=args.source)
            print(f"source key for {args.source} written (0600) to {args.key}")
            print(f"public key (register it with ledger-register): {pub.hex()}")
            return 0

        def _source_key():
            kd = ledger.read_key_file(args.key)
            if kd.get("kind") != "source":
                raise ledger.LedgerError(
                    f"{args.key} is not a source key file")
            if kd.get("source") is not None and kd["source"] != args.source:
                raise ledger.LedgerError(
                    "key file belongs to a different source"
                    " (source permission)")
            return kd

        if args.cmd == "ledger-register":
            kd = _source_key()
            if kd.get("source") is not None and kd["source"] != args.source:
                raise ledger.LedgerError("source permission: key/source mismatch")
            payload = {"pubkey": kd["_pub"].hex()}
            created = args.created_at or core.utcnow()
            intent = ledger.build_intent(
                attest.KIND_REGISTER, args.source, payload, kd["_seed"], created)
            entry = ledger.append(conn, intent,
                                  expected_head_seq=args.expect_head)
            print(_entry_json(entry))
            return 0

        if args.cmd == "ledger-submit":
            kd = _source_key()
            fingerprints = _batch_fingerprints(args.file)
            prefix_len = int(ledger._meta(conn, ledger.META_PREFIX_LEN)) \
                if ledger.is_initialised(conn) else ledger.LEDGER_PREFIX_LEN
            prefixes = sorted({fp[:prefix_len] for fp in fingerprints})
            file_digest = _file_sha256(args.file)
            payload = {"file_sha256": file_digest, "prefixes": prefixes}
            if args.reason:
                payload["reason"] = args.reason
            created = args.created_at or core.utcnow()
            intent = ledger.build_intent(
                attest.KIND_SUBMIT, args.source, payload, kd["_seed"], created,
                claim_id=args.idempotency_key or None)
            entry = ledger.append(conn, intent,
                                  expected_head_seq=args.expect_head)
            print(_entry_json(entry))
            return 0

        if args.cmd == "ledger-retract":
            kd = _source_key()
            file_digest = _file_sha256(args.file)
            payload = {"claim_seq": args.claim_seq,
                       "file_sha256": file_digest, "reason": args.reason}
            created = args.created_at or core.utcnow()
            intent = ledger.build_intent(
                attest.KIND_RETRACT, args.source, payload, kd["_seed"], created)
            entry = ledger.append(conn, intent,
                                  expected_head_seq=args.expect_head)
            print(_entry_json(entry))
            return 0

        if args.cmd == "ledger-correct":
            kd = _source_key()
            fingerprints = sorted({fp.lower()
                                   for fp in _batch_fingerprints(args.file)})
            payload = {"claim_seq": args.claim_seq,
                       "fingerprints": fingerprints}
            created = args.created_at or core.utcnow()
            intent = ledger.build_intent(
                attest.KIND_CORRECT, args.source, payload, kd["_seed"], created)
            entry = ledger.append(conn, intent,
                                  expected_head_seq=args.expect_head)
            print(_entry_json(entry))
            return 0

        if args.cmd == "ledger-replay":
            intents = _load_intents(args.intents)
            result = ledger.replay_intents(
                conn, intents, expected_head_seq=args.expect_head)
            print(json.dumps(result, indent=2))
            return 0

        if args.cmd == "ledger-head":
            if not ledger.is_initialised(conn):
                raise ledger.LedgerError("ledger is not initialised")
            print(json.dumps(ledger.ledger_info(conn), indent=2, sort_keys=True))
            return 0
    except core.CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except delta.DeltaError as exc:  # delta-generate validation failures
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ledger.LedgerError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except budgetaudit.BudgetAuditError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except budget.BudgetError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except budgetverify.BudgetVerifyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 1  # pragma: no cover


def _file_sha256(path: str) -> str:
    h = _hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _batch_fingerprints(path: str) -> list[str]:
    """Fingerprints of a batch file, using the same parsing/edge-hashing
    rules as the existing 'ingest' command."""
    fps = []
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.lower().startswith("sha1:"):
                fps.append(core.fingerprint({"sha1": line[5:]}))
            else:
                fps.append(core.fingerprint(line))
    if not fps:
        raise ledger.LedgerError("batch file contains no items")
    return fps


def _load_intents(path: str) -> list[dict]:
    intents = []
    required = {"kind", "source", "payload", "created_at", "claim_id",
                "signature"}
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                intent = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ledger.LedgerError(
                    f"{path}:{n}: invalid intent JSON: {exc}") from exc
            missing = required - set(intent)
            if missing:
                raise ledger.LedgerError(
                    f"{path}:{n}: intent missing {sorted(missing)}")
            intents.append(intent)
    if not intents:
        raise ledger.LedgerError("intents file is empty")
    return intents


def _entry_json(entry: dict) -> str:
    return json.dumps({
        "seq": entry["seq"], "kind": entry["kind"],
        "source": entry["source"], "duplicate": entry.get("duplicate", False),
        "claim_id": entry["claim_id"], "created_at": entry["created_at"],
        "entry_hash": entry.get("entry_hash"), "prev_hash": entry["prev_hash"],
    }, indent=2, sort_keys=True)



if __name__ == "__main__":
    raise SystemExit(main())
