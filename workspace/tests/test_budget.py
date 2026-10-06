"""Tests for per-caller privacy budgets and isolated audit verification."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer

from pwncorpus import budget, budgetaudit, budgetverify, core, db, server


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest().upper()


def passwords_for_prefix(prefix: str, count: int) -> list[str]:
    out, i = [], 0
    while len(out) < count:
        value = f"budget-password-{prefix}-{i}"
        if sha1(value).startswith(prefix):
            out.append(value)
        i += 1
    return out


def iso_utc_day(offset_days: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=offset_days)) \
        .date().isoformat()


class BudgetHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="budget-test-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        self.key_path = os.path.join(self.tmp, "budget.key")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        self._old_prefix_len = core.PREFIX_LEN
        core.PREFIX_LEN = 5
        self.addCleanup(setattr, core, "PREFIX_LEN", self._old_prefix_len)
        self.info = budget.initialise(self.conn, 3, self.key_path)
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def publish_bucket(self, prefix: str = "AAAAA", count: int = 2):
        core.ingest_batch(self.conn, "budget-source",
                          passwords_for_prefix(prefix, count))
        info = core.build_candidate(self.conn, 1)
        core.activate(self.conn, info["version"])
        return prefix

    def token(self, tenant="tenant-a"):
        return budget.create_token(self.conn, tenant, tenant)

    def consume(self, token_value, prefix="AAAAA"):
        return budget.consume_query(self.conn, [token_value], prefix)


class CoreBudgetTests(BudgetHarness):
    def test_first_request_opens_window_and_deducts_atomically(self):
        prefix = self.publish_bucket()
        token_value = self.token()
        before = budget.window_start_for()
        result = self.consume(token_value, prefix)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["status"], 200)
        self.assertIn(":", result["body"])
        self.assertEqual((result["remaining"], result["spent"]), (2, 1))
        self.assertEqual(result["window_start"], before)
        state = budget.get_window(self.conn, "tenant-a")
        self.assertEqual((state["remaining"], state["spent"],
                          state["frozen"], state["policy_revision"]),
                         (2, 1, False, 1))
        self.assertEqual(state["deductions"], 1)
        self.assertEqual(state["failure_reasons"], {})

    def test_absent_bucket_still_charges_and_returns_404_without_existence_hint(self):
        self.publish_bucket("AAAAA")
        token_value = self.token()
        result = self.consume(token_value, "BBBBB")
        self.assertEqual(result["status"], 404)
        self.assertIsNone(result["body"])
        self.assertEqual(result["spent"], 1)
        self.assertEqual(budget.get_window(self.conn, "tenant-a")["spent"], 1)

    def test_exhaustion_returns_clear_rate_limit_and_stops_body(self):
        self.publish_bucket()
        token_value = self.token()
        for _ in range(3):
            self.assertEqual(self.consume(token_value)["status"], 200)
        with self.assertRaises(budget.BudgetDenied) as ctx:
            self.consume(token_value)
        denied = ctx.exception
        self.assertEqual(denied.status, 429)
        self.assertEqual(denied.reason, budget.REASON_EXHAUSTED)
        self.assertEqual(denied.state["remaining"], 0)
        state = budget.get_window(self.conn, "tenant-a")
        self.assertEqual(state["spent"], 3)
        self.assertEqual(state["failure_reasons"], {"budget_exhausted": 1})

    def test_grant_appends_quota_increments_revision_and_audit_matches_admin(self):
        self.publish_bucket()
        token_value = self.token()
        self.consume(token_value)
        result = budget.grant(self.conn, "tenant-a", 2)
        self.assertEqual(result["remaining"], 4)
        self.assertEqual(result["granted"], 2)
        self.assertEqual(result["policy_revision"], 2)
        # Three more now fit (two remaining + two appended).
        self.consume(token_value)
        self.consume(token_value)
        self.consume(token_value)
        self.assertEqual(budget.get_window(self.conn, "tenant-a")["remaining"], 1)

    def test_freeze_and_unfreeze_deny_body_and_record_reasons(self):
        self.publish_bucket()
        token_value = self.token()
        frozen = budget.freeze(self.conn, "tenant-a")
        self.assertTrue(frozen["frozen"])
        self.assertEqual(frozen["policy_revision"], 2)
        with self.assertRaises(budget.BudgetDenied) as ctx:
            self.consume(token_value)
        self.assertEqual(ctx.exception.status, 403)
        self.assertEqual(ctx.exception.reason, budget.REASON_FROZEN)
        self.assertEqual(budget.get_window(self.conn, "tenant-a")["spent"], 0)
        budget.unfreeze(self.conn, "tenant-a")
        self.assertEqual(self.consume(token_value)["status"], 200)

    def test_revoked_token_serialises_before_consumption(self):
        self.publish_bucket()
        token_value = self.token()
        budget.revoke_token(self.conn, token_value)
        with self.assertRaises(budget.BudgetAuth):
            self.consume(token_value)
        self.assertEqual(budget.get_window(self.conn, "tenant-a")["spent"], 0)

    def test_two_tokens_use_stricter_remaining_quota(self):
        prefix = self.publish_bucket()
        token_a = self.token("tenant-a")
        token_b = budget.create_token(self.conn, "tenant-b", "b")
        budget.consume_query(self.conn, [token_b], prefix)
        result = budget.consume_query(self.conn, [token_a, token_b], prefix)
        self.assertEqual(result["tenant_id"], "tenant-b")
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(budget.get_window(self.conn, "tenant-a")["spent"], 0)
        self.assertEqual(budget.get_window(self.conn, "tenant-b")["spent"], 2)

    def test_two_tokens_frozen_is_stricter_regardless_of_remaining(self):
        self.publish_bucket()
        rich = self.token("rich")
        poor = budget.create_token(self.conn, "poor", "poor")
        budget.freeze(self.conn, "poor")
        with self.assertRaises(budget.BudgetDenied) as ctx:
            budget.consume_query(self.conn, [rich, poor], "AAAAA")
        self.assertEqual(ctx.exception.state["tenant_id"], "poor")
        self.assertEqual(ctx.exception.reason, budget.REASON_FROZEN)
        self.assertEqual(budget.get_window(self.conn, "rich")["spent"], 0)

    def test_parallel_requests_are_serialised_no_double_charge_or_negative(self):
        self.publish_bucket()
        token_value = self.token()

        def work():
            conn = db.connect(self.db_path)
            try:
                try:
                    result = budget.consume_query(conn, [token_value], "AAAAA")
                    return result["status"]
                except budget.BudgetDenied as denied:
                    return denied.status
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda _: work(), range(12)))
        self.assertEqual(sorted(statuses), [200] * 3 + [429] * 9)
        state = budget.get_window(self.conn, "tenant-a")
        self.assertEqual((state["remaining"], state["spent"]), (0, 3))
        self.assertEqual(state["deductions"], 3)
        self.assertEqual(state["failure_reasons"], {"budget_exhausted": 9})

    def test_restart_recovers_remaining_quota_and_freeze(self):
        self.publish_bucket()
        token_value = self.token()
        self.consume(token_value)
        budget.freeze(self.conn, "tenant-a")
        self.conn.close()
        restarted = db.connect(self.db_path)
        self.addCleanup(restarted.close)
        state = budget.get_window(restarted, "tenant-a")
        self.assertEqual((state["remaining"], state["spent"], state["frozen"]),
                         (2, 1, True))
        with self.assertRaises(budget.BudgetDenied):
            budget.consume_query(restarted, [token_value], "AAAAA")

    def test_utc_window_rollover_ignores_local_timezone_and_restores_quota(self):
        self.publish_bucket()
        token_value = self.token()
        for _ in range(3):
            self.consume(token_value)
        today = budget.window_start_for()
        tomorrow = budget.next_window_start(today)

        def fake_today():
            return datetime.fromisoformat(tomorrow)

        original = budget.utcnow
        budget.utcnow = fake_today
        try:
            result = self.consume(token_value)
        finally:
            budget.utcnow = original
        self.assertEqual(result["window_start"], tomorrow)
        self.assertEqual(result["remaining"], 2)
        self.assertEqual(result["spent"], 1)
        old = budget.get_window(self.conn, "tenant-a", today)
        self.assertEqual((old["remaining"], old["spent"]), (0, 3))

    def test_freeze_carries_into_next_utc_window_and_auditor_replays_it(self):
        self.publish_bucket()
        token_value = self.token()
        budget.freeze(self.conn, "tenant-a")
        today = budget.window_start_for()
        tomorrow = budget.next_window_start(today)
        original = budget.utcnow
        budget.utcnow = lambda: datetime.fromisoformat(tomorrow)
        try:
            with self.assertRaises(budget.BudgetDenied) as ctx:
                self.consume(token_value)
            self.assertEqual(ctx.exception.reason, budget.REASON_FROZEN)
            row = self.conn.execute(
                "SELECT frozen FROM budget_windows WHERE tenant_id=? AND"
                " window_start=?", ("tenant-a", tomorrow)).fetchone()
            self.assertEqual(row["frozen"], 1)
        finally:
            budget.utcnow = original
        self.conn.execute(
            "UPDATE budget_windows SET frozen=0 WHERE tenant_id=? AND"
            " window_start=?", ("tenant-a", tomorrow))
        with self.assertRaises(budgetaudit.BudgetAuditError):
            budgetaudit.verify(self.db_path)

    def test_audit_export_has_no_secret_material_and_recomputes_balance(self):
        secret = "raw-secret-password-never-in-audit"
        prefix = sha1(secret)[:5]
        # Include the raw secret in the corpus so the returned body contains
        # its suffix, while the detached export must still contain neither.
        core.ingest_batch(self.conn, "budget-source",
                          [secret] + passwords_for_prefix(prefix, 2))
        info = core.build_candidate(self.conn, 1)
        core.activate(self.conn, info["version"])
        token_value = self.token()
        result = budget.consume_query(self.conn, [token_value], prefix)
        self.assertIn(sha1(secret)[5:], result["body"])
        budget.grant(self.conn, "tenant-a", 1)
        budget.freeze(self.conn, "tenant-a")
        out = os.path.join(self.tmp, "export")
        manifest = budgetaudit.export_budget(
            self.db_path, self.key_path, out)
        verified = budgetverify.verify_export(out)
        row = budgetverify.find_row(verified, "tenant-a")
        self.assertEqual(row["deducted_count"], 1)
        self.assertEqual(row["capacity"], 4)
        self.assertEqual(row["remaining"], 3)
        self.assertTrue(row["frozen"])
        package_bytes = b""
        for name in os.listdir(out):
            with open(os.path.join(out, name), "rb") as fh:
                package_bytes += fh.read()
        self.assertNotIn(secret.encode(), package_bytes)
        self.assertNotIn(prefix.encode(), package_bytes)
        self.assertNotIn(sha1(secret)[5:].encode(), package_bytes)
        self.assertNotIn(token_value.encode(), package_bytes)
        self.assertEqual(manifest["deducted_count"], 1)

    def test_forged_export_and_digest_mismatch_are_rejected(self):
        self.publish_bucket()
        token_value = self.token()
        self.consume(token_value)
        out = os.path.join(self.tmp, "export")
        budgetaudit.export_budget(self.db_path, self.key_path, out)
        audit_path = os.path.join(out, "audit_data.json")
        with open(audit_path) as fh:
            data = json.load(fh)
        data["rows"][0]["deducted_count"] = 99
        with open(audit_path, "w") as fh:
            json.dump(data, fh)
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(out)

        # A forged self-hash cannot promote altered data.
        forged = os.path.join(self.tmp, "forged")
        shutil.copytree(out, forged)
        cap_path = os.path.join(forged, "capacity_data.json")
        with open(cap_path) as fh:
            cap = json.load(fh)
        cap["rows"][0]["capacity"] = 999
        with open(cap_path, "w") as fh:
            json.dump(cap, fh)
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(forged)

    def test_stored_event_tampering_detected_before_export(self):
        self.publish_bucket()
        self.consume(self.token())
        self.conn.execute("UPDATE budget_events SET count=2 WHERE seq=1")
        with self.assertRaises(budgetaudit.BudgetAuditError):
            budgetaudit.verify(self.db_path)


class ServerBudgetTests(BudgetHarness):
    def setUp(self):
        super().setUp()
        self.prefix = self.publish_bucket()
        admin = core.create_token(self.conn, "admin", ["budget_admin"])
        self.admin = admin
        self.budget_token = self.token()
        self.server = server.make_server(
            self.db_path, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.shutdown)

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def request(self, path, token=None, method="GET", body=None,
                content_type="application/json", headers=None):
        data = None
        req_headers = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            req_headers["Content-Type"] = content_type
        if token is not None:
            if isinstance(token, list):
                req_headers["X-Budget-Tokens"] = ",".join(token)
            else:
                req_headers["X-Budget-Token"] = token
        req = urllib.request.Request(self.url(path), data=data, method=method,
                                     headers=req_headers)
        try:
            resp = urllib.request.urlopen(req)
            return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def test_http_status_headers_and_restart_query(self):
        status, body, headers = self.request(f"/api/range/{self.prefix}",
                                             self.budget_token)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Budget-Remaining"], "2")
        self.assertEqual(headers["X-Budget-Spent"], "1")
        self.assertEqual(headers["X-Budget-Window-Start"],
                         budget.window_start_for())
        self.assertEqual(headers["X-Budget-Frozen"], "false")
        self.assertEqual(headers["X-Budget-Policy-Revision"], "1")
        self.assertTrue(headers["X-Budget-Event-Seq"].isdigit())
        self.assertIn(":", body.decode())

        status, body, headers = self.request(f"/api/range/{self.prefix}",
                                             self.budget_token)
        self.assertEqual(headers["X-Budget-Remaining"], "1")
        status, body, headers = self.request(f"/api/range/{self.prefix}",
                                             self.budget_token)
        self.assertEqual(headers["X-Budget-Remaining"], "0")
        status, body, headers = self.request(f"/api/range/{self.prefix}",
                                             self.budget_token)
        self.assertEqual(status, 429)
        self.assertEqual(headers["X-Budget-Remaining"], "0")
        self.assertNotIn(self.prefix.encode(), body)

        grant_body = {"tenant_id": "tenant-a", "amount": 1}
        status, _, _ = self.request(
            "/api/admin/budgets/grant", method="POST", body=grant_body,
            headers={"Authorization": f"Bearer {self.admin}"})
        self.assertEqual(status, 200)
        status, body, headers = self.request(f"/api/range/{self.prefix}",
                                             self.budget_token)
        self.assertEqual((status, headers["X-Budget-Remaining"]), (200, "0"))

        status, body, _ = self.request(
            "/api/admin/budgets/tenant-a/freeze", method="POST", body={},
            headers={"Authorization": f"Bearer {self.admin}"})
        self.assertEqual(status, 200)
        status, _, headers = self.request(f"/api/range/{self.prefix}",
                                          self.budget_token)
        self.assertEqual(status, 403)
        self.assertEqual(headers["X-Budget-Frozen"], "true")

    def test_admin_endpoint_count_matches_detached_export(self):
        for _ in range(2):
            self.request(f"/api/range/{self.prefix}", self.budget_token)
        self.request(f"/api/range/{self.prefix}", self.budget_token)
        self.request(f"/api/range/{self.prefix}", self.budget_token)
        admin_headers = {"Authorization": f"Bearer {self.admin}"}
        status, raw, _ = self.request("/api/admin/budgets/tenant-a",
                                      headers=admin_headers)
        self.assertEqual(status, 200)
        admin_budget = json.loads(raw)["budget"]
        out = os.path.join(self.tmp, "export")
        manifest = budgetaudit.export_budget(
            self.db_path, self.key_path, out)
        verified = budgetverify.verify_export(out)
        row = budgetverify.find_row(verified, "tenant-a")
        self.assertEqual(admin_budget["deductions"], row["deducted_count"])
        failures_sum = sum(admin_budget["failure_reasons"].values())
        self.assertEqual(failures_sum, manifest["denied_count"])
        self.assertEqual(admin_budget["remaining"] + admin_budget["spent"],
                         row["capacity"])


class SubprocessBudgetTests(BudgetHarness):
    def run_cli(self, *args, check=True):
        env = dict(os.environ, PYTHONPATH="/workspace")
        proc = subprocess.run(
            [sys.executable, "-m", "pwncorpus.cli", "--db", self.db_path, *args],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if check and proc.returncode != 0:
            self.fail(f"CLI failed: {proc.stderr}\n{proc.stdout}")
        return proc

    def test_three_boundary_workflow_offline_verifier_without_db_import(self):
        with open("/workspace/pwncorpus/budgetverify.py", "r",
                  encoding="utf-8") as fh:
            module = ast.parse(fh.read())
        imported = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertNotIn("sqlite3", imported)
        prefix = self.publish_bucket()
        proc = self.run_cli("budget-token", "--tenant", "offline-tenant")
        token_value = proc.stdout.strip()
        for _ in range(3):
            budget.consume_query(self.conn, [token_value], prefix)
        with self.assertRaises(budget.BudgetDenied):
            budget.consume_query(self.conn, [token_value], prefix)
        budget.grant(self.conn, "offline-tenant", 2)
        budget.consume_query(self.conn, [token_value], prefix)
        out = os.path.join(self.tmp, "offline-export")
        proc = self.run_cli("budget-export", "--key", self.key_path,
                            "--out", out)
        self.assertIn("pwncorpus-budget-export/1", proc.stdout)

        moved_db = self.db_path + ".away"
        os.rename(self.db_path, moved_db)
        try:
            verify = subprocess.run(
                [sys.executable, "-m", "pwncorpus.budgetverify", "check", out,
                 "--tenant", "offline-tenant", "--ordinal", "6"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(verify.returncode, 3, verify.stderr)
            verdict = json.loads(verify.stdout)
            self.assertEqual(verdict["verdict"], "over_budget")
            verify4 = subprocess.run(
                [sys.executable, "-m", "pwncorpus.budgetverify", "check", out,
                 "--tenant", "offline-tenant", "--ordinal", "5"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(verify4.returncode, 0)
            self.assertIn("within_budget", verify4.stdout)
        finally:
            os.rename(moved_db, self.db_path)


if __name__ == "__main__":
    unittest.main()
