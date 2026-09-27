import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store
from service import iso, now


class KeyIncidentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "degree", "required": True}], 365,
        )

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def _issue_token(self, holder="alice", key="issue-1"):
        credential = self.service.issue("issuer-a", "issuer", self.template["id"], holder, {"name": "Alice", "degree": "BSc"}, key)
        token = self.service.present(holder, "holder", credential["id"], None)["token"]
        return credential, token

    def _register(self, version=1, effective_at=None, **overrides):
        params = {
            "actor": "issuer-a", "role": "issuer", "issuer": "issuer-a", "key_version": version,
            "discovered_at": iso(now() - timedelta(hours=2)),
            "effective_at": effective_at or iso(now() - timedelta(hours=1)),
            "reason": "密钥版本疑似泄露",
        }
        params.update(overrides)
        return self.service.register_incident(
            params["actor"], params["role"], params["issuer"], params["key_version"],
            params["discovered_at"], params["effective_at"], params["reason"],
        )

    def test_incident_makes_only_its_key_version_unavailable(self):
        old_credential, old_token = self._issue_token()
        self.assertEqual("valid", self.service.verify(old_token)["status"])
        incident = self._register()
        self.assertEqual("open", incident["status"])
        result = self.service.verify(old_token)
        self.assertFalse(result["valid"])
        self.assertEqual("unavailable", result["status"])
        self.assertEqual(incident["id"], result["incident_id"])
        # 轮换后的新密钥版本签出的凭证不受影响
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        new_credential, new_token = self._issue_token("bob", "issue-2")
        self.assertEqual(2, new_credential["key_version"])
        self.assertTrue(self.service.verify(new_token)["valid"])
        # 旧版本凭证在事故生效前的时间点仍按原规则判定
        before = iso(now() - timedelta(hours=2))
        self.assertEqual("valid", self.service.verify(old_token, at=before)["status"])
        self.assertEqual(old_credential["id"], self.service._row("credentials", old_credential["id"])["id"])

    def test_incident_not_effective_until_effective_at(self):
        _, token = self._issue_token()
        future = iso(now() + timedelta(hours=1))
        self._register(effective_at=future)
        self.assertTrue(self.service.verify(token)["valid"])
        after = iso(now() + timedelta(hours=2))
        self.assertEqual("unavailable", self.service.verify(token, at=after)["status"])

    def test_only_one_open_incident_per_version(self):
        self._register()
        with self.assertRaises(ApiError) as ctx:
            self._register(reason="重复登记")
        self.assertEqual(409, ctx.exception.status)
        # 其他版本不受占用；关闭后可重新登记
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self._register(version=2)
        incident = self.service.store.open_incident("issuer-a", 1)
        closed = self.service.close_incident("issuer-a", "issuer", incident["id"], "withdraw", "误报")
        self.assertEqual("withdrawn", closed["status"])
        again = self._register(reason="确认泄露")
        self.assertEqual("open", again["status"])

    def test_close_rejudges_and_keeps_independent_revocation(self):
        revoked_credential, revoked_token = self._issue_token()
        _, active_token = self._issue_token("bob", "issue-2")
        self.service.revoke("issuer-a", "issuer", revoked_credential["id"], "持有人申请撤销")
        incident = self._register()
        self.assertEqual("unavailable", self.service.verify(revoked_token)["status"])
        self.assertEqual("unavailable", self.service.verify(active_token)["status"])
        # 更正事故后按撤销、争议和有效期重新判定，独立撤销记录保留
        closed = self.service.close_incident("issuer-a", "issuer", incident["id"], "correct", "已更换密钥并核对")
        self.assertEqual("corrected", closed["status"])
        revoked_result = self.service.verify(revoked_token)
        self.assertEqual("revoked", revoked_result["status"])
        self.assertEqual("持有人申请撤销", revoked_result["reason"])
        self.assertEqual("valid", self.service.verify(active_token)["status"])
        row = self.service._row("credentials", revoked_credential["id"])
        self.assertEqual("revoked", row["status"])
        self.assertEqual("持有人申请撤销", row["revocation_reason"])

    def test_incident_validation_and_permissions(self):
        with self.assertRaises(ApiError) as ctx:
            self._register(reason=" ")
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self._register(discovered_at=None)
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self._register(version=99)
        self.assertEqual(404, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self._register(actor="issuer-b", issuer="issuer-b")
        self.assertEqual(404, ctx.exception.status)  # issuer-b 没有该版本密钥
        with self.assertRaises(ApiError) as ctx:
            self._register(actor="issuer-b", issuer="issuer-a")
        self.assertEqual(403, ctx.exception.status)
        incident = self._register()
        with self.assertRaises(ApiError) as ctx:
            self.service.close_incident("issuer-a", "issuer", incident["id"], "erase")
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.service.close_incident("issuer-b", "issuer", incident["id"], "correct")
        self.assertEqual(403, ctx.exception.status)
        self.service.close_incident("issuer-a", "issuer", incident["id"], "correct")
        with self.assertRaises(ApiError) as ctx:
            self.service.close_incident("issuer-a", "issuer", incident["id"], "correct")
        self.assertEqual(409, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
