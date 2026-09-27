import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store


class CredentialFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def test_issue_minimal_disclosure_revoke_and_dispute(self):
        template = self.service.create_template("issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}], 365)
        credential = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1")
        self.assertEqual("active", credential["status"])
        proof = self.service.present("alice", "holder", credential["id"], ["name", "degree"])
        self.assertEqual({"name", "degree"}, set(proof["payload"]["claims"]))
        self.assertNotIn("gpa", proof["token"])
        self.assertEqual("valid_offline", self.service.verify(proof["token"], online=False)["status"])
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.assertTrue(self.service.verify(proof["token"])["key_retired"])
        self.service.revoke("issuer-a", "issuer", credential["id"], "持有人申请撤销")
        self.assertEqual("revoked", self.service.verify(proof["token"])["status"])
        dispute = self.service.dispute("alice", "holder", credential["id"], "撤销依据错误")
        result = self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销依据不足")
        self.assertEqual("active", result["credential_status"])

    def test_permissions_duplicate_and_stale_dispute(self):
        template = self.service.create_template("issuer-a", "issuer", "skill", "技能凭证", [{"name": "skill", "required": True}], 30)
        with self.assertRaises(ApiError):
            self.service.issue("issuer-b", "issuer", template["id"], "bob", {"skill": "Python"}, "x")
        first = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        second = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        self.assertEqual(first["id"], second["id"])
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "different-key")
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.service.dispute("charlie", "holder", first["id"], "冒名争议")


    def _isots(self, delta_seconds: int = 0) -> str:
        value = datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    def test_key_version_incident_makes_batch_unavailable(self):
        template = self.service.create_template("issuer-a", "issuer", "pass", "通行证", [{"name": "name", "required": True}], 30)
        v1_cred = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice"}, "v1")
        v1_token = self.service.present("alice", "holder", v1_cred["id"], ["name"])["token"]
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        v2_cred = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"name": "Bob"}, "v2")
        v2_token = self.service.present("bob", "holder", v2_cred["id"], ["name"])["token"]

        # 登记 v1 泄露事故，生效时间在 1 小时后。
        discovered = self._isots(-3600)
        effective = self._isots(3600)
        incident = self.service.incidents.register(
            "issuer-a", "issuer", "issuer-a", 1, "构建机被入侵，疑似私钥泄露", discovered, effective
        )
        self.assertEqual("open", incident["status"])
        self.assertEqual("INC-%04d" % incident["id"], incident["incident_no"])
        # 生效前：v1 凭证仍正常核验。
        self.assertEqual("valid", self.service.verify(v1_token, at=self._isots())["status"])
        # 生效后：v1 批次不可用并带事故编号；v2 版本不受影响。
        at = self._isots(7200)
        blocked = self.service.verify(v1_token, at=at)
        self.assertFalse(blocked["valid"])
        self.assertEqual("unavailable", blocked["status"])
        self.assertEqual(incident["incident_no"], blocked["incident_no"])
        self.assertTrue(self.service.verify(v2_token, at=at)["valid"])
        # 离线核验无法感知事故。
        self.assertEqual("valid_offline", self.service.verify(v1_token, at=at, online=False)["status"])

    def test_one_open_incident_per_version_and_owner_only(self):
        self.service.incidents.register("issuer-a", "issuer", "issuer-a", 1, "首次事故")
        with self.assertRaises(ApiError) as ctx:
            self.service.incidents.register("issuer-a", "issuer", "issuer-a", 1, "重复事故")
        self.assertEqual(409, ctx.exception.status)
        # 别的签发方不能登记或处理，不存在的版本 404，持有人角色被拒。
        with self.assertRaises(ApiError):
            self.service.incidents.register("issuer-b", "issuer", "issuer-b", 1, "他人事故")
        with self.assertRaises(ApiError):
            self.service.incidents.register("issuer-a", "issuer", "issuer-a", 99, "幽灵版本")
        with self.assertRaises(ApiError):
            self.service.incidents.register("alice", "holder", "issuer-a", 1, "越权事故")

    def test_incident_withdraw_reevaluates_without_touching_revocation(self):
        template = self.service.create_template("issuer-a", "issuer", "pass", "通行证", [{"name": "name", "required": True}], 30)
        credential = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice"}, "c1")
        token = self.service.present("alice", "holder", credential["id"], ["name"])["token"]
        incident = self.service.incidents.register("issuer-a", "issuer", "issuer-a", 1, "私钥泄露")
        self.assertEqual("unavailable", self.service.verify(token)["status"])
        # 独立撤销记录在事故期间仍然存在。
        self.service.revoke("issuer-a", "issuer", credential["id"], "持有人申请撤销")
        self.assertEqual("unavailable", self.service.verify(token)["status"])
        closed = self.service.incidents.close("issuer-a", "issuer", incident["id"], "withdraw", "确认为误报")
        self.assertEqual("withdrawn", closed["status"])
        # 撤回后按撤销/争议/有效期重新判定：撤销记录原样保留，凭证仍判撤销。
        result = self.service.verify(token)
        self.assertEqual("revoked", result["status"])
        self.assertFalse(result["valid"])
        self.assertEqual("持有人申请撤销", result["reason"])
        self.assertNotIn("incident_no", result)
        # 已关闭事故不能再处理，且同一版本可以重新登记事故。
        with self.assertRaises(ApiError):
            self.service.incidents.close("issuer-a", "issuer", incident["id"], "correct", "重复关闭")
        again = self.service.incidents.register("issuer-a", "issuer", "issuer-a", 1, "再次确认泄露")
        self.assertEqual("open", again["status"])

    def test_incident_correct_then_dispute_reject_restores_active(self):
        template = self.service.create_template("issuer-a", "issuer", "pass", "通行证", [{"name": "name", "required": True}], 30)
        credential = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice"}, "c1")
        token = self.service.present("alice", "holder", credential["id"], ["name"])["token"]
        incident = self.service.incidents.register("issuer-a", "issuer", "issuer-a", 1, "私钥泄露")
        self.assertEqual("unavailable", self.service.verify(token)["status"])
        # 更正事故：凭证没有独立撤销记录，恢复后按有效期判定为有效。
        self.service.incidents.close("issuer-a", "issuer", incident["id"], "correct", "事故影响范围更正，撤销该批次封禁")
        self.assertTrue(self.service.verify(token)["valid"])
        # 撤销 -> 争议 -> 监管驳回撤销：最终回到 active，说明判定链路未受事故残留影响。
        self.service.revoke("issuer-a", "issuer", credential["id"], "误操作")
        self.assertEqual("revoked", self.service.verify(token)["status"])
        dispute = self.service.dispute("alice", "holder", credential["id"], "撤销误操作")
        self.assertEqual("disputed", self.service.verify(token)["status"])
        decision = self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销不成立")
        self.assertEqual("active", decision["credential_status"])
        self.assertTrue(self.service.verify(token)["valid"])


if __name__ == "__main__":
    unittest.main()
