"""评审人利益冲突：分派前拦截、申报即失权、管理员解除必须留理由。

覆盖需求：
- 秘书处在分派前申报冲突；Python 分派接口拒绝存在未解除冲突的评审人；
- 申报成为 SQLite 事件（reviewer_conflicts），并改变可见范围：原评审人
  连案件本身都不能再读取（包视图/内容下载/分配列表/继续评审全部拒绝）；
- 管理员解除冲突必须填写理由，理由与操作人落库并进入审计日志；解除后
  可见性与可分派性恢复。
"""
import unittest

from service_09252_006.domain.enums import Role
from service_09252_006.domain.errors import (
    ConflictError,
    PermissionDeniedError,
    ValidationError,
)
from tests.flow import seal_new_package
from tests.support import Harness


class ConflictOfInterestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.reviewer2 = self.h.user(
            "rev-2", Role.REVIEWER, institution_id="inst-ext2"
        )
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id
        # items[0] 非敏感大纲，items[1] 敏感企业反馈
        self.normal_version = self.sealed.items[0].version["version_id"]
        self.sensitive_version = self.sealed.items[1].version["version_id"]

    def tearDown(self) -> None:
        self.h.close()

    # ------------------------------------------------------- 分派前拦截
    def test_assignment_rejected_when_conflict_declared_before_dispatch(self) -> None:
        result = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="评审人近三年在送审企业任顾问",
        )
        self.assertEqual(result["status"], "open")
        self.assertEqual(result["reason"], "评审人近三年在送审企业任顾问")

        with self.assertRaises(ConflictError) as cm:
            self.h.ctx.reviews.assign_reviewer(
                self.authority,
                package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
            )
        self.assertEqual(cm.exception.details["reviewer_id"], self.reviewer.user_id)
        # 被拦截的评审人没有产生任何请求
        self.assertEqual(self.h.repo.list_requests_by_package(self.pid), [])

    def test_conflict_blocks_assignment_even_without_existing_request(self) -> None:
        # 从未分配过的评审人，申报后同样不能分派，也不能读取案件
        self.h.ctx.reviews.declare_conflict(
            self.admin,
            package_id=self.pid,
            reviewer_id=self.reviewer2.user_id,
            reason="配偶持有送审机构股份",
        )
        with self.assertRaises(ConflictError):
            self.h.ctx.reviews.assign_reviewer(
                self.admin,
                package_id=self.pid,
                reviewer_id=self.reviewer2.user_id,
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.reviewer2, self.pid)

    # ------------------------------------------------------- 申报即失权
    def test_declaring_conflict_after_assignment_revokes_all_case_access(self) -> None:
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        rid = req["request_id"]
        self.h.ctx.reviews.respond_assignment(
            self.reviewer, request_id=rid, accept=True
        )
        # 申报前可正常读取与下载
        view = self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        self.assertFalse(view["entries"][1]["redacted"])

        # 秘书处事后核对发现冲突并申报
        self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="发现评审人参与了该课程的联合研发",
        )

        # 包视图：连案件本身都不能打开
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        # 下载：敏感与非敏感内容一律拒绝
        for vid in (self.sensitive_version, self.normal_version):
            with self.assertRaises(PermissionDeniedError):
                self.h.ctx.packages.download_entry(
                    self.reviewer, package_id=self.pid, version_id=vid
                )
        # 分配列表不可读
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.list_requests(self.reviewer, self.pid)
        # 不能继续在该请求上操作（响应/异议/结论）
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.respond_assignment(
                self.reviewer, request_id=rid, accept=True
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.record_objection(
                self.reviewer,
                request_id=rid,
                category="材料问题",
                detail="无法继续评审",
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.submit_verdict(
                self.reviewer, request_id=rid, verdict="approve"
            )

    def test_other_reviewer_and_roles_unaffected_by_someone_elses_conflict(self) -> None:
        req2 = self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer2.user_id,
        )
        self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="仅 rev-1 有冲突",
        )
        # rev-2 的有效分配与访问不受影响
        view = self.h.ctx.packages.build_package_view(self.reviewer2, self.pid)
        self.assertFalse(view["entries"][1]["redacted"])
        self.h.ctx.reviews.respond_assignment(
            self.reviewer2, request_id=req2["request_id"], accept=True
        )

    # ------------------------------------------------- SQLite 事件与审计
    def test_conflict_is_persisted_as_sqlite_event(self) -> None:
        before = self.h.ctx.reviews.declare_conflict(
            self.admin,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="与送审机构存在咨询合同",
        )
        cid = before["conflict_id"]

        # 直接以只读 SQL 核验事件落库
        import sqlite3

        conn = sqlite3.connect(
            f"file:{self.h.db_path}?mode=ro", uri=True
        )
        try:
            row = conn.execute(
                "SELECT conflict_id, package_id, institution_id, reviewer_id,"
                " status, reason, declared_by, resolved_by, resolved_at,"
                " resolution_note FROM reviewer_conflicts WHERE conflict_id = ?",
                (cid,),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], cid)
        self.assertEqual(row[1], self.pid)
        self.assertEqual(row[2], "inst-a")
        self.assertEqual(row[3], self.reviewer.user_id)
        self.assertEqual(row[4], "open")
        self.assertEqual(row[5], "与送审机构存在咨询合同")
        self.assertEqual(row[6], self.admin.user_id)
        self.assertIsNone(row[7])
        self.assertIsNone(row[8])
        self.assertIsNone(row[9])

        audit = self.h.repo.list_audit(self.pid)
        actions = {a.action: a.detail for a in audit}
        self.assertIn("review.conflict_declared", actions)
        self.assertEqual(actions["review.conflict_declared"]["reason"], "与送审机构存在咨询合同")

    def test_duplicate_declaration_is_idempotent(self) -> None:
        first = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="同一冲突",
            idempotency_key="coi-1",
        )
        second = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="同一冲突",
            idempotency_key="coi-1",
        )
        self.assertEqual(first["conflict_id"], second["conflict_id"])
        self.assertTrue(second["replayed"])
        # 无幂等键的重复申报也回放既有 open 事件，不产生第二条
        third = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="同一冲突",
        )
        self.assertEqual(third["conflict_id"], first["conflict_id"])
        self.assertEqual(
            len(self.h.repo.list_conflicts(self.pid, self.reviewer.user_id)), 1
        )

    # ------------------------------------------------- 管理员解除须留理由
    def test_resolve_conflict_requires_reason(self) -> None:
        declared = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="疑似关联",
        )
        for bad in ("", "   "):
            with self.assertRaises(ValidationError):
                self.h.ctx.reviews.resolve_conflict(
                    self.admin,
                    conflict_id=declared["conflict_id"],
                    resolution_note=bad,
                )

    def test_admin_resolution_with_reason_persists_and_restores_access(self) -> None:
        self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        declared = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="疑似关联",
        )
        # 解除前不能读取也不能分派
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.reviewer, self.pid)

        resolved = self.h.ctx.reviews.resolve_conflict(
            self.admin,
            conflict_id=declared["conflict_id"],
            resolution_note="经核验咨询合同已于评审前到期，不构成利益冲突",
        )
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolved_by"], self.admin.user_id)
        self.assertIsNotNone(resolved["resolved_at"])
        self.assertEqual(
            resolved["resolution_note"],
            "经核验咨询合同已于评审前到期，不构成利益冲突",
        )

        # 解除理由与操作人作为事件状态落库
        import sqlite3

        conn = sqlite3.connect(f"file:{self.h.db_path}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT status, resolved_by, resolution_note FROM reviewer_conflicts"
                " WHERE conflict_id = ?",
                (declared["conflict_id"],),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "resolved")
        self.assertEqual(row[1], self.admin.user_id)
        self.assertTrue(row[2])

        audit = {
            a.action: a.detail for a in self.h.repo.list_audit(self.pid)
        }
        self.assertIn("review.conflict_resolved", audit)
        self.assertTrue(audit["review.conflict_resolved"]["resolution_note"])
        self.assertEqual(
            audit["review.conflict_resolved"]["reviewer_id"], self.reviewer.user_id
        )

        # 可见性恢复；分派不再被拦截（同一评审人重新分派成功）
        view = self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        self.assertFalse(view["entries"][1]["redacted"])
        new_req = self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        self.assertEqual(new_req["status"], "pending")

    def test_resolve_is_idempotent_and_cannot_be_replayed_without_note_first_time(
        self,
    ) -> None:
        declared = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="疑似关联",
        )
        self.h.ctx.reviews.resolve_conflict(
            self.admin,
            conflict_id=declared["conflict_id"],
            resolution_note="核实无关联",
            idempotency_key="resolve-1",
        )
        # 已解除后，即便重放不带理由的幂等键也回放首次结果，不产生新事件
        again = self.h.ctx.reviews.resolve_conflict(
            self.admin,
            conflict_id=declared["conflict_id"],
            resolution_note="核实无关联",
            idempotency_key="resolve-1",
        )
        self.assertTrue(again["replayed"])
        self.assertEqual(
            len(self.h.repo.list_conflicts(self.pid, self.reviewer.user_id)), 1
        )

    # ----------------------------------------------------------- 权限边界
    def test_only_managing_roles_can_declare_or_resolve(self) -> None:
        # 提交人无权申报
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.declare_conflict(
                self.submitter,
                package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
                reason="提交人不该操作",
            )
        declared = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="跨机构解除测试",
        )
        # 其他机构管理员不能解除
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.resolve_conflict(
                self.admin_b,
                conflict_id=declared["conflict_id"],
                resolution_note="外机构管理员的理由",
            )
        # 其他机构管理员也不能申报本机构案件
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.declare_conflict(
                self.admin_b,
                package_id=self.pid,
                reviewer_id=self.reviewer2.user_id,
                reason="外机构申报",
            )

    def test_redeclare_after_resolution_creates_new_open_event(self) -> None:
        first = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="第一次冲突",
        )
        self.h.ctx.reviews.resolve_conflict(
            self.admin, conflict_id=first["conflict_id"], resolution_note="已排除"
        )
        # 解除后再次发现冲突：追加新的 open 事件，分派重新被拦截
        second = self.h.ctx.reviews.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="新发现的关联",
        )
        self.assertNotEqual(second["conflict_id"], first["conflict_id"])
        self.assertEqual(second["status"], "open")
        with self.assertRaises(ConflictError):
            self.h.ctx.reviews.assign_reviewer(
                self.authority,
                package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
            )


if __name__ == "__main__":
    unittest.main()
