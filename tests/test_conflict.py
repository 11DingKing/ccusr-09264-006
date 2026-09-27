"""评审人利益冲突：分派前拦截、事件流、可见范围收回、管理操作留理由。"""
import unittest

from service_09252_006.domain.enums import Role
from service_09252_006.domain.errors import (
    PermissionDeniedError,
    ReviewerConflictError,
    ValidationError,
)
from tests.flow import seal_new_package
from tests.support import Harness


class ConflictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.admin_b = self.h.user(
            "admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b"
        )
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.reviewer = self.h.user(
            "rev-1", Role.REVIEWER, institution_id="inst-ext"
        )
        self.reviewer2 = self.h.user(
            "rev-2", Role.REVIEWER, institution_id="inst-ext2"
        )
        self.sealed = seal_new_package(self.h, self.admin)
        self.pid = self.sealed.package_id
        self.sensitive_version = self.sealed.items[1].version["version_id"]

    def tearDown(self) -> None:
        self.h.close()

    # ------------------------------------------------- 分派前拦截
    def test_declared_conflict_blocks_assignment(self) -> None:
        result = self.h.ctx.conflicts.declare_conflict(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="评审人近三年在送审机构兼职",
        )
        self.assertEqual(result["event_type"], "declared")

        # Python 分派接口直接拒绝冲突评审人
        with self.assertRaises(ReviewerConflictError):
            self.h.ctx.reviews.assign_reviewer(
                self.authority,
                package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
            )
        # 其他无冲突评审人仍可分派
        ok = self.h.ctx.reviews.assign_reviewer(
            self.authority,
            package_id=self.pid,
            reviewer_id=self.reviewer2.user_id,
        )
        self.assertTrue(ok["request_id"])

    def test_declaration_is_appended_event_and_current_state_derived(self) -> None:
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="持有送审机构股份",
        )
        self.assertTrue(
            self.h.ctx.conflicts.is_conflicted(self.pid, self.reviewer.user_id)
        )
        events = self.h.repo.list_conflict_events(self.pid, self.reviewer.user_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "declared")

    def test_duplicate_declaration_rejected(self) -> None:
        kwargs = dict(
            package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
            reason="亲属在送审机构任职",
        )
        self.h.ctx.conflicts.declare_conflict(self.authority, **kwargs)
        from service_09252_006.domain.errors import ConflictError

        with self.assertRaises(ConflictError):
            self.h.ctx.conflicts.declare_conflict(self.authority, **kwargs)
        # 仍然只有一条事件（不是更新覆盖）
        self.assertEqual(
            len(self.h.repo.list_conflict_events(self.pid, self.reviewer.user_id)),
            1,
        )

    # ------------------------------------------------- 管理操作必须有理由
    def test_declare_requires_reason(self) -> None:
        for bad in ("", "   "):
            with self.assertRaises(ValidationError):
                self.h.ctx.conflicts.declare_conflict(
                    self.authority,
                    package_id=self.pid,
                    reviewer_id=self.reviewer.user_id,
                    reason=bad,
                )

    def test_clear_requires_reason(self) -> None:
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="师生关系",
        )
        with self.assertRaises(ValidationError):
            self.h.ctx.conflicts.clear_conflict(
                self.authority,
                package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
                reason="",
            )

    def test_admin_actions_record_reason_in_audit(self) -> None:
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="理由 A：兼职",
        )
        self.h.ctx.conflicts.clear_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="理由 B：兼职已结束",
        )
        audit = self.h.repo.list_audit(self.pid)
        actions = {a.action: a for a in audit}
        self.assertIn("review.conflict_declared", actions)
        self.assertIn("review.conflict_cleared", actions)
        self.assertEqual(
            actions["review.conflict_declared"].detail["reason"], "理由 A：兼职"
        )
        self.assertEqual(
            actions["review.conflict_cleared"].detail["reason"], "理由 B：兼职已结束"
        )
        self.assertEqual(
            actions["review.conflict_declared"].detail["reviewer_id"],
            self.reviewer.user_id,
        )

    def test_institution_admin_may_declare_for_own_package_only(self) -> None:
        # 本机构管理员可申报
        self.h.ctx.conflicts.declare_conflict(
            self.admin, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="本机构管理员核对发现",
        )
        # 其他机构管理员不可申报
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.conflicts.declare_conflict(
                self.admin_b, package_id=self.pid,
                reviewer_id=self.reviewer2.user_id, reason="越权",
            )

    def test_non_admin_cannot_declare(self) -> None:
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.conflicts.declare_conflict(
                self.reviewer, package_id=self.pid,
                reviewer_id=self.reviewer.user_id, reason="自己申报也不行",
            )

    # ------------------------------------------------- 申报后即刻失权
    def test_conflict_revokes_access_even_with_active_assignment(self) -> None:
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        rid = req["request_id"]
        # 分配后可见
        view = self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        self.assertFalse(any(e["redacted"] for e in view["entries"]))

        # 秘书处申报冲突
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="评审中途发现利益关系",
        )

        # 整个案件不能再读（包视图、下载、分配情况）
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.packages.download_entry(
                self.reviewer,
                package_id=self.pid,
                version_id=self.sensitive_version,
            )
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.reviews.list_requests(self.reviewer, self.pid)

        # 评审动作也被拦截：响应、异议、结论
        with self.assertRaises(ReviewerConflictError):
            self.h.ctx.reviews.respond_assignment(
                self.reviewer, request_id=rid, accept=True
            )

    def test_conflict_blocks_objection_and_verdict_after_acceptance(self) -> None:
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        rid = req["request_id"]
        self.h.ctx.reviews.respond_assignment(
            self.reviewer, request_id=rid, accept=True
        )
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="新发现的利益关系",
        )
        with self.assertRaises(ReviewerConflictError):
            self.h.ctx.reviews.record_objection(
                self.reviewer, request_id=rid, category="x", detail="y"
            )
        with self.assertRaises(ReviewerConflictError):
            self.h.ctx.reviews.submit_verdict(
                self.reviewer, request_id=rid, verdict="approve"
            )

    # ------------------------------------------------- 解除恢复
    def test_clear_restores_assignment_and_visibility(self) -> None:
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="冲突",
        )
        with self.assertRaises(ReviewerConflictError):
            self.h.ctx.reviews.assign_reviewer(
                self.authority, package_id=self.pid,
                reviewer_id=self.reviewer.user_id,
            )
        self.h.ctx.conflicts.clear_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="冲突情形已消除并复核",
        )
        self.assertFalse(
            self.h.ctx.conflicts.is_conflicted(self.pid, self.reviewer.user_id)
        )
        # 事件流追加：两条；最新状态为 cleared
        events = self.h.repo.list_conflict_events(self.pid, self.reviewer.user_id)
        self.assertEqual([e.event_type for e in events], ["declared", "cleared"])

        # 可重新分派、可读
        req = self.h.ctx.reviews.assign_reviewer(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id,
        )
        self.assertTrue(req["request_id"])
        view = self.h.ctx.packages.build_package_view(self.reviewer, self.pid)
        self.assertFalse(any(e["redacted"] for e in view["entries"]))

    def test_clear_without_active_conflict_rejected(self) -> None:
        from service_09252_006.domain.errors import ConflictError

        with self.assertRaises(ConflictError):
            self.h.ctx.conflicts.clear_conflict(
                self.authority, package_id=self.pid,
                reviewer_id=self.reviewer.user_id, reason="无的放矢",
            )

    # ------------------------------------------------- 查询
    def test_list_conflicts_for_secretariat(self) -> None:
        self.h.ctx.conflicts.declare_conflict(
            self.authority, package_id=self.pid,
            reviewer_id=self.reviewer.user_id, reason="核对记录",
        )
        for actor in (self.authority, self.admin):
            view = self.h.ctx.conflicts.list_conflicts(actor, self.pid)
            self.assertEqual(len(view["conflicts"]), 1)
            self.assertEqual(view["conflicts"][0]["reason"], "核对记录")

        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.conflicts.list_conflicts(self.admin_b, self.pid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.conflicts.list_conflicts(self.reviewer, self.pid)


if __name__ == "__main__":
    unittest.main()
