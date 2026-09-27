"""评审人利益冲突服务。

案件分派前，秘书处（质量权威机构或送审机构管理员）先登记/核对评审人的
利益冲突：

- 申报（declared）是**追加事件**（reviewer_conflict_events 表），不修改
  历史；当前状态由同一 (package, reviewer) 的最新事件推导；
- 申报后该评审人对该案件**即刻失权**：包视图与内容下载被拒，即便已有
  仍有效的分配；该评审人对该包的评审动作（响应/异议/结论）也被拦截；
- Python 分派接口对处于冲突中的评审人直接拒绝；
- 解除（cleared）同样是追加事件，且必须给出理由；
- 两类管理操作都强制要求理由，理由随事件与审计日志留存。
"""
from __future__ import annotations

from ..domain.enums import ConflictEventType, Role
from ..domain.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.models import ConflictEvent, User
from .base import Service, require_roles


class ConflictService(Service):
    # --------------------------------------------------------------- 申报
    def declare_conflict(
        self,
        actor: User,
        *,
        package_id: str,
        reviewer_id: str,
        reason: str,
        idempotency_key: str | None = None,
    ) -> dict:
        return self._record_event(
            actor,
            package_id=package_id,
            reviewer_id=reviewer_id,
            reason=reason,
            event_type=ConflictEventType.DECLARED,
            action="review.conflict_declared",
            already_msg="该评审人对此案件已处于利益冲突状态",
            idempotency_key=idempotency_key,
        )

    # --------------------------------------------------------------- 解除
    def clear_conflict(
        self,
        actor: User,
        *,
        package_id: str,
        reviewer_id: str,
        reason: str,
        idempotency_key: str | None = None,
    ) -> dict:
        return self._record_event(
            actor,
            package_id=package_id,
            reviewer_id=reviewer_id,
            reason=reason,
            event_type=ConflictEventType.CLEARED,
            action="review.conflict_cleared",
            already_msg="该评审人对此案件不存在待解除的利益冲突",
            idempotency_key=idempotency_key,
        )

    def _record_event(
        self,
        actor: User,
        *,
        package_id: str,
        reviewer_id: str,
        reason: str,
        event_type: ConflictEventType,
        action: str,
        already_msg: str,
        idempotency_key: str | None,
    ) -> dict:
        require_roles(actor, Role.QUALITY_AUTHORITY, Role.INSTITUTION_ADMIN)
        # 管理操作必须留下理由（服务层强制，不依赖接口层）
        if not reason or not reason.strip():
            raise ValidationError("利益冲突操作必须填写理由")

        def work() -> dict:
            package = self.repo.get_package(package_id)
            if package is None:
                raise NotFoundError("评审包不存在")
            if (
                not actor.has_role(Role.QUALITY_AUTHORITY)
                and package.institution_id != actor.institution_id
            ):
                raise PermissionDeniedError("只能登记本机构评审包的利益冲突")

            reviewer = self.repo.get_user(reviewer_id)
            if reviewer is None or not reviewer.has_role(Role.REVIEWER):
                raise ValidationError(
                    "对象不是评审人", details={"reviewer_id": reviewer_id}
                )

            events = self.repo.list_conflict_events(package_id, reviewer_id)
            latest = events[-1].event_type if events else None
            declared = ConflictEventType.DECLARED.value
            if event_type is ConflictEventType.DECLARED and latest == declared:
                raise ConflictError(already_msg)
            if event_type is ConflictEventType.CLEARED and latest != declared:
                raise ConflictError(already_msg)

            event = ConflictEvent(
                event_id=self.ids.new_id("cfl"),
                package_id=package_id,
                institution_id=package.institution_id,
                reviewer_id=reviewer_id,
                event_type=event_type.value,
                reason=reason.strip(),
                declared_by=actor.user_id,
                created_at=self.clock.now_iso(),
            )
            self.repo.insert_conflict_event(event)
            self.audit(
                actor.user_id,
                action,
                package_id=package_id,
                institution_id=package.institution_id,
                detail={
                    "event_id": event.event_id,
                    "reviewer_id": reviewer_id,
                    "reason": event.reason,
                },
            )
            return self._event_dict(event)

        return self.idempotent(idempotency_key, work)

    # --------------------------------------------------------------- 查询
    def list_conflicts(self, actor: User, package_id: str) -> dict:
        """秘书处（权威机构/本机构管理员）与审计核对分派前的冲突记录。"""
        require_roles(
            actor,
            Role.QUALITY_AUTHORITY,
            Role.INSTITUTION_ADMIN,
            Role.AUDITOR,
        )
        package = self.repo.get_package(package_id)
        if package is None:
            raise NotFoundError("评审包不存在")
        if (
            not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
            and package.institution_id != actor.institution_id
        ):
            raise PermissionDeniedError("不能查看其他机构评审包的利益冲突记录")
        events = self.repo.list_conflict_events(package_id)
        return {
            "package_id": package_id,
            "conflicts": [self._event_dict(e) for e in events],
        }

    def is_conflicted(self, package_id: str, reviewer_id: str) -> bool:
        """分派前拦截用：该评审人对该包当前是否处于已申报未解除的冲突。"""
        return package_id in set(
            self.repo.list_active_conflict_package_ids(reviewer_id)
        )

    @staticmethod
    def _event_dict(e: ConflictEvent, *, replayed: bool = False) -> dict:
        return {
            "event_id": e.event_id,
            "package_id": e.package_id,
            "reviewer_id": e.reviewer_id,
            "event_type": e.event_type,
            "reason": e.reason,
            "declared_by": e.declared_by,
            "created_at": e.created_at,
            "replayed": replayed,
        }
