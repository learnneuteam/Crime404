"""
CRIME404 Role-Based Access Control (RBAC), Case-Level Permissions & Multi-Tenancy
(Checklist Section 2 & 9.7)
Roles:
- system_admin: Full platform, org, user/role management, audit & backup access.
- lead_investigator: Create/manage cases, assign case members, approve sensitive actions, export.
- investigator: Upload evidence, add notes, compare, run reassessment on assigned cases.
- evidence_reviewer: Verify integrity, review/approve sensitive actions, view custody & audit logs.
- read_only_auditor: Read-only access to assigned/org cases, custody, and audit logs.
"""

from typing import Dict, Set, Tuple, Optional


ROLES = (
    "system_admin",
    "lead_investigator",
    "investigator",
    "evidence_reviewer",
    "read_only_auditor",
)

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "system_admin": {
        "case:create", "case:read", "case:update", "case:delete", "case:assign",
        "evidence:upload", "evidence:read", "evidence:download", "evidence:exclude",
        "evidence:approve_sensitive", "evidence:dispose", "evidence:note",
        "audit:read", "audit:verify", "admin:manage_roles", "backup:manage",
        "export:report",
    },
    "lead_investigator": {
        "case:create", "case:read", "case:update", "case:delete", "case:assign",
        "evidence:upload", "evidence:read", "evidence:download", "evidence:exclude",
        "evidence:approve_sensitive", "evidence:note",
        "audit:read", "audit:verify", "export:report",
    },
    "investigator": {
        "case:create", "case:read", "case:update", "case:delete",
        "evidence:upload", "evidence:read", "evidence:download", "evidence:exclude",
        "evidence:note", "export:report",
    },
    "evidence_reviewer": {
        "case:read",
        "evidence:read", "evidence:download", "evidence:approve_sensitive",
        "audit:read", "audit:verify", "export:report",
    },
    "read_only_auditor": {
        "case:read",
        "evidence:read",
        "audit:read", "audit:verify",
    },
}


def is_valid_role(role: str) -> bool:
    return role in ROLE_PERMISSIONS


def role_has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role or "", set())


def check_user_case_permission(
    user,
    case,
    permission: str,
    membership=None,
) -> Tuple[bool, str]:
    """
    Enforces multi-tenancy (org isolation), role-based permissions, and case-level membership.
    - Users cannot access cases in another organization.
    - system_admin within the same org has org-wide case access.
    - Other roles require either case ownership (case.user_id == user.id) or an active
      CaseMembership record.
    - Effective role is the CaseMembership.role_override if present, else user.role.
    """
    if not user or not getattr(user, "is_active", True):
        return False, "Account is inactive or suspended."
    if not case:
        return False, "Case not found."

    # Multi-tenant organization isolation
    if getattr(user, "org_id", None) != getattr(case, "org_id", None):
        return False, "Cross-organization access denied."

    effective_role = user.role or "investigator"
    if user.role == "system_admin":
        if role_has_permission("system_admin", permission):
            return True, "Authorized (system_admin)."
        return False, f"Permission '{permission}' denied."

    # Must be case owner or explicitly assigned active member
    is_owner = (case.user_id == user.id)
    if not is_owner:
        if not membership or not getattr(membership, "is_active", False):
            return False, "Case-level access denied: not assigned to this case."
        if membership.role_override and is_valid_role(membership.role_override):
            effective_role = membership.role_override

    if not role_has_permission(effective_role, permission):
        return False, f"Role '{effective_role}' lacks permission '{permission}'."

    return True, f"Authorized ({effective_role})."


def can_modify_user_role(actor, target_user_id: int, new_role: str) -> Tuple[bool, str]:
    """Prevents self-privilege escalation and restricts role changes to system_admin."""
    if not actor or actor.role != "system_admin":
        return False, "Only a system_admin can modify user roles."
    if actor.id == target_user_id:
        return False, "Self-privilege modification is prohibited."
    if not is_valid_role(new_role):
        return False, f"Invalid role '{new_role}'."
    return True, "OK"
