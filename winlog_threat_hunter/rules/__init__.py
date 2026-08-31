from .brute_force import BruteForceRule
from .privilege_escalation import PrivilegeEscalationRule
from .suspicious_process import SuspiciousProcessRule
from .persistence import AdminPersistenceRule

ALL_RULES = [
    BruteForceRule(),
    PrivilegeEscalationRule(),
    SuspiciousProcessRule(),
    AdminPersistenceRule(),
]

__all__ = ["ALL_RULES", "BruteForceRule", "PrivilegeEscalationRule", "SuspiciousProcessRule", "AdminPersistenceRule"]
