"""Available checks, in the order they run."""

from secscan.checks.base import Check, ScanConfig, ScanContext
from secscan.checks.headers import HeaderCheck
from secscan.checks.ports import PortCheck
from secscan.checks.tls import TLSCheck

CHECKS: dict[str, type[Check]] = {
    PortCheck.name: PortCheck,
    TLSCheck.name: TLSCheck,
    HeaderCheck.name: HeaderCheck,
}

__all__ = ["CHECKS", "Check", "HeaderCheck", "PortCheck", "ScanConfig", "ScanContext", "TLSCheck"]
