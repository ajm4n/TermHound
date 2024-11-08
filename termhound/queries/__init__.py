"""Query modules for TermHound."""

from .certificate_queries import CertificateQueries
from .domain_queries import DomainQueries
from .kerberos_queries import KerberosQueries
from .privilege_queries import PrivilegeQueries

__all__ = [
    "CertificateQueries",
    "DomainQueries",
    "KerberosQueries",
    "PrivilegeQueries"
]
