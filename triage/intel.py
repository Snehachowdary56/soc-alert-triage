"""Small SAMPLE threat-intelligence and asset lists used for enrichment.

In a real company these would come from a threat-intel feed and the asset inventory.
IPs and domains use reserved documentation ranges (RFC 5737) and .example, so nothing is real.
"""

import ipaddress

BAD_IPS = {"198.51.100.23": "known command-and-control server", "203.0.113.200": "known scanner"}
BAD_DOMAINS = {"micros0ft-login.example": "look-alike of a Microsoft sign-in page",
               "payroll-update.example": "reported phishing domain"}
IP_COUNTRY = {"203.0.113.45": "RU", "198.51.100.23": "NL", "192.0.2.77": "BR", "203.0.113.200": "CN",
              "198.51.100.9": "US"}
HOME_COUNTRY = "CA"
PRIVILEGED_USERS = {"admin.ivan", "svc.backup"}
CRITICAL_HOSTS = {"SRV-FILE01", "SRV-DB02"}


INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str | None) -> bool:
    """True for company-internal (RFC 1918) addresses."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS)


def country(ip: str | None) -> str | None:
    if not ip:
        return None
    return HOME_COUNTRY if is_internal(ip) else IP_COUNTRY.get(ip, "unknown")
