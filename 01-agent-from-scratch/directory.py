"""
The agent's two lookup tools (stage 2): who is this account, and what is this
machine. Both read-only.

Accounts come from Active Directory on DC01, over LDAPS (port 636), signed in as
the agent's own AD account, svc-ask-siem (Domain Users, nothing more).

Machines come from assets.json, the lab inventory, because most lab machines are
Linux or appliances that AD has never heard of, and AD does not store IP
addresses at all. Machines that did join the domain get their AD details added.

ACCOUNT_ATTRIBUTES and HOST_ATTRIBUTES are allow-lists, like FIELDS for Wazuh.
Any signed-in account can read most of AD, so AD will not limit what the agent
sees: these lists do. Attributes that hold secrets (LAPS passwords, BitLocker
recovery keys, gMSA passwords) are never asked for, so they cannot leak even if
AD's own permissions are one day set wrong.
"""

import ipaddress
import json
import os
import re
import ssl
from pathlib import Path

from ldap3 import Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

from redact import clean  # AD descriptions are free text: same filter as command lines.

HERE = Path(__file__).resolve().parent

# It must be the name, not 192.168.50.2: DC01's certificate is issued to this
# name, and the check compares exactly.
DC01 = "DC01.corp.biirabank.com"
BIIRA_CA = HERE / "certs" / "biira-root-ca.pem"  # CA01's public root certificate
BASE = "DC=corp,DC=biirabank,DC=com"  # Search the whole domain
INVENTORY = HERE / "assets.json"

# The only attributes ever read. Nothing else is asked for, so nothing else can leave.
ACCOUNT_ATTRIBUTES = ["sAMAccountName", "objectClass", "displayName", "userPrincipalName",
                      "description", "memberOf", "primaryGroupID", "userAccountControl",
                      "whenCreated", "lastLogonTimestamp", "pwdLastSet"]
HOST_ATTRIBUTES = ["dNSHostName", "operatingSystem", "operatingSystemVersion", "description",
                   "userAccountControl", "whenCreated", "lastLogonTimestamp"]

# userAccountControl is one number holding many on/off switches. These are the ones worth reporting.
DISABLED = 0x2
PASSWORD_NEVER_EXPIRES = 0x10000
NOT_DELEGATED = 0x100000  # "Account is sensitive and cannot be delegated"

# memberOf never lists an account's primary group. AD stores it as a number instead.
PRIMARY_GROUPS = {513: "Domain Users", 515: "Domain Computers", 516: "Domain Controllers"}

# A Windows account name: up to 20 plain characters, plus $ for a computer account.
# Anything else is refused before it gets near a search.
ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}\$?$")


def connect() -> Connection:
    """Sign in to DC01 over LDAPS as the agent. Raises an LDAPException if it cannot."""
    # CERT_REQUIRED: no valid certificate from Biira Bank Root CA, no connection.
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=str(BIIRA_CA))
    server = Server(DC01, port=636, use_ssl=True, tls=tls, connect_timeout=5)
    # read_only=True: ldap3 itself refuses any add, modify or delete, so even a
    # bug here cannot write to AD. AD's own permissions are the real wall.
    return Connection(server, user=os.environ["AD_BIND_USER"],
                      password=os.environ["AD_BIND_PASSWORD"],
                      read_only=True, auto_bind=True, receive_timeout=10)


def find_one(search: str, attributes: list[str]) -> list:
    """Sign in, run one search, sign out. A fresh connection per lookup keeps it simple."""
    conn = connect()
    try:
        conn.search(BASE, search, attributes=attributes, size_limit=1)
        return list(conn.entries)
    finally:
        conn.unbind()


def lookup_account(account: str) -> dict:
    """Who is this account? Accepts svc-x, CORP\\svc-x, svc-x@biirabank.com or WKS01$."""
    name = account.strip().split("\\")[-1].split("@")[0]
    if not ACCOUNT_NAME.match(name):
        return {"account": account, "found": False, "note": "Not a valid Windows account name."}

    # escape_filter_chars: the name goes into an LDAP filter, so * ( ) and friends
    # are neutralised. Without it, "*" would match every account (LDAP injection).
    entries = find_one(f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(name)}))",
                       ACCOUNT_ATTRIBUTES)
    if not entries:
        return {"account": name, "found": False, "note": "No such account in corp.biirabank.com."}

    e = entries[0]
    flags = e.userAccountControl.value or 0
    return {
        "account": e.sAMAccountName.value,
        "found": True,
        "source": "Active Directory (DC01, live)",
        "type": "computer" if "computer" in e.objectClass.values else "user",
        "location": location(e.entry_dn),
        "display_name": e.displayName.value,
        "upn": e.userPrincipalName.value,
        "description": described(e.description.value),
        "enabled": not flags & DISABLED,
        "groups": [group_name(dn) for dn in e.memberOf.values],
        "primary_group": PRIMARY_GROUPS.get(e.primaryGroupID.value, f"RID {e.primaryGroupID.value}"),
        "password_never_expires": bool(flags & PASSWORD_NEVER_EXPIRES),
        "sensitive_cannot_be_delegated": bool(flags & NOT_DELEGATED),
        "created": when(e.whenCreated.value),
        # Replicated between DCs only every 9 to 14 days: "around then", not "exactly".
        "last_logon_approx": when(e.lastLogonTimestamp.value),
        "password_last_set": when(e.pwdLastSet.value),
    }


def lookup_host(host: str) -> dict:
    """What is this machine? Accepts a lab IP address or a machine name."""
    query = host.strip()
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    try:
        ip = ipaddress.ip_address(query)
    except ValueError:
        ip = None

    if ip:
        matches = [h for h in inventory["hosts"] if h["ip"] == str(ip)]
    else:
        short = query.split(".")[0].rstrip("$").upper()  # DC01.corp.biirabank.com -> DC01
        matches = [h for h in inventory["hosts"]
                   if short in [h["name"].upper(), *(a.upper() for a in h["aliases"])]]
    entry = matches[0] if matches else None

    result = {"query": query, "inventory": entry,
              "inventory_note": "From assets.json, kept by hand." if entry else "Not in the lab inventory."}
    if ip:
        result["network"] = next((n for n in inventory["networks"]
                                  if ip in ipaddress.ip_network(n["cidr"])), None)

    # Domain-joined machines also have a computer account in AD. Ask, but never
    # let an AD problem hide what the inventory already knows.
    name = entry["name"] if entry else (None if ip else query.split(".")[0].rstrip("$"))
    if name and ACCOUNT_NAME.match(name):
        try:
            result["active_directory"] = ad_computer(name)
        except Exception as e:  # Unreachable, certificate refused, bad login: say so.
            result["active_directory"] = {"error": f"Could not ask DC01: {type(e).__name__}"}
    return result


def ad_computer(name: str) -> dict:
    entries = find_one(f"(&(objectCategory=computer)(sAMAccountName={escape_filter_chars(name)}$))",
                       HOST_ATTRIBUTES)
    if not entries:
        return {"domain_joined": False,
                "note": "No computer account in AD. Normal for Linux hosts and appliances."}
    e = entries[0]
    return {
        "domain_joined": True,
        "source": "Active Directory (DC01, live)",
        "dns_name": e.dNSHostName.value,
        "location": location(e.entry_dn),
        "os": e.operatingSystem.value,
        "os_version": e.operatingSystemVersion.value,
        "description": described(e.description.value),
        "enabled": not (e.userAccountControl.value or 0) & DISABLED,
        "created": when(e.whenCreated.value),
        "last_logon_approx": when(e.lastLogonTimestamp.value),
    }


def location(dn: str) -> str:
    """CN=svc-x,OU=ServiceAccounts,OU=Users,OU=BIIRA,DC=... -> BIIRA/Users/ServiceAccounts"""
    parts = [p.split("=", 1)[1] for p in dn.split(",")[1:] if not p.upper().startswith("DC=")]
    return "/".join(reversed(parts)) or "(domain root)"


def group_name(dn: str) -> str:
    """CN=Domain Admins,CN=Users,DC=... -> Domain Admins"""
    return dn.split(",")[0].split("=", 1)[1]


def described(value) -> str | None:
    if not value:
        return None
    text = " ".join(value) if isinstance(value, list) else str(value)
    return clean(text)  # Secrets out before anything leaves the lab.


def when(value) -> str | None:
    """AD dates as text. AD says "never" with the year 1601, its zero date."""
    if value is None or getattr(value, "year", 1601) <= 1601:
        return None
    return value.isoformat(timespec="seconds")
