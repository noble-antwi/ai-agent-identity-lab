"""
Ask my SIEM, stage 2: prove the agent's own AD account can sign in to DC01 over
LDAPS, before any of it goes into the agent.

No AI here. It signs in as svc-ask-siem on port 636 (directory.connect checks
DC01's certificate against the Biira Bank root CA), asks AD "who am I?", then
looks up one account with the agent's own lookup_account tool.
Read-only: nothing is written to AD.

Run it (the account name to look up is optional):
    python ldap_check.py
    python ldap_check.py some.user
"""

import json
import sys

from dotenv import load_dotenv
from ldap3.core.exceptions import LDAPException

import directory

load_dotenv(directory.HERE / ".env")


def main(account: str) -> int:
    try:
        conn = directory.connect()
    except LDAPException as error:
        # Wrong password, certificate not trusted, DC01 unreachable: all land here.
        print("Could not sign in to DC01 over LDAPS:", error)
        return 1
    try:
        print("1. Signed in over LDAPS")
        print("   TLS version :", conn.socket.version())
        print("   Cipher      :", conn.socket.cipher()[0])
        print("   DC01 says I am:", conn.extend.standard.who_am_i())
    finally:
        conn.unbind()

    print(f"\n2. lookup_account('{account}'), exactly what Claude would receive:")
    print(json.dumps(directory.lookup_account(account), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "svc-ask-siem"))
