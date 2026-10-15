# AI Agent Identity Lab

Hands-on projects on securing AI agents as non-human identities: scoped OAuth access, secrets management, just-in-time privilege, workload identity, prompt injection defense, and detection.

This lab runs against two existing environments:
- **Enterprise IAM lab** (hybrid AD + Okta, fictional "Biira Bank"): https://github.com/noble-antwi/enterprise-iam-lab
- **Security homelab** (Proxmox, Windows Server AD, Wazuh, pfSense, VLANs, Ansible): https://github.com/noble-antwi/enterprise-security-homelab

All work uses lab accounts, test tenants, and fake data only.

## Projects

| # | Project | Status |
|---|---------|--------|
| 01 | [Agent from scratch: "Ask my SIEM"](01-agent-from-scratch/) | In progress (stage 1a done) |
| 02 | Okta MCP server | Not started |
| 03 | Agent identity with Okta + Vault | Not started |
| 04 | Service account hunter | Not started |
| 05 | AI-assisted access review | Not started |
| 06 | JIT access broker | Not started |
| 07 | Secretless cloud access | Not started |
| 08 | SPIFFE/SPIRE workload identity | Not started |
| 09 | Prompt injection red team | Not started |
| 10 | Wazuh agent detection | Not started |
| 11 | Governed support assistant (capstone) | Not started |

Each project gets its own folder with a README covering what it does, how to run it, an architecture diagram, and what broke along the way. This table is updated as they land.
