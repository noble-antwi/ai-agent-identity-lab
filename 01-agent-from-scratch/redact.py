"""
The filter every command line passes through before it can leave the lab.

Command lines are free text. People and scripts put passwords, keys and tokens in
them, and an attacker on a machine can put anything there at all. Whatever the
tool returns is sent to the model provider, so command lines are cleaned here
first. Paths (image, parentImage, targetFilename) are not filtered: they name
programs and files, not secrets.

Each removal is replaced with a label saying what was removed, so the model (and
a human reading its answer) knows something was there without seeing it.

This is a safety net, not a guarantee. A secret in an unusual shape can still get
through, which is why command lines were a deliberate decision, not a default.
"""

import re

MAX_LENGTH = 300  # Long command lines are cut: enough to read, not enough to smuggle an essay in.

RULES = [
    # net user bob Winter2026! /add  ->  net user bob [REDACTED:password] /add
    (re.compile(r"(?i)\b(net(?:1)?(?:\.exe)?\s+user\s+\S+\s+)(?!/)(\S+)"), r"\1[REDACTED:password]"),
    # -Password x, --password=x, /password:x, -pwd x, -passwd x, -Secret x, -Token x, -ApiKey x
    (re.compile(r"(?i)((?:^|\s)[-/]{1,2}(?:password|passwd|pwd|pass|secret|token|apikey|api-key|key)\s*[:=\s]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1[REDACTED:secret]"),
    # password=x, pwd=x, token=x, apikey=x, secret=x  (connection strings, query strings)
    (re.compile(r"(?i)\b((?:password|passwd|pwd|token|apikey|api_key|access_key|secret|client_secret)\s*=\s*)([^;&\s\"']+)"),
     r"\1[REDACTED:secret]"),
    # ConvertTo-SecureString "Winter2026!" -AsPlainText
    (re.compile(r"(?i)(ConvertTo-SecureString\s+)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED:password]"),
    # https://user:pass@host  ->  https://user:[REDACTED:password]@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)"), r"\1[REDACTED:password]\3"),
    # Authorization: Bearer eyJ...  /  Basic dXNlcjpwYXNz
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED:token]"),
    # -EncodedCommand <base64>: keep the fact (a strong signal), drop the payload.
    (re.compile(r"(?i)((?:^|\s)-e(?:nc|ncodedcommand|c)?\s+)([A-Za-z0-9+/=]{16,})"),
     lambda m: f"{m.group(1)}[REMOVED:encoded command, {len(m.group(2))} chars]"),
    # Any other long base64 or hex run: keys, tokens, blobs.
    (re.compile(r"\b(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/]{40,}={0,2})"), "[REDACTED:long string]"),
]


def clean(command_line: str) -> str:
    """Return the command line with secrets replaced by labels, and cut to length."""
    text = command_line
    for pattern, replacement in RULES:
        text = pattern.sub(replacement, text)
    if len(text) > MAX_LENGTH:
        text = f"{text[:MAX_LENGTH]}... [cut, {len(text) - MAX_LENGTH} more chars]"
    return text
