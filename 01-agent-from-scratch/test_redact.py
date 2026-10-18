"""
Proof that the filter in redact.py does its job. Run:  python test_redact.py

Each case is (what Wazuh might record, what is allowed to leave the lab).
The secrets in here are made up for the test.
"""

from redact import clean

CASES = [
    # Secrets that must never reach the model.
    ("net user bob Winter2026! /add",
     "net user bob [REDACTED:password] /add"),
    ("net1.exe user svc-backup S3cr3t-Pass /domain",
     "net1.exe user svc-backup [REDACTED:password] /domain"),
    ("backup.exe -Password Hunter2 -Target D:\\",
     "backup.exe -Password [REDACTED:secret] -Target D:\\"),
    ("tool --password=\"pa ss\" --verbose",
     "tool --password=[REDACTED:secret] --verbose"),
    ("sqlcmd -S db01 -Q \"x\" Server=db01;User Id=sa;Password=Letmein1;",
     "sqlcmd -S db01 -Q \"x\" Server=db01;User Id=sa;Password=[REDACTED:secret];"),
    ("powershell $p = ConvertTo-SecureString \"Winter2026!\" -AsPlainText -Force",
     "powershell $p = ConvertTo-SecureString [REDACTED:password] -AsPlainText -Force"),
    ("curl https://admin:Tr0ub4dor@10.0.0.5/api",
     "curl https://admin:[REDACTED:password]@10.0.0.5/api"),
    ("curl -H \"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def\" https://x",
     "curl -H \"Authorization: Bearer [REDACTED:token]\" https://x"),
    ("powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
     "powershell.exe -NoP -EncodedCommand [REMOVED:encoded command, 40 chars]"),
    ("app.exe --apikey sk-lab-0123456789abcdef",
     "app.exe --apikey [REDACTED:secret]"),

    # Ordinary command lines that must pass through untouched.
    ("C:\\WINDOWS\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc",
     "C:\\WINDOWS\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc"),
    ("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ExecutionPolicy Bypass -File C:\\scripts\\check.ps1",
     "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ExecutionPolicy Bypass -File C:\\scripts\\check.ps1"),
    ("net user bob /domain",
     "net user bob /domain"),
]


def main() -> None:
    failed = 0
    for given, expected in CASES:
        got = clean(given)
        if got != expected:
            failed += 1
            print(f"FAIL\n  given:    {given}\n  expected: {expected}\n  got:      {got}")
    long_line = "x " * 400
    if not clean(long_line).endswith("more chars]"):
        failed += 1
        print("FAIL  long command line was not cut")
    print(f"{len(CASES) + 1 - failed} of {len(CASES) + 1} passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
