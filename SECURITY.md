# Security Policy

GreyNOC Non-Human Identity Risk Engine is defensive cybersecurity software.

## Supported Scope

Security review covers the current default branch of this repository unless GreyNOC documents additional supported release branches.

## Tool Safety Boundaries

- Run it only against code and systems you own or are authorized to assess.
- The tool does not validate credentials.
- The tool does not call third-party APIs with discovered keys.
- The tool does not attempt login, replay, cracking, exploitation, privilege escalation, exfiltration, or credential testing.
- The tool masks secrets in terminal output, GUI views, reports, and SQLite.
- SARIF, JSON, HTML, Markdown, baseline, and SQLite outputs must contain masked evidence only.
- Do not upload real scan outputs publicly.

## Reporting a Vulnerability

Please do not post exploit details, credentials, private data, unmasked scan output, or working attack instructions in public issues or pull requests.

Use GitHub private vulnerability reporting when it is available for this repository. If a private report path is not available, open a minimal public issue that says you have a security report for @GreyNOC and omit sensitive details until a private channel is arranged.

Report suspected tool issues responsibly and include only masked evidence. Do not access, modify, destroy, or exfiltrate data that is not yours. Good-faith security research and defensive reports are welcome.
