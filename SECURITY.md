# Security reporting

Report a suspected vulnerability in an ENKV protocol, SDK, author tool, example
or official plugin through
[GitHub private vulnerability reporting](https://github.com/enkv-sh/extensions/security/advisories/new).
For the CLI, storage, key custody or domain state implementation, use
[ENKV core private reporting](https://github.com/enkv-sh/core/security/advisories/new).
If the owner is unclear, report to either repository and name the affected tool
or plugin.

Do not publish secret values, credentials, private keys, exploit details or
private operational files in a public issue. Include the plugin/tool version,
CLI archive version if relevant, native platform, expected result and a minimal
reproduction with synthetic values. Describe the suspected impact.

The repository owner must enable private reporting. If the **Report a
vulnerability** option is unavailable, open an ordinary issue asking only for
a private security contact. Keep the technical details private. See
[GitHub's reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

The maintainer reviews reports, requests details privately and coordinates
correction and disclosure. No fixed response time is promised. Ordinary bugs
can use [GitHub Issues](https://github.com/enkv-sh/extensions/issues) with safe,
synthetic reproduction data.

Native plugins are trusted code. A valid signature identifies authenticated
bytes; it does not sandbox those bytes or reduce broad credentials. Trust local
author builds deliberately and preserve exact old builds required by accepted
work. The [operator guide](https://github.com/enkv-sh/core/blob/main/docs/README.md)
explains installation, plugin selection, updates and recovery.
