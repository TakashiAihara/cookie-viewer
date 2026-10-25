# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on the Security tab of this repository. Do not open a public issue.

Include the Chrome version, the extension version, and the steps to reproduce.

## Scope

In scope: anything that lets this extension leak cookie values (sending them anywhere, storing them, exposing them to a web page), run code that is not in the package, or read a site the user has not granted.

Out of scope: other extensions or malware on the same machine reading cookies, and the OS clipboard keeping a value the user copied.
