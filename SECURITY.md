# Security

This developer preview has not completed its Windows installation, unattended-service and release acceptance matrix. Use explicitly authorized test machines until those checks are complete.

Please use GitHub's **Report a vulnerability** workflow when private reporting is available. If it is unavailable, open an issue requesting a private reporting channel without including exploit details, credentials, private keys or another person's data. Do not probe third-party deployments while reporting a source issue.

Useful reports describe the affected revision, prerequisites, authorization boundary and a minimal local reproduction using disposable identities. Do not attach production runtime databases or raw remote-session logs.

Outer HTTPS/WSS carrier certificate verification is skipped by default. Inner endpoint mutual TLS, public-key pins and capability grants remain mandatory. A change that accepts arbitrary inner peers, bypasses grants or routes outside the fixed/sandboxed destination is a security boundary change.
