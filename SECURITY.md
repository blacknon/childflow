# Security Policy

If you believe you found a security issue in `childflow`, please avoid posting exploit details in a public issue first.

Open a private report if you have a direct maintainer contact. If you do not, open a minimal public issue that says a security-sensitive problem exists and asks for a private follow-up path.

Please include:

- affected version or commit
- Linux distribution and kernel details
- backend used, such as `rootless-internal` or `--root`
- reproduction steps
- expected impact

Security fixes may involve namespace isolation, packet handling, policy enforcement, proxy routing, or flow-log behavior, so complete reproduction details are especially helpful.
