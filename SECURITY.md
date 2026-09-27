# Security policy

This repository currently contains experimental beta software for a specific
router configuration. No version is represented as a fully audited or
hardware-validated security product. Read README.md and docs/SAFETY.md before use.

Keep router management LAN-only, protect repository access with strong
authentication, review software changes before installation and retain independent
router/Skynet backups. Automatic update downloads are not automatic installation.
The update manifest uses hashes for integrity, not independent signatures.

Do not post API keys, session tokens, public management endpoints, unredacted
firewall exports or personal connection logs in public issues. Use GitHub's private
vulnerability reporting feature if the repository owner enables it. Otherwise,
request a private reporting channel without publishing exploitation details or
secrets. No particular reporting feature or response SLA is asserted to be enabled.

For ordinary bugs, include the router model, firmware version, add-on version,
redacted error text and reproduction steps. Never include the AbuseIPDB key.
