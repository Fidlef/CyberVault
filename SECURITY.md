# Security policy

## Threat model

CyberVault protects file contents at rest from someone who obtains only the
`.cvlt` file and does not know its password. AES-GCM also detects accidental or
malicious changes to the envelope.

## Out of scope

It does not protect against malware, keyloggers, screen capture, a compromised
browser or operating system, weak passwords, shoulder surfing, memory or swap
inspection, deleted-file recovery, malicious dependencies, or access to the
decrypted download. It is not an audited password manager, backup system, disk
encryption product, or key-management service.

## Privacy behavior

- The server binds to `127.0.0.1` by default.
- The request class keeps multipart file parts in memory rather than using
  Werkzeug's temporary spool files. Uploaded bytes and passwords are not logged
  or deliberately written by the application.
- Responses use `Cache-Control: no-store` and restrictive browser headers.
- The browser writes explicit downloads; operating-system behavior is outside
  the application's control.

Do not expose the Flask development server to a network. Do not use this
demonstration as the only copy of important data. Test decryption before relying
on any encrypted output.

## Reporting

Use a private GitHub security advisory with synthetic data and no passwords,
personal files, credentials, or active exploit payloads.
