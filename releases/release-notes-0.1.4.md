# iptools 0.1.4

iptools 0.1.4 is a security maintenance release. Existing deployments should
upgrade promptly.

## Highlights

- Isolates every MTR invocation in a unique output file.
- Accounts for active MTR runs with lock-protected reservations that fail closed.
- Keeps each polling page attached to a run owned by its browser session.
- Applies the shared strict session and cookie policy to the MTR poller.
- Adds dependency-free regression tests for concurrency and session handling.

## Installation

1. Download `ip-tools-0.1.4.tar.gz` or `ip-tools-0.1.4.zip` from the project
   release.
2. Back up the per-tool configuration values at the top of your installed PHP
   files.
3. Extract the archive into the web root, then reapply those configuration
   values.
4. Ensure `tmp/` exists and is writable by the web server when using MTR.

The archive does not include or overwrite runtime `logs/` and `tmp/` data.

## Requirements

- PHP 7.3 or newer with the GMP extension for IPv6 tools.
- A web server that honors the supplied Apache rules, or equivalent Nginx rules.
- The command-line utilities used by the enabled tools.
- MTR installed for `mtr.php`; see `README.md` for optional sudo configuration.
