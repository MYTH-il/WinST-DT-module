# Harmless end-to-end validation

The fixture under `fixtures/windows-validation/` is a separate Rust/Win32 program. It displays a distinctive window, touches only its own `%TEMP%\WinSTDT\Validation` file, sets/reads/clears only its own clipboard canary, queries non-sensitive computer information without transmitting it, resolves `validation.winstdt.test`, and sends exactly three generated canary posts to the private responder.

Build it reproducibly:

```bash
cd fixtures/windows-validation
cargo build --release
diec target/x86_64-pc-windows-gnu/release/winstdt-windows-validation.exe
```

Create a short-lived signed gateway policy for `192.168.125.10:8080`, then dry-run and execute:

```bash
scripts/run-end-to-end-validation.sh \
  --config /srv/winstdt/approvals/RUN.json \
  --fixture fixtures/windows-validation/target/x86_64-pc-windows-gnu/release/winstdt-windows-validation.exe

scripts/run-end-to-end-validation.sh \
  --config /srv/winstdt/approvals/RUN.json \
  --fixture fixtures/windows-validation/target/x86_64-pc-windows-gnu/release/winstdt-windows-validation.exe \
  --execute
```

The execution trap always revokes policy and attempts snapshot reversion. Already captured PCAP/ETL evidence is retained even if later screenshot, gateway, analyzer, or database stages fail. A passing run requires three signed responder receipts, a Suricata marker, real eligible correlation inside 15 seconds, identity-consistent JSON/IOC/PostgreSQL output, read-only hash-complete result validation, snapshot reversion, empty/default-drop forwarding state, and absence of a libvirt public route.

Negative acceptance additionally covers wrong destination and port, expiry during an open connection, byte and connection ceilings, DNS pin mismatch, responder outage, malformed access events, excessive uncertainty, missing-event fixture prevention, malformed-feed rollback, allowlist ranking, SQL round trip, and capture preservation.

## Failure recovery

Failed analyzer stages remain under a marked `.failed` staging directory. Handoffs and successful prior results are never rewritten. Revoke the gateway, collect both captures and responder receipts, confirm the forwarding chain is default-drop, revert `hardened-baseline-antievasion-v1`, and diagnose from preserved evidence.

## Deferred reboot acceptance

The host is not rebooted automatically. Complete the resumable workflow on separate boots:

```bash
scripts/validation/validate-libvirt-reboots.sh prepare
# operator reboot
scripts/validation/validate-libvirt-reboots.sh after-reboot-1
# operator reboot
scripts/validation/validate-libvirt-reboots.sh after-reboot-2
```

Until both distinct boot IDs pass, reboot persistence and all dependent capabilities remain `Degraded`.
