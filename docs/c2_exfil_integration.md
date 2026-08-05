# C2/Exfiltration analyzer integration

The upstream project is **C2-Exfil-E-Rakshak**, created and maintained by Raghav Shrivastav (`demistifying`): `https://github.com/demistifying/C2-Exfil-E-Rakshak.git`. Upstream questions belong in that repository.

`integrations/c2-exfil/` is a byte-for-byte subtree at `c417276196586c676d3f0b63d23100d2cd20fce9`. WinST/DT never edits it. The ordered files under `integrations/c2-exfil-patches/` are applied only to a versioned staging copy. The installer verifies upstream, dependency, patch-series, and effective-tree hashes; runs upstream and compatibility tests; and atomically promotes `/srv/winstdt/libexec/c2-exfil/<effective-version>/current` while retaining the prior version.

## Identity and fixtures

The patched CLI accepts `--analysis-id`, `--sample-sha256`, `--pcap-sha256`, `--access-events`, `--access-events-source`, `--static-prior`, `--zeek-dir`, and `--validation-mode`. The submitted SHA-256 is canonical. Direct upstream use without identity flags retains legacy PCAP identity.

Omitted access events mean `disabled`. A known fixture requires both `synthetic-test` and validation mode; the production wrapper never permits it. Real access events must have CAPE/capemon provenance and an eligible status file.

## Processing and output

Native Zeek is used only when the complete directory validates. A malformed directory triggers the upstream streamed fallback. Failed fallback preserves PCAP-only analysis. Provenance labels all three modes and never presents fallback as native-equivalent.

The runner validates the immutable handoff before analysis, snapshots all handoff hashes, supplies explicit inputs, optionally performs transactional PostgreSQL loading, normalizes analyzer files, rechecks the handoff, seals every regular result file in `hashes.sha256`, removes write bits, validates with `winstdt validate-c2-result`, and atomically promotes the task directory.

Event confidence is `confirmed`, `strong`, `weak`, `unconfirmed`, or `allowlisted`. Attribution confidence is `confirmed`, `likely`, or `possible`; basis is `static_prior`, `threat_intel`, or `behavioural`. These are separate contracts.

The upstream tree currently has no explicit license file. The departmental authorization used for this deployment does not resolve licensing for third-party redistribution; downstream distributors must obtain their own appropriate permission.
