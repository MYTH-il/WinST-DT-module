# C2/Exfiltration analyzer integration

The upstream project is **C2-Exfil-E-Rakshak**, created and maintained by Raghav Shrivastav (`demistifying`): `https://github.com/demistifying/C2-Exfil-E-Rakshak.git`. Upstream questions belong in that repository.

`integrations/c2-exfil/` is a byte-for-byte subtree at `47225ecb439936659e55ffa9118db083bb2f56c2`. WinST/DT never edits it. The ordered files under `integrations/c2-exfil-patches/` are applied only to a versioned staging copy. The installer verifies upstream, dependency, patch-series, and effective-tree hashes; runs upstream and compatibility tests; and atomically promotes `/srv/winstdt/libexec/c2-exfil/<effective-version>/current` while retaining the prior version.

This revision adds the offline explainable dictionary-DGA model, domain-only IOC export fixes, attribution context in every output sink, unanswered-handshake beacon protection, guest/time-window bundle scoping, manifest-driven honesty gates, per-run join fields, and a custody link to the handoff hash manifest. DGA inference is deterministic pure Python; NumPy is not a production dependency and is used only by the optional retraining tool.

## Identity and fixtures

The patched CLI accepts `--analysis-id`, `--sample-sha256`, `--pcap-sha256`, `--access-events`, `--access-events-source`, `--static-prior`, `--zeek-dir`, `--handoff`, and `--validation-mode`. The submitted SHA-256 is canonical. Integrated execution requires the already validated handoff manifest; direct pristine-upstream use retains its legacy interface.

Omitted access events mean `disabled`. A known fixture requires both `synthetic-test` and validation mode; the production wrapper never permits it. Real access events must have CAPE/capemon provenance and an eligible status file.

## Processing and output

Native Zeek is used only when the complete directory validates. A malformed directory triggers the upstream streamed fallback. Failed fallback preserves PCAP-only analysis. Provenance labels all three modes and never presents fallback as native-equivalent.

The runner validates the immutable handoff before analysis, snapshots all handoff hashes, supplies explicit inputs, optionally performs transactional PostgreSQL loading, normalizes analyzer files, rechecks the handoff, seals every regular result file in `hashes.sha256`, removes write bits, validates with `winstdt validate-c2-result`, and atomically promotes the task directory. `output/analysis_notes.json` always records network simulation, clock and telemetry caveats plus guest/window scoping. Result schema 1.1 carries `session_id` and `cape_task_id`; the first event links to `integrity.hash_manifest_sha256`, and provenance records the verified custody-chain seed and tip.

PostgreSQL schema 3 is an additive upgrade. Run `scripts/migrate-c2-database.sh` to preview it and add `--execute` with `DATABASE_URL` to apply it. If runtime rollback is required after migration, disable PostgreSQL loading for the retained prior runtime or temporarily restore the schema-version marker to 2; the added columns do not need to be removed.

## Upstream test packaging note

The pinned tree collects 268 tests. A clean clone passes 254 and skips 11
corpus-dependent cases: six require `ftp-auth-tls.pcap`, three require omitted
synthetic loader PCAPs, one requires an omitted reputation-hit PCAP, and one requires
the omitted Snake KeyLogger PCAP. These are upstream-declared conditional skips,
not failures. The shipped DGA model is present, so its model-dependent tests run.

Three additional tests in `tests/test_schema_contract.py` are explicitly
deselected because they unconditionally reference that reputation-hit malware PCAP even
though upstream excludes that file from the repository. The missing-file check,
the resulting populated-attribution check, and its CSV-export check therefore
cannot succeed in a clean clone. WinST/DT recreates the attribution, domain-only
IOC, CSV, and STIX contract assertions with committed synthetic observables. It
does not claim that this substitutes for exercising the specific omitted capture,
and it never downloads or fabricates malware traffic silently.

Event confidence is `confirmed`, `strong`, `weak`, `unconfirmed`, or `allowlisted`. Attribution confidence is `confirmed`, `likely`, or `possible`; basis is `static_prior`, `threat_intel`, or `behavioural`. These are separate contracts.

The upstream tree currently has no explicit license file. The departmental authorization used for this deployment does not resolve licensing for third-party redistribution; downstream distributors must obtain their own appropriate permission.
