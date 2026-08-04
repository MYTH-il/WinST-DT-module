# C2/Exfiltration analyzer integration

The authorized upstream is `https://github.com/demistifying/C2-Exfil-E-Rakshak.git`, pinned as a Git subtree under `integrations/c2-exfil/`. The subtree contains upstream code only. WinST/DT adapters remain under `scripts/`.

## Trust boundary

The immutable handoff is input-only. Each execution writes to `/srv/winstdt/c2-results/{task_id}/`; it must never modify `/srv/winstdt/handoff/{task_id}`. The runner always supplies an explicit access-event path, so the analyzer cannot silently fall back to `data/access_events_fixture.json`.

Inputs are the original PCAP, real CAPE/capemon access events, a static IOC prior, and optional Suricata, TLS, or Zeek metadata. The upstream access-event contract is a JSON array whose entries contain `timestamp`, `data_type`, `api_call`, and optional `process`.

Clock correction is applied from `behavior/clock-sync.json`. Host/network correlation is disabled when the measurement is missing or its uncertainty cannot support the analyzer's 15-second window. Network-only findings may still be produced and are labeled accordingly.

Upstream commit `5d153d960fc101cdad171aa22f8cf434318d3202` is the current pin, and its Python environment is frozen in `config/c2-exfil-requirements.lock.txt`. Its 206-test suite passes locally with 196 tests passing and 10 optional tests skipped. A network-only integration run against immutable CAPE task 7 produced one weak beacon finding for `5.149.249.242:80`; fixture events were not used and host/network correlation was explicitly disabled because the older bundle lacks trustworthy access events.

## Execution and updates

Install dependencies into a dedicated virtual environment with `scripts/install-c2-analyzer.sh --execute`, then run `scripts/run-c2-analyzer.sh /srv/winstdt/handoff/123`. The runner validates the bundle, supplies explicit inputs, writes provenance with upstream and input hashes, and atomically promotes `/srv/winstdt/c2-results/{task_id}`.

Update only after reviewing a new upstream commit and from a clean worktree:

```text
git subtree pull --prefix integrations/c2-exfil \
  https://github.com/demistifying/C2-Exfil-E-Rakshak.git <reviewed-commit> --squash
```

Never place WinST/DT-specific changes inside the subtree.

## Completion status

The integration is sound for pinned, fixture-free network-only processing: the
upstream suite passes, immutable task 7 was consumed successfully, inputs and
outputs are hashed, and derived output is separated from the handoff. Full
integration is not yet accepted. Remaining work is:

- interpolate start/end guest clock measurements instead of averaging offsets;
- corroborate classified capemon events with ETL rather than relying on
  capemon alone;
- pass Suricata and decrypted-traffic metadata through an upstream-supported
  interface;
- validate the static-prior extractor against known CAPA/CAPE IOC fixtures;
- validate the emitted result bundle against a dedicated schema; and
- complete one clock-valid run with non-empty real access events and a
  demonstrated host/network correlation inside the 15-second window.

The upstream repository currently has no license file in the pinned tree.
Repository visibility alone does not grant redistribution rights; retain the
project owner's explicit authorization and confirm licensing before distributing
WinST/DT builds containing the subtree.
