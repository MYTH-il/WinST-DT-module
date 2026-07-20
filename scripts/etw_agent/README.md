# WinST/DT ETW Agent

The ETW agent is a Windows-side mode of the `winstdt` Rust binary:

```powershell
winstdt.exe etw-agent --config C:\ProgramData\WinSTDT\etw-agent.config.json start
winstdt.exe etw-agent --config C:\ProgramData\WinSTDT\etw-agent.config.json stop
```

`start` creates an ETW trace session and enables each configured provider with
graceful degradation. If a provider cannot be enabled, the agent records that
provider in `etw_state.json` but keeps the session alive.

`stop` stops the trace session and writes:

```text
C:\ProgramData\WinSTDT\behavior\trace.etl
C:\ProgramData\WinSTDT\behavior\telemetry.json
```

These are the paths the CAPE exporter expects to retrieve into the analysis
directory before packaging.

## Build on the Ubuntu Host

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The Windows binary will be:

```text
target/x86_64-pc-windows-gnu/release/WinST-DT-module.exe
```

## VMCloak/Post-Hardening Install

Copy these files into the golden image during the post-VMCloak hardening pass:

```text
C:\ProgramData\WinSTDT\bin\winstdt.exe
C:\ProgramData\WinSTDT\etw-agent.config.json
```

Create `C:\ProgramData\WinSTDT\behavior` and make sure the account running the
agent has rights to create ETW trace sessions. The MVP path can run the agent
from CAPE's analyzer lifecycle rather than installing a persistent service:

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\WinSTDT\bin | Out-Null
New-Item -ItemType Directory -Force C:\ProgramData\WinSTDT\behavior | Out-Null
Copy-Item .\winstdt.exe C:\ProgramData\WinSTDT\bin\winstdt.exe
Copy-Item .\etw-agent.config.json C:\ProgramData\WinSTDT\etw-agent.config.json
```

The trace session name in the example config is intentionally plain. Do not use
obvious sandbox names such as `malware-monitor` or `etw-agent`.

## Manual Validation Inside the Guest

Open PowerShell as Administrator from the directory containing:

```text
winstdt.exe
etw-agent.config.json
Invoke-EtwAgentValidation.ps1
```

Then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-EtwAgentValidation.ps1
```

Expected result:

```text
ETW validation passed.
Trace: C:\ProgramData\WinSTDT\behavior\trace.etl (<non-zero> bytes)
Telemetry degraded: <true|false>
Providers enabled: ...
```

Missing `Microsoft-Windows-Kernel-Image` or
`Microsoft-Windows-Threat-Intelligence` is acceptable as long as the trace is
non-empty and the missing provider is recorded in telemetry metadata.
