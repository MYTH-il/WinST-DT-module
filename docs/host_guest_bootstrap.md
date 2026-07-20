# WinST/DT Host and Windows Guest Bootstrap

There is one setup entry point:

```bash
scripts/setup-ubuntu24-host.sh
```

The script is a stable dashboard runner. It keeps one checklist on screen,
records per-component logs, and reports the exact log file for any failed
component.

Default logs:

```text
/srv/winstdt/logs/setup/<run-id>/
    01-ubuntu.log
    02-apt.log
    03-rust.log
    04-layout.log
    05-network.log
    06-cape.log
    07-vmcloak.log
    08-build.log
    09-overlay.log
    10-guest.log
    errors.log
```

Dry-run:

```bash
scripts/setup-ubuntu24-host.sh
```

Execute setup:

```bash
scripts/setup-ubuntu24-host.sh --execute
```

Execute setup and build the Windows guest when a licensed Windows 10 22H2 x64
ISO is available:

```bash
scripts/setup-ubuntu24-host.sh \
  --windows-iso ./Win10_22H2_x64.iso \
  --execute
```

Force CAPE installer phases to rerun:

```bash
scripts/setup-ubuntu24-host.sh \
  --rerun-cape-installers \
  --execute
```

The setup flow is resumable. It skips installed apt packages, existing users,
existing directories, an already active libvirt network, an existing VMCloak
install, and CAPE installer phases with marker files under:

```text
/srv/winstdt/setup-state/
```

After VMCloak creates the Windows guest, copy the installed guest payload into
the guest and run the ETW validation script as Administrator:

```text
/srv/winstdt/bin/winstdt.exe
/srv/winstdt/scripts/etw_agent/etw-agent.config.json
/srv/winstdt/scripts/etw_agent/Invoke-EtwAgentValidation.ps1
```

Inside the Windows guest:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-EtwAgentValidation.ps1 -SourceBinary .\winstdt.exe -SourceConfig .\etw-agent.config.json
```
