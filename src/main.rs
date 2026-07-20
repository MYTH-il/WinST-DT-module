use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
    thread,
    time::Duration,
};

use clap::{Parser, Subcommand};
use goblin::pe::{PE, section_table::SectionTable};
use md5::Md5;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA_VERSION: &str = "1.0";
const TRACE_ETL_PATH: &str = "behavior/trace.etl";
const PCAP_PATH: &str = "network/capture.pcapng";
const HASH_MANIFEST_PATH: &str = "hashes.sha256";
const MANIFEST_PATH: &str = "manifest.json";
const SAMPLE_META_PATH: &str = "sample.meta.json";

#[derive(Debug, Parser)]
#[command(name = "winstdt")]
#[command(about = "WinST/DT handoff contract tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate one completed handoff bundle directory.
    ValidateBundle {
        /// Path to /handoff/{session_id}.
        bundle: PathBuf,
        /// Skip hashes.sha256 content validation.
        #[arg(long)]
        skip_hashes: bool,
    },
    /// Mock the C2/Exfiltration consumer by validating session directories.
    MockConsume {
        /// Path to /handoff.
        handoff_root: PathBuf,
        /// Scan once and exit.
        #[arg(long)]
        once: bool,
        /// Poll interval for watch mode.
        #[arg(long, default_value_t = 5000)]
        interval_ms: u64,
    },
    /// Run standalone static pre-triage and emit sample.meta.json.
    Pretriage {
        /// Path to the submitted sample.
        sample: PathBuf,
        /// Optional output file. Defaults to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Maximum number of extracted strings to include.
        #[arg(long, default_value_t = 200)]
        max_strings: usize,
    },
    /// Manage the Windows guest ETW trace-session capture agent.
    EtwAgent {
        /// ETW agent action to run.
        #[command(subcommand)]
        action: EtwAgentAction,
        /// JSON config path.
        #[arg(
            long,
            default_value = "C:\\ProgramData\\WinSTDT\\etw-agent.config.json"
        )]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand, Clone, Copy)]
enum EtwAgentAction {
    /// Start the ETW trace session and record provider enablement state.
    Start,
    /// Stop the ETW trace session and write behavior/telemetry.json.
    Stop,
    /// Write telemetry.json from the stored state without touching the session.
    WriteMetadata,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    schema_version: String,
    session_id: String,
    status: SessionStatus,
    errors: Vec<ManifestError>,
    sample_sha256: String,
    static_risk_score: f64,
    cape_task_id: u64,
    telemetry: Telemetry,
    artifact_paths: ArtifactPaths,
    integrity: Integrity,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SessionStatus {
    Completed,
    CaptureError,
    AnalysisError,
    Timeout,
}

#[derive(Debug, Deserialize)]
struct ManifestError {
    stage: String,
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Telemetry {
    format: String,
    artifact_path: String,
    capture_started: bool,
    capture_completed: bool,
    telemetry_degraded: bool,
    degradation_reasons: Vec<ProviderIssue>,
    providers_targeted: Vec<String>,
    providers_enabled: Vec<String>,
    providers_unavailable: Vec<ProviderIssue>,
    etw_ti_status: EtwTiStatus,
}

#[derive(Debug, Deserialize)]
struct ProviderIssue {
    provider: String,
    reason: ProviderIssueReason,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProviderIssueReason {
    ProviderMissing,
    AccessDenied,
    NoEventsObserved,
    AgentError,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EtwTiStatus {
    EnabledAndObserved,
    EnabledNoEvents,
    Unavailable,
    NotAttempted,
}

#[derive(Debug, Deserialize)]
struct ArtifactPaths {
    pcap: String,
    trace_etl: String,
}

#[derive(Debug, Deserialize)]
struct Integrity {
    hash_manifest: String,
    hash_manifest_sha256: String,
    hash_log_ref: String,
}

#[derive(Debug, Deserialize)]
struct SampleMeta {
    schema_version: String,
    sample_sha256: String,
    static_risk_score: f64,
}

#[derive(Debug)]
struct ValidationReport {
    session_id: String,
    status: SessionStatus,
    telemetry_degraded: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PretriageReport {
    schema_version: &'static str,
    sample_sha256: String,
    sample_md5: String,
    sample_sha1: String,
    file_type: String,
    size_bytes: u64,
    whole_file_entropy: f64,
    static_risk_score: f64,
    static_hypotheses: Vec<String>,
    yara: YaraSummary,
    clamav: ClamAvSummary,
    vt_lookup: String,
    strings: StringSummary,
    iocs: IocSummary,
    pe: Option<PeSummary>,
}

#[derive(Debug, Serialize)]
struct YaraSummary {
    fast_hits: Vec<String>,
    deep_hits: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClamAvSummary {
    status: String,
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct StringSummary {
    ascii_count: usize,
    utf16le_count: usize,
    extracted: Vec<String>,
}

#[derive(Debug, Serialize)]
struct IocSummary {
    ipv4: Vec<String>,
    urls: Vec<String>,
    registry_paths: Vec<String>,
    windows_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PeSummary {
    machine: String,
    entry: u32,
    image_base: u64,
    subsystem: String,
    compile_timestamp: u32,
    imports: Vec<String>,
    sections: Vec<PeSectionSummary>,
}

#[derive(Debug, Serialize)]
struct PeSectionSummary {
    name: String,
    virtual_size: u32,
    raw_size: u32,
    characteristics: u32,
    entropy: f64,
}

#[derive(Debug, Deserialize)]
struct EtwAgentConfig {
    session_name: String,
    trace_path: PathBuf,
    telemetry_path: PathBuf,
    state_path: PathBuf,
    providers: Vec<EtwProviderConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EtwProviderConfig {
    name: String,
    tier: EtwProviderTier,
    #[serde(default = "default_etw_keywords")]
    keywords: String,
    #[serde(default = "default_etw_level")]
    level: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EtwProviderTier {
    Baseline,
    Optional,
}

#[derive(Debug, Deserialize, Serialize)]
struct EtwAgentState {
    schema_version: String,
    session_name: String,
    trace_path: PathBuf,
    capture_started: bool,
    providers_targeted: Vec<String>,
    providers_enabled: Vec<String>,
    providers_unavailable: Vec<EtwProviderIssue>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
struct EtwProviderIssue {
    provider: String,
    reason: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct EtwTelemetryMetadata {
    capture_started: bool,
    capture_completed: bool,
    telemetry_degraded: bool,
    degradation_reasons: Vec<EtwProviderIssue>,
    providers_targeted: Vec<String>,
    providers_enabled: Vec<String>,
    providers_unavailable: Vec<EtwProviderIssue>,
    etw_ti_status: String,
}

#[derive(Debug, Error)]
enum ValidationError {
    #[error("{0}")]
    Contract(String),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse JSON {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("command failed: {program} {args:?}: {message}")]
    CommandFailed {
        program: String,
        args: Vec<String>,
        message: String,
    },
}

type Result<T> = std::result::Result<T, ValidationError>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateBundle {
            bundle,
            skip_hashes,
        } => match validate_bundle(&bundle, !skip_hashes) {
            Ok(report) => {
                print_report(&bundle, &report);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("invalid bundle {}: {error}", bundle.display());
                ExitCode::from(1)
            }
        },
        Command::MockConsume {
            handoff_root,
            once,
            interval_ms,
        } => match mock_consume(&handoff_root, once, Duration::from_millis(interval_ms)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("mock consumer failed: {error}");
                ExitCode::from(1)
            }
        },
        Command::Pretriage {
            sample,
            output,
            max_strings,
        } => match pretriage_sample(&sample, max_strings)
            .and_then(|report| write_pretriage(report, output.as_deref()))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("pretriage failed for {}: {error}", sample.display());
                ExitCode::from(1)
            }
        },
        Command::EtwAgent { action, config } => match run_etw_agent(action, &config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("etw-agent failed: {error}");
                ExitCode::from(1)
            }
        },
    }
}

fn run_etw_agent(action: EtwAgentAction, config_path: &Path) -> Result<()> {
    let config = read_etw_agent_config(config_path)?;
    match action {
        EtwAgentAction::Start => start_etw_capture(&config),
        EtwAgentAction::Stop => stop_etw_capture(&config),
        EtwAgentAction::WriteMetadata => write_etw_metadata_from_state(&config, false),
    }
}

fn read_etw_agent_config(path: &Path) -> Result<EtwAgentConfig> {
    let config: EtwAgentConfig = read_json(path)?;
    validate_etw_agent_config(&config)?;
    Ok(config)
}

fn validate_etw_agent_config(config: &EtwAgentConfig) -> Result<()> {
    if config.session_name.trim().is_empty() {
        return contract_error("ETW agent session_name is empty");
    }
    if config.providers.is_empty() {
        return contract_error("ETW agent providers list is empty");
    }
    for provider in &config.providers {
        if provider.name.trim().is_empty() {
            return contract_error("ETW provider name is empty");
        }
    }
    Ok(())
}

fn start_etw_capture(config: &EtwAgentConfig) -> Result<()> {
    ensure_parent_dir(&config.trace_path)?;
    ensure_parent_dir(&config.telemetry_path)?;
    ensure_parent_dir(&config.state_path)?;
    remove_file_if_exists(&config.trace_path)?;

    run_logman(&[
        "start",
        &config.session_name,
        "-ets",
        "-o",
        &config.trace_path.to_string_lossy(),
    ])?;

    let mut providers_enabled = Vec::new();
    let mut providers_unavailable = Vec::new();
    for provider in &config.providers {
        match enable_etw_provider(config, provider) {
            Ok(()) => providers_enabled.push(provider.name.clone()),
            Err(error) => providers_unavailable.push(EtwProviderIssue {
                provider: provider.name.clone(),
                reason: provider_error_reason(&error),
                message: error.to_string(),
            }),
        }
    }

    let state = EtwAgentState {
        schema_version: SCHEMA_VERSION.to_string(),
        session_name: config.session_name.clone(),
        trace_path: config.trace_path.clone(),
        capture_started: true,
        providers_targeted: config
            .providers
            .iter()
            .map(|provider| provider.name.clone())
            .collect(),
        providers_enabled,
        providers_unavailable,
    };
    write_json_file(&config.state_path, &state)
}

fn enable_etw_provider(config: &EtwAgentConfig, provider: &EtwProviderConfig) -> Result<()> {
    run_logman(&[
        "update",
        &config.session_name,
        "-ets",
        "-p",
        &provider.name,
        &provider.keywords,
        &provider.level,
    ])
}

fn stop_etw_capture(config: &EtwAgentConfig) -> Result<()> {
    let stop_result = run_logman(&["stop", &config.session_name, "-ets"]);
    let capture_completed = stop_result.is_ok() && is_non_empty_file(&config.trace_path);
    write_etw_metadata_from_state(config, capture_completed)?;
    stop_result
}

fn write_etw_metadata_from_state(config: &EtwAgentConfig, capture_completed: bool) -> Result<()> {
    let state: EtwAgentState = read_json(&config.state_path)?;
    let telemetry = etw_telemetry_from_state(&state, capture_completed);
    write_json_file(&config.telemetry_path, &telemetry)
}

fn etw_telemetry_from_state(
    state: &EtwAgentState,
    capture_completed: bool,
) -> EtwTelemetryMetadata {
    let degradation_reasons = state.providers_unavailable.clone();
    EtwTelemetryMetadata {
        capture_started: state.capture_started,
        capture_completed,
        telemetry_degraded: !degradation_reasons.is_empty(),
        degradation_reasons,
        providers_targeted: state.providers_targeted.clone(),
        providers_enabled: state.providers_enabled.clone(),
        providers_unavailable: state.providers_unavailable.clone(),
        etw_ti_status: derive_etw_ti_status(&state.providers_enabled, &state.providers_unavailable),
    }
}

fn derive_etw_ti_status(enabled: &[String], unavailable: &[EtwProviderIssue]) -> String {
    const ETW_TI: &str = "Microsoft-Windows-Threat-Intelligence";
    if enabled.iter().any(|provider| provider == ETW_TI) {
        "enabled_no_events".to_string()
    } else if unavailable.iter().any(|issue| issue.provider == ETW_TI) {
        "unavailable".to_string()
    } else {
        "not_attempted".to_string()
    }
}

fn provider_error_reason(error: &ValidationError) -> String {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("access") || message.contains("denied") || message.contains("privilege") {
        "access_denied".to_string()
    } else if message.contains("provider")
        || message.contains("not found")
        || message.contains("does not exist")
        || message.contains("0x80070002")
    {
        "provider_missing".to_string()
    } else if message.contains("event") {
        "no_events_observed".to_string()
    } else if message.contains("logman") {
        "agent_error".to_string()
    } else {
        "unknown".to_string()
    }
}

fn run_logman(args: &[&str]) -> Result<()> {
    run_platform_command("logman", args)
}

#[cfg(windows)]
fn run_platform_command(program: &str, args: &[&str]) -> Result<()> {
    let output = ProcessCommand::new(program)
        .args(args)
        .output()
        .map_err(|source| ValidationError::Read {
            path: PathBuf::from(program),
            source,
        })?;
    if output.status.success() {
        return Ok(());
    }
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Err(ValidationError::CommandFailed {
        program: program.to_string(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        message: message.trim().to_string(),
    })
}

#[cfg(not(windows))]
fn run_platform_command(program: &str, args: &[&str]) -> Result<()> {
    let _ = ProcessCommand::new(program).args(args);
    Err(ValidationError::CommandFailed {
        program: program.to_string(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        message: "ETW capture requires Windows".to_string(),
    })
}

fn mock_consume(root: &Path, once: bool, interval: Duration) -> Result<()> {
    let mut seen = HashSet::new();
    loop {
        for entry in read_dir_sorted(root)? {
            let path = entry.path();
            if !path.is_dir() || !path.join(MANIFEST_PATH).exists() {
                continue;
            }
            let key = path.to_string_lossy().to_string();
            if seen.contains(&key) {
                continue;
            }
            match validate_bundle(&path, true) {
                Ok(report) => {
                    print_report(&path, &report);
                    seen.insert(key);
                }
                Err(error) => {
                    eprintln!("rejected {}: {error}", path.display());
                    seen.insert(key);
                }
            }
        }

        if once {
            return Ok(());
        }
        thread::sleep(interval);
    }
}

fn pretriage_sample(sample: &Path, max_strings: usize) -> Result<PretriageReport> {
    let bytes = fs::read(sample).map_err(|source| ValidationError::Read {
        path: sample.to_path_buf(),
        source,
    })?;
    if bytes.is_empty() {
        return contract_error("sample is empty");
    }

    let size_bytes = bytes.len() as u64;
    let sample_md5 = hex_digest::<Md5>(&bytes);
    let sample_sha1 = hex_digest::<Sha1>(&bytes);
    let sample_sha256 = hex_digest::<Sha256>(&bytes);
    let whole_file_entropy = shannon_entropy(&bytes);
    let file_type = sniff_file_type(&bytes);
    let pe = parse_pe_summary(&bytes);
    let ascii_strings = extract_ascii_strings(&bytes, 4);
    let utf16le_strings = extract_utf16le_strings(&bytes, 4);
    let all_strings = merged_limited_strings(&ascii_strings, &utf16le_strings, max_strings);
    let iocs = extract_iocs(&all_strings);
    let (static_hypotheses, static_risk_score) =
        score_static_findings(whole_file_entropy, pe.as_ref(), &iocs, &file_type);

    Ok(PretriageReport {
        schema_version: SCHEMA_VERSION,
        sample_sha256,
        sample_md5,
        sample_sha1,
        file_type,
        size_bytes,
        whole_file_entropy,
        static_risk_score,
        static_hypotheses,
        yara: YaraSummary {
            fast_hits: Vec::new(),
            deep_hits: Vec::new(),
        },
        clamav: ClamAvSummary {
            status: "not_run".to_string(),
            signature: None,
        },
        vt_lookup: "not_run".to_string(),
        strings: StringSummary {
            ascii_count: ascii_strings.len(),
            utf16le_count: utf16le_strings.len(),
            extracted: all_strings,
        },
        iocs,
        pe,
    })
}

fn write_pretriage(report: PretriageReport, output: Option<&Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(&report).map_err(|source| {
        ValidationError::Contract(format!("failed to serialize report: {source}"))
    })?;
    match output {
        Some(path) => {
            fs::write(path, format!("{json}\n")).map_err(|source| ValidationError::Write {
                path: path.to_path_buf(),
                source,
            })
        }
        None => {
            println!("{json}");
            Ok(())
        }
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure_parent_dir(path)?;
    let json = serde_json::to_string_pretty(value).map_err(|source| {
        ValidationError::Contract(format!("failed to serialize JSON: {source}"))
    })?;
    fs::write(path, format!("{json}\n")).map_err(|source| ValidationError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ValidationError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ValidationError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn is_non_empty_file(path: &Path) -> bool {
    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.len() > 0)
            .unwrap_or(false)
}

fn default_etw_keywords() -> String {
    "0xffffffffffffffff".to_string()
}

fn default_etw_level() -> String {
    "5".to_string()
}

fn hex_digest<D: Digest + Default>(bytes: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(bytes);
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn sniff_file_type(bytes: &[u8]) -> String {
    if bytes.starts_with(b"MZ") {
        "PE executable".to_string()
    } else if bytes.starts_with(b"\x7fELF") {
        "ELF executable".to_string()
    } else if bytes.starts_with(b"%PDF") {
        "PDF document".to_string()
    } else if bytes.starts_with(b"PK\x03\x04") {
        "ZIP/container".to_string()
    } else if bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        "OLE compound document".to_string()
    } else if bytes.iter().all(|byte| {
        byte.is_ascii() && !byte.is_ascii_control() || matches!(byte, b'\r' | b'\n' | b'\t')
    }) {
        "ASCII text".to_string()
    } else {
        "unknown binary".to_string()
    }
}

fn parse_pe_summary(bytes: &[u8]) -> Option<PeSummary> {
    let pe = PE::parse(bytes).ok()?;
    let imports = pe
        .imports
        .iter()
        .map(|import| format!("{}!{}", import.dll, import.name))
        .collect::<Vec<_>>();
    let sections = pe
        .sections
        .iter()
        .map(|section| section_summary(section, bytes))
        .collect::<Vec<_>>();

    Some(PeSummary {
        machine: format!("0x{:04x}", pe.header.coff_header.machine),
        entry: pe.entry as u32,
        image_base: pe.image_base as u64,
        subsystem: format!(
            "0x{:04x}",
            pe.header
                .optional_header
                .as_ref()
                .map(|header| header.windows_fields.subsystem)
                .unwrap_or_default()
        ),
        compile_timestamp: pe.header.coff_header.time_date_stamp,
        imports,
        sections,
    })
}

fn section_summary(section: &SectionTable, bytes: &[u8]) -> PeSectionSummary {
    let start = section.pointer_to_raw_data as usize;
    let size = section.size_of_raw_data as usize;
    let end = start.saturating_add(size).min(bytes.len());
    let entropy = if start < end {
        shannon_entropy(&bytes[start..end])
    } else {
        0.0
    };

    PeSectionSummary {
        name: section
            .name()
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string(),
        virtual_size: section.virtual_size,
        raw_size: section.size_of_raw_data,
        characteristics: section.characteristics,
        entropy,
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            push_ascii_if_long_enough(&mut strings, &mut current, min_len);
        }
    }
    push_ascii_if_long_enough(&mut strings, &mut current, min_len);
    strings
}

fn push_ascii_if_long_enough(strings: &mut Vec<String>, current: &mut Vec<u8>, min_len: usize) {
    if current.len() >= min_len {
        if let Ok(value) = String::from_utf8(current.clone()) {
            strings.push(value);
        }
    }
    current.clear();
}

fn extract_utf16le_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        let Some(character) = char::from_u32(code as u32) else {
            push_utf16_if_long_enough(&mut strings, &mut current, min_len);
            continue;
        };
        if character.is_ascii_graphic() || character == ' ' {
            current.push(character);
        } else {
            push_utf16_if_long_enough(&mut strings, &mut current, min_len);
        }
    }
    push_utf16_if_long_enough(&mut strings, &mut current, min_len);
    strings
}

fn push_utf16_if_long_enough(strings: &mut Vec<String>, current: &mut Vec<char>, min_len: usize) {
    if current.len() >= min_len {
        strings.push(current.iter().collect());
    }
    current.clear();
}

fn merged_limited_strings(ascii: &[String], utf16le: &[String], max_strings: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    ascii
        .iter()
        .chain(utf16le.iter())
        .filter_map(|value| {
            if seen.insert(value.clone()) {
                Some(value.clone())
            } else {
                None
            }
        })
        .take(max_strings)
        .collect()
}

fn extract_iocs(strings: &[String]) -> IocSummary {
    let ipv4_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid ipv4 regex");
    let url_re = Regex::new(r#"https?://[^\s"'<>]+"#).expect("valid url regex");
    let registry_re =
        Regex::new(r#"(?i)\bHK(?:LM|CU|CR|U|CC)\\[^\s"'<>]+"#).expect("valid registry regex");
    let path_re = Regex::new(r#"(?i)\b[A-Z]:\\[^\s"'<>]+"#).expect("valid path regex");

    IocSummary {
        ipv4: collect_regex_matches(strings, &ipv4_re),
        urls: collect_regex_matches(strings, &url_re),
        registry_paths: collect_regex_matches(strings, &registry_re),
        windows_paths: collect_regex_matches(strings, &path_re),
    }
}

fn collect_regex_matches(strings: &[String], regex: &Regex) -> Vec<String> {
    let mut values = HashSet::new();
    for string in strings {
        for matched in regex.find_iter(string) {
            values.insert(matched.as_str().to_string());
        }
    }
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

fn score_static_findings(
    whole_file_entropy: f64,
    pe: Option<&PeSummary>,
    iocs: &IocSummary,
    file_type: &str,
) -> (Vec<String>, f64) {
    let mut hypotheses = Vec::new();
    let mut score = 0.0;

    if !file_type.starts_with("PE") {
        hypotheses.push("non_windows_or_non_pe_sample".to_string());
    }

    if whole_file_entropy >= 7.2 {
        hypotheses.push("high_entropy".to_string());
        score += 20.0;
    }

    if !iocs.urls.is_empty() || !iocs.ipv4.is_empty() {
        hypotheses.push("network_iocs_present".to_string());
        score += 10.0;
    }

    if let Some(pe) = pe {
        let import_names = pe
            .imports
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let has_virtual_alloc = import_names
            .iter()
            .any(|value| value.contains("virtualalloc"));
        let has_write_process_memory = import_names
            .iter()
            .any(|value| value.contains("writeprocessmemory"));
        let has_create_remote_thread = import_names
            .iter()
            .any(|value| value.contains("createremotethread"));
        if has_virtual_alloc && has_write_process_memory && has_create_remote_thread {
            hypotheses.push("suspicious_imports:CreateRemoteThread".to_string());
            score += 25.0;
        }

        if pe.sections.iter().any(|section| section.entropy >= 7.2) {
            hypotheses.push("packed_or_encrypted_section".to_string());
            score += 20.0;
        }
    }

    hypotheses.sort();
    hypotheses.dedup();
    (hypotheses, score)
}

fn validate_bundle(bundle: &Path, verify_hashes: bool) -> Result<ValidationReport> {
    if !bundle.is_dir() {
        return contract_error(format!(
            "bundle path is not a directory: {}",
            bundle.display()
        ));
    }

    let manifest: Manifest = read_json(&bundle.join(MANIFEST_PATH))?;
    let sample_meta: SampleMeta = read_json(&bundle.join(SAMPLE_META_PATH))?;

    let mut warnings = Vec::new();
    validate_manifest_shape(&manifest)?;
    validate_sample_meta(&manifest, &sample_meta)?;
    validate_artifacts(bundle, &manifest)?;
    validate_telemetry(&manifest, &mut warnings)?;

    if verify_hashes {
        validate_hash_manifest(bundle, &manifest)?;
    }

    Ok(ValidationReport {
        session_id: manifest.session_id,
        status: manifest.status,
        telemetry_degraded: manifest.telemetry.telemetry_degraded,
        warnings,
    })
}

fn validate_manifest_shape(manifest: &Manifest) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        return contract_error(format!(
            "unsupported manifest schema_version: {}",
            manifest.schema_version
        ));
    }
    if manifest.session_id.is_empty() {
        return contract_error("session_id is empty");
    }
    if manifest.sample_sha256.len() != 64
        || !manifest
            .sample_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return contract_error("sample_sha256 must be 64 hex characters");
    }
    if manifest.static_risk_score.is_sign_negative() {
        return contract_error("static_risk_score must be non-negative");
    }
    if manifest.cape_task_id == 0 {
        return contract_error("cape_task_id must be positive");
    }
    for error in &manifest.errors {
        if error.stage.is_empty() || error.code.is_empty() || error.message.is_empty() {
            return contract_error(
                "manifest errors must include non-empty stage, code, and message",
            );
        }
    }
    if manifest.artifact_paths.pcap != PCAP_PATH {
        return contract_error(format!("artifact_paths.pcap must be {PCAP_PATH}"));
    }
    if manifest.artifact_paths.trace_etl != TRACE_ETL_PATH {
        return contract_error(format!("artifact_paths.trace_etl must be {TRACE_ETL_PATH}"));
    }
    if manifest.integrity.hash_manifest != HASH_MANIFEST_PATH {
        return contract_error(format!(
            "integrity.hash_manifest must be {HASH_MANIFEST_PATH}"
        ));
    }
    if manifest.integrity.hash_manifest_sha256.len() != 64
        || !manifest
            .integrity
            .hash_manifest_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return contract_error("integrity.hash_manifest_sha256 must be 64 hex characters");
    }
    if manifest.integrity.hash_log_ref.trim().is_empty() {
        return contract_error("integrity.hash_log_ref must not be empty");
    }
    Ok(())
}

fn validate_sample_meta(manifest: &Manifest, sample_meta: &SampleMeta) -> Result<()> {
    if sample_meta.schema_version != SCHEMA_VERSION {
        return contract_error(format!(
            "unsupported sample.meta.json schema_version: {}",
            sample_meta.schema_version
        ));
    }
    if sample_meta.sample_sha256 != manifest.sample_sha256 {
        return contract_error("sample.meta.json sample_sha256 does not match manifest");
    }
    if (sample_meta.static_risk_score - manifest.static_risk_score).abs() > f64::EPSILON {
        return contract_error("sample.meta.json static_risk_score does not match manifest");
    }
    Ok(())
}

fn validate_artifacts(bundle: &Path, manifest: &Manifest) -> Result<()> {
    ensure_non_empty(bundle.join(SAMPLE_META_PATH))?;

    match manifest.status {
        SessionStatus::Completed => {
            ensure_non_empty(bundle.join(&manifest.artifact_paths.pcap))?;
            ensure_non_empty(bundle.join(&manifest.artifact_paths.trace_etl))?;
            ensure_non_empty(bundle.join(HASH_MANIFEST_PATH))?;
        }
        SessionStatus::CaptureError => {
            if manifest.errors.iter().all(|error| error.stage != "capture") {
                return contract_error(
                    "capture_error status requires at least one capture-stage error",
                );
            }
        }
        SessionStatus::AnalysisError | SessionStatus::Timeout => {}
    }

    Ok(())
}

fn validate_telemetry(manifest: &Manifest, warnings: &mut Vec<String>) -> Result<()> {
    let telemetry = &manifest.telemetry;
    if telemetry.format != "etl" {
        return contract_error("telemetry.format must be etl");
    }
    if telemetry.artifact_path != TRACE_ETL_PATH {
        return contract_error(format!("telemetry.artifact_path must be {TRACE_ETL_PATH}"));
    }
    if manifest.status == SessionStatus::Completed
        && (!telemetry.capture_started || !telemetry.capture_completed)
    {
        return contract_error(
            "completed sessions require telemetry capture_started and capture_completed",
        );
    }

    let targeted: HashSet<&str> = telemetry
        .providers_targeted
        .iter()
        .map(String::as_str)
        .collect();
    for enabled in &telemetry.providers_enabled {
        if !targeted.contains(enabled.as_str()) {
            warnings.push(format!(
                "provider enabled but not listed as targeted: {enabled}"
            ));
        }
    }

    if telemetry.telemetry_degraded {
        if telemetry.degradation_reasons.is_empty() {
            return contract_error("telemetry_degraded requires at least one degradation reason");
        }
    } else if !telemetry.degradation_reasons.is_empty()
        || !telemetry.providers_unavailable.is_empty()
    {
        return contract_error(
            "non-degraded telemetry cannot include degradation_reasons or providers_unavailable",
        );
    }

    for issue in telemetry
        .degradation_reasons
        .iter()
        .chain(telemetry.providers_unavailable.iter())
    {
        if issue.provider.is_empty() {
            return contract_error("provider issue has empty provider");
        }
        if issue.message.is_empty() {
            return contract_error(format!(
                "provider issue for {} has empty message",
                issue.provider
            ));
        }
        match issue.reason {
            ProviderIssueReason::ProviderMissing
            | ProviderIssueReason::AccessDenied
            | ProviderIssueReason::NoEventsObserved
            | ProviderIssueReason::AgentError
            | ProviderIssueReason::Unknown => {}
        }
    }

    match telemetry.etw_ti_status {
        EtwTiStatus::Unavailable | EtwTiStatus::EnabledNoEvents => {
            if !telemetry.telemetry_degraded {
                warnings.push(
                    "ETW-TI status indicates reduced coverage but telemetry_degraded is false"
                        .to_string(),
                );
            }
        }
        EtwTiStatus::EnabledAndObserved | EtwTiStatus::NotAttempted => {}
    }

    Ok(())
}

fn validate_hash_manifest(bundle: &Path, manifest: &Manifest) -> Result<()> {
    let hash_manifest_path = bundle.join(HASH_MANIFEST_PATH);
    let content = read_to_string(&hash_manifest_path)?;
    let actual_hash_manifest_sha256 = sha256_file(&hash_manifest_path)?;
    if actual_hash_manifest_sha256 != manifest.integrity.hash_manifest_sha256.to_ascii_lowercase() {
        return contract_error(format!(
            "hashes.sha256 digest mismatch: manifest={} actual={}",
            manifest.integrity.hash_manifest_sha256, actual_hash_manifest_sha256
        ));
    }

    let expected = parse_hash_manifest(&content)?;
    if manifest.status == SessionStatus::Completed {
        for relative in [SAMPLE_META_PATH, PCAP_PATH, TRACE_ETL_PATH] {
            validate_hash_entry(bundle, &expected, relative)?;
        }
    } else {
        validate_hash_entry(bundle, &expected, SAMPLE_META_PATH)?;
        for relative in [PCAP_PATH, TRACE_ETL_PATH] {
            if expected.contains_key(relative) {
                validate_hash_entry(bundle, &expected, relative)?;
            }
        }
    }

    Ok(())
}

fn validate_hash_entry(
    bundle: &Path,
    hashes: &HashMap<String, String>,
    relative: &str,
) -> Result<()> {
    let expected_hash = hashes
        .get(relative)
        .ok_or_else(|| ValidationError::Contract(format!("hashes.sha256 missing {relative}")))?;
    let actual_hash = sha256_file(&bundle.join(relative))?;
    if *expected_hash != actual_hash {
        return contract_error(format!(
            "digest mismatch for {relative}: expected={expected_hash} actual={actual_hash}"
        ));
    }

    Ok(())
}

fn parse_hash_manifest(content: &str) -> Result<HashMap<String, String>> {
    let mut hashes = HashMap::new();
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let hash = parts
            .next()
            .ok_or_else(|| ValidationError::Contract(format!("invalid hash line {}", index + 1)))?;
        let path = parts
            .next()
            .ok_or_else(|| ValidationError::Contract(format!("invalid hash line {}", index + 1)))?;
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return contract_error(format!("invalid sha256 on line {}", index + 1));
        }
        hashes.insert(path.to_string(), hash.to_ascii_lowercase());
    }
    Ok(hashes)
}

fn print_report(bundle: &Path, report: &ValidationReport) {
    println!(
        "accepted bundle={} session_id={} status={:?} telemetry_degraded={}",
        bundle.display(),
        report.session_id,
        report.status,
        report.telemetry_degraded
    );
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

fn read_dir_sorted(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| ValidationError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<std::result::Result<Vec<_>, io::Error>>()
        .map_err(|source| ValidationError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.path());
    Ok(entries)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = read_to_string(path)?;
    serde_json::from_str(&content).map_err(|source| ValidationError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| ValidationError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn ensure_non_empty(path: PathBuf) -> Result<()> {
    let metadata = fs::metadata(&path).map_err(|source| ValidationError::Read {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return contract_error(format!(
            "required artifact is not a file: {}",
            path.display()
        ));
    }
    if metadata.len() == 0 {
        return contract_error(format!("required artifact is empty: {}", path.display()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|source| ValidationError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| ValidationError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn contract_error<T>(message: impl Into<String>) -> Result<T> {
    Err(ValidationError::Contract(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_complete_fixture() {
        let report = validate_bundle(Path::new("tests/fixtures/handoff/valid_complete"), true)
            .expect("valid fixture should pass");
        assert_eq!(report.session_id, "1001");
        assert!(!report.telemetry_degraded);
    }

    #[test]
    fn accepts_degraded_optional_provider_fixture() {
        let report = validate_bundle(
            Path::new("tests/fixtures/handoff/degraded_optional_provider"),
            true,
        )
        .expect("degraded fixture should pass");
        assert_eq!(report.session_id, "1002");
        assert!(report.telemetry_degraded);
    }

    #[test]
    fn rejects_completed_bundle_missing_etl() {
        let error = validate_bundle(
            Path::new("tests/fixtures/handoff/invalid_missing_etl"),
            false,
        )
        .expect_err("missing ETL must fail completed bundle");
        assert!(error.to_string().contains("behavior/trace.etl"));
    }

    #[test]
    fn pretriage_extracts_iocs_from_fixture() {
        let report = pretriage_sample(Path::new("tests/fixtures/pretriage/pseudo_pe.bin"), 100)
            .expect("pretriage should parse fixture");
        assert_eq!(report.file_type, "PE executable");
        assert!(
            report
                .iocs
                .urls
                .contains(&"http://example.test/path".to_string())
        );
        assert!(report.iocs.ipv4.contains(&"192.0.2.10".to_string()));
        assert!(
            report
                .iocs
                .registry_paths
                .contains(&"HKLM\\Software\\Microsoft".to_string())
        );
        assert!(
            report
                .iocs
                .windows_paths
                .contains(&"C:\\Users\\Analyst\\Downloads\\payload.exe".to_string())
        );
    }

    #[test]
    fn pretriage_flags_non_pe_text() {
        let report = pretriage_sample(Path::new("tests/fixtures/pretriage/plain.txt"), 100)
            .expect("pretriage should parse text fixture");
        assert_eq!(report.file_type, "ASCII text");
        assert!(
            report
                .static_hypotheses
                .contains(&"non_windows_or_non_pe_sample".to_string())
        );
    }

    #[test]
    fn parses_etw_agent_config_fixture() {
        let config = read_etw_agent_config(Path::new("scripts/etw_agent/etw-agent.config.json"))
            .expect("ETW config fixture should parse");
        assert_eq!(config.session_name, "DiagTrack-Compatibility");
        assert_eq!(config.providers.len(), 6);
        assert!(config.providers.iter().any(|provider| provider.name
            == "Microsoft-Windows-Threat-Intelligence"
            && provider.tier == EtwProviderTier::Optional));
    }

    #[test]
    fn etw_metadata_marks_optional_provider_degradation() {
        let state = EtwAgentState {
            schema_version: SCHEMA_VERSION.to_string(),
            session_name: "DiagTrack-Compatibility".to_string(),
            trace_path: PathBuf::from(r"C:\ProgramData\WinSTDT\behavior\trace.etl"),
            capture_started: true,
            providers_targeted: vec![
                "Microsoft-Windows-Kernel-Process".to_string(),
                "Microsoft-Windows-Kernel-Image".to_string(),
                "Microsoft-Windows-Threat-Intelligence".to_string(),
            ],
            providers_enabled: vec!["Microsoft-Windows-Kernel-Process".to_string()],
            providers_unavailable: vec![
                EtwProviderIssue {
                    provider: "Microsoft-Windows-Kernel-Image".to_string(),
                    reason: "provider_missing".to_string(),
                    message: "provider not present".to_string(),
                },
                EtwProviderIssue {
                    provider: "Microsoft-Windows-Threat-Intelligence".to_string(),
                    reason: "access_denied".to_string(),
                    message: "provider requires elevated access".to_string(),
                },
            ],
        };

        let telemetry = etw_telemetry_from_state(&state, true);

        assert!(telemetry.capture_started);
        assert!(telemetry.capture_completed);
        assert!(telemetry.telemetry_degraded);
        assert_eq!(telemetry.degradation_reasons.len(), 2);
        assert_eq!(telemetry.etw_ti_status, "unavailable");
    }

    #[test]
    fn etw_metadata_records_etw_ti_probe_without_observed_events() {
        let state = EtwAgentState {
            schema_version: SCHEMA_VERSION.to_string(),
            session_name: "DiagTrack-Compatibility".to_string(),
            trace_path: PathBuf::from(r"C:\ProgramData\WinSTDT\behavior\trace.etl"),
            capture_started: true,
            providers_targeted: vec!["Microsoft-Windows-Threat-Intelligence".to_string()],
            providers_enabled: vec!["Microsoft-Windows-Threat-Intelligence".to_string()],
            providers_unavailable: Vec::new(),
        };

        let telemetry = etw_telemetry_from_state(&state, true);

        assert!(!telemetry.telemetry_degraded);
        assert_eq!(telemetry.etw_ti_status, "enabled_no_events");
    }
}
