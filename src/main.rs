use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, ExitCode},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use goblin::pe::{PE, section_table::SectionTable};
use md5::Md5;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

const SCHEMA_VERSION: &str = "1.0";
const TRACE_ETL_PATH: &str = "behavior/trace.etl";
const PCAP_PATH: &str = "network/capture.pcapng";
const HASH_MANIFEST_PATH: &str = "hashes.sha256";
const MANIFEST_PATH: &str = "manifest.json";
const SAMPLE_META_PATH: &str = "sample.meta.json";
const REPORT_JSON_PATH: &str = "report.json";
const REPORT_HTML_PATH: &str = "report.html";

#[derive(Debug, Parser)]
#[command(name = "winstdt")]
#[command(about = "WinST/DT handoff contract tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Emit the guest UTC Unix timestamp in nanoseconds for host clock alignment.
    ClockSample,
    /// Validate one completed handoff bundle directory.
    ValidateBundle {
        /// Path to /handoff/{session_id}.
        bundle: PathBuf,
        /// Skip hashes.sha256 content validation.
        #[arg(long)]
        skip_hashes: bool,
    },
    /// Validate a completed derived C2 result bundle and its immutable handoff.
    ValidateC2Result {
        /// Path to /srv/winstdt/c2-results/{task_id}.
        result_directory: PathBuf,
        /// Immutable CAPE handoff used as analyzer input.
        #[arg(long)]
        handoff: PathBuf,
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
    /// Generate stable analyst JSON and HTML reports for a bundle.
    ReportBundle {
        /// Path to /handoff/{session_id}.
        bundle: PathBuf,
        /// Output path for report.json.
        #[arg(long)]
        json: PathBuf,
        /// Output path for report.html.
        #[arg(long)]
        html: PathBuf,
    },
    /// Compare ETW and capemon coverage signals for a bundle.
    CompareTelemetry {
        /// Path to /handoff/{session_id}.
        bundle: PathBuf,
    },
    /// Remove old completed handoff bundles while respecting a free-space floor.
    CleanupHandoff {
        /// Path to /handoff.
        root: PathBuf,
        /// Only remove bundle directories older than this many days.
        #[arg(long)]
        max_age_days: u64,
        /// Stop cleanup once this free-space floor is met.
        #[arg(long)]
        min_free_gb: f64,
    },
    /// Summarize local handoff health and gated runtime status.
    MonitorHealth {
        /// Path to /handoff.
        #[arg(long, default_value = "/srv/winstdt/handoff")]
        handoff_root: PathBuf,
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
    #[serde(default = "default_profile")]
    profile: String,
    #[serde(default)]
    resolved_options: Value,
    #[serde(default)]
    capabilities: Value,
}

fn default_profile() -> String {
    "standard".to_string()
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SessionStatus {
    Completed,
    CaptureError,
    AnalysisError,
    Timeout,
}

impl SessionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Completed => "completed",
            SessionStatus::CaptureError => "capture_error",
            SessionStatus::AnalysisError => "analysis_error",
            SessionStatus::Timeout => "timeout",
        }
    }
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
    #[serde(default)]
    report_json: Option<String>,
    #[serde(default)]
    report_html: Option<String>,
    #[serde(default)]
    events_jsonl: Option<String>,
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
struct AnalystReport {
    schema_version: &'static str,
    generated_at_unix: u64,
    session_id: String,
    validation: ReportValidation,
    sample: Value,
    cape: Value,
    telemetry: Value,
    profile: Value,
    resolved_options: Value,
    capabilities: Value,
    artifact_paths: Value,
    enrichment: Value,
    residual_anti_evasion_risks: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ReportValidation {
    status: String,
    telemetry_degraded: bool,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct HandoffHealth {
    total_bundles: usize,
    completed: usize,
    capture_error: usize,
    analysis_error: usize,
    timeout: usize,
    degraded: usize,
}

#[derive(Debug, Default)]
struct MongoHealth {
    version: Option<String>,
    bind_addresses: Vec<String>,
    packages_held: Option<bool>,
    exposure_pass: Option<bool>,
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
        Command::ClockSample => match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                println!("{}", duration.as_nanos());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("clock-sample failed: {error}");
                ExitCode::from(1)
            }
        },
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
        Command::ValidateC2Result {
            result_directory,
            handoff,
        } => match validate_c2_result(&result_directory, &handoff) {
            Ok(()) => {
                println!("accepted C2 result={}", result_directory.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("invalid C2 result {}: {error}", result_directory.display());
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
        Command::ReportBundle { bundle, json, html } => {
            match report_bundle(&bundle, &json, &html) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("report-bundle failed for {}: {error}", bundle.display());
                    ExitCode::from(1)
                }
            }
        }
        Command::CompareTelemetry { bundle } => match compare_telemetry(&bundle) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("compare-telemetry failed for {}: {error}", bundle.display());
                ExitCode::from(1)
            }
        },
        Command::CleanupHandoff {
            root,
            max_age_days,
            min_free_gb,
        } => match cleanup_handoff(&root, max_age_days, min_free_gb) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("cleanup-handoff failed for {}: {error}", root.display());
                ExitCode::from(1)
            }
        },
        Command::MonitorHealth { handoff_root } => match monitor_health(&handoff_root) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!(
                    "monitor-health failed for {}: {error}",
                    handoff_root.display()
                );
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

fn report_bundle(bundle: &Path, json_path: &Path, html_path: &Path) -> Result<()> {
    let validation = validate_bundle(bundle, true)?;
    let manifest: Value = read_json(&bundle.join(MANIFEST_PATH))?;
    let sample_meta: Value = read_json(&bundle.join(SAMPLE_META_PATH))?;
    let report = build_analyst_report(&validation, &manifest, &sample_meta);
    write_json_file(json_path, &report)?;
    write_text_file(html_path, &render_analyst_report_html(&report))
}

fn build_analyst_report(
    validation: &ValidationReport,
    manifest: &Value,
    sample_meta: &Value,
) -> AnalystReport {
    AnalystReport {
        schema_version: SCHEMA_VERSION,
        generated_at_unix: now_unix_seconds(),
        session_id: validation.session_id.clone(),
        validation: ReportValidation {
            status: validation.status.as_str().to_string(),
            telemetry_degraded: validation.telemetry_degraded,
            warnings: validation.warnings.clone(),
        },
        sample: json!({
            "hashes": {
                "sha256": value_at(sample_meta, "/sample_sha256"),
                "sha1": value_at(sample_meta, "/sample_sha1"),
                "md5": value_at(sample_meta, "/sample_md5")
            },
            "file_type": value_at(sample_meta, "/file_type"),
            "static_risk_score": value_at(sample_meta, "/static_risk_score"),
            "static_hypotheses": value_at(sample_meta, "/static_hypotheses")
        }),
        cape: json!({
            "task_id": value_at(manifest, "/cape_task_id"),
            "status": value_at(manifest, "/status"),
            "submitted_at_utc": value_at(manifest, "/submitted_at_utc"),
            "detonation_start_utc": value_at(manifest, "/detonation_start_utc"),
            "detonation_end_utc": value_at(manifest, "/detonation_end_utc"),
            "guest_vm_identity": value_at(manifest, "/guest_vm_identity"),
            "capemon_enabled": value_at(manifest, "/capemon_enabled")
        }),
        telemetry: json!({
            "etw_provider_state": value_at(manifest, "/telemetry"),
            "telemetry_degradation_warnings": value_at(manifest, "/telemetry/degradation_reasons")
        }),
        profile: value_at(manifest, "/profile"),
        resolved_options: value_at(manifest, "/resolved_options"),
        capabilities: value_at(manifest, "/capabilities"),
        artifact_paths: value_at(manifest, "/artifact_paths"),
        enrichment: json!({
            "yara": value_at(sample_meta, "/yara"),
            "clamav": value_at(sample_meta, "/clamav"),
            "virustotal": value_at(sample_meta, "/vt_lookup")
        }),
        residual_anti_evasion_risks: residual_anti_evasion_risks(),
    }
}

fn render_analyst_report_html(report: &AnalystReport) -> String {
    let report_json = serde_json::to_value(report).unwrap_or_else(|_| json!({}));
    let artifact_paths = report
        .artifact_paths
        .as_object()
        .map(|paths| {
            paths
                .iter()
                .map(|(name, path)| {
                    format!(
                        "<li><code>{}</code>: <code>{}</code></li>",
                        escape_html(name),
                        escape_html(path.as_str().unwrap_or(""))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    format!(
        concat!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<title>WinST/DT Report {session}</title>",
            "<style>body{{font-family:Arial,sans-serif;margin:32px;line-height:1.45;color:#202124}}",
            "code,pre{{background:#f4f6f8;border:1px solid #d9dde3;border-radius:4px}}",
            "code{{padding:1px 4px}}pre{{padding:16px;overflow:auto}}",
            ".status{{font-weight:700}}</style></head><body>",
            "<h1>WinST/DT Analyst Report</h1>",
            "<p>Session <code>{session}</code> validation status: <span class=\"status\">{status}</span></p>",
            "<h2>Artifacts</h2><ul>{artifacts}</ul>",
            "<h2>Report Model</h2><pre>{model}</pre>",
            "</body></html>\n"
        ),
        session = escape_html(&report.session_id),
        status = escape_html(&report.validation.status),
        artifacts = artifact_paths,
        model = escape_html(&serde_json::to_string_pretty(&report_json).unwrap_or_default())
    )
}

fn compare_telemetry(bundle: &Path) -> Result<()> {
    let validation = validate_bundle(bundle, true)?;
    let manifest: Value = read_json(&bundle.join(MANIFEST_PATH))?;
    let telemetry = value_at(&manifest, "/telemetry");
    let capemon_enabled = value_at(&manifest, "/capemon_enabled")
        .as_bool()
        .unwrap_or(true);
    let degraded = telemetry
        .get("telemetry_degraded")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let enabled_count = telemetry
        .get("providers_enabled")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    let targeted_count = telemetry
        .get("providers_targeted")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    let decision = if capemon_enabled {
        "keep_capemon_enabled"
    } else if degraded || enabled_count < targeted_count {
        "re_enable_capemon"
    } else {
        "capemon_disabled_by_config"
    };

    println!(
        "session_id={} validation_status={:?} capemon_enabled={} etw_enabled={}/{} telemetry_degraded={} decision={}",
        validation.session_id,
        validation.status,
        capemon_enabled,
        enabled_count,
        targeted_count,
        degraded,
        decision
    );
    for warning in validation.warnings {
        println!("warning: {warning}");
    }
    Ok(())
}

fn cleanup_handoff(root: &Path, max_age_days: u64, min_free_gb: f64) -> Result<()> {
    if max_age_days == 0 {
        return contract_error("--max-age-days must be greater than zero");
    }
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(max_age_days.saturating_mul(86_400)))
        .ok_or_else(|| ValidationError::Contract("invalid max age".to_string()))?;
    let mut removed = 0_usize;
    let mut candidates = bundle_dirs_older_than(root, cutoff)?;
    candidates.sort_by_key(|path| {
        path.metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    });

    for bundle in candidates {
        if free_gb(root)? >= min_free_gb {
            break;
        }
        fs::remove_dir_all(&bundle).map_err(|source| ValidationError::Write {
            path: bundle.clone(),
            source,
        })?;
        removed += 1;
    }

    println!(
        "cleanup_handoff root={} removed={} free_gb={:.2}",
        root.display(),
        removed,
        free_gb(root)?
    );
    Ok(())
}

fn monitor_health(root: &Path) -> Result<()> {
    let health = handoff_health(root)?;
    let degradation_rate = if health.total_bundles == 0 {
        0.0
    } else {
        health.degraded as f64 / health.total_bundles as f64
    };
    let free = free_gb(root)?;
    let golden_report = env::var_os("WINSTDT_GOLDEN_IMAGE_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("docs/validation/golden_image_report_current.md"));
    let stale_days = golden_report_age_days(&golden_report).unwrap_or(u64::MAX);
    let stale_limit = env::var("WINSTDT_GOLDEN_IMAGE_MAX_AGE_DAYS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    let golden_decision = read_to_string(&golden_report)
        .ok()
        .and_then(|content| current_golden_decision(&content))
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "handoff_health root={} total={} completed={} capture_error={} analysis_error={} timeout={} telemetry_degraded={} degradation_rate={:.3}",
        root.display(),
        health.total_bundles,
        health.completed,
        health.capture_error,
        health.analysis_error,
        health.timeout,
        health.degraded,
        degradation_rate
    );
    println!("disk_pressure root={} free_gb={:.2}", root.display(), free);
    println!(
        "golden_image report={} decision={} age_days={} stale={}",
        golden_report.display(),
        golden_decision,
        stale_days,
        stale_days > stale_limit || !golden_decision.eq_ignore_ascii_case("accepted")
    );
    println!(
        "gates events_jsonl={} streaming_handoff={} live_egress={} vm_count={}",
        env_flag("WINSTDT_ENABLE_EVENTS_JSONL"),
        env_flag("WINSTDT_STREAMING_HANDOFF"),
        env_flag("WINSTDT_LIVE_EGRESS_ENABLED"),
        env::var("WINSTDT_VM_COUNT").unwrap_or_else(|_| "1".to_string())
    );
    let mongo = mongo_health();
    let version = mongo.version.as_deref().unwrap_or("unknown");
    let secure_exception = version == "8.0.4";
    let bind = if mongo.bind_addresses.is_empty() {
        "unknown".to_string()
    } else {
        mongo.bind_addresses.join(",")
    };
    let packages_held = mongo.packages_held.map(bool_word).unwrap_or("unknown");
    let exposure = match mongo.exposure_pass {
        Some(true) => "pass",
        Some(false) => "fail",
        None => "unknown",
    };
    println!(
        "mongodb_version={} mongodb_secure_exception={} mongodb_bind={} mongodb_packages_held={} mongodb_exposure={}",
        version,
        bool_word(secure_exception),
        bind,
        packages_held,
        exposure
    );
    Ok(())
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
        "-f",
        "bincirc",
        "-max",
        "64",
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
    if !once && !env_flag("WINSTDT_STREAMING_HANDOFF") {
        return contract_error(
            "watch mode requires WINSTDT_STREAMING_HANDOFF=1; use --once for batch handoff",
        );
    }
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
    let yara = run_yara_tiers(sample);
    let clamav = run_clamav(sample);
    let vt_lookup = run_vt_hash_lookup(&sample_sha256);
    let (static_hypotheses, static_risk_score) =
        score_static_findings(whole_file_entropy, pe.as_ref(), &iocs, &file_type);
    let (static_hypotheses, static_risk_score) = score_scanner_findings(
        static_hypotheses,
        static_risk_score,
        &yara,
        &clamav,
        &vt_lookup,
    );

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
        yara,
        clamav,
        vt_lookup,
        strings: StringSummary {
            ascii_count: ascii_strings.len(),
            utf16le_count: utf16le_strings.len(),
            extracted: all_strings,
        },
        iocs,
        pe,
    })
}

fn run_yara_tiers(sample: &Path) -> YaraSummary {
    YaraSummary {
        fast_hits: env::var_os("WINSTDT_YARA_FAST_RULES")
            .map(PathBuf::from)
            .map(|rules| run_yara_rules(&rules, sample))
            .unwrap_or_default(),
        deep_hits: env::var_os("WINSTDT_YARA_DEEP_RULES")
            .map(PathBuf::from)
            .map(|rules| run_yara_rules(&rules, sample))
            .unwrap_or_default(),
    }
}

fn run_yara_rules(rules: &Path, sample: &Path) -> Vec<String> {
    if !rules.exists() || command_missing("yara") {
        return Vec::new();
    }
    let output = ProcessCommand::new("yara")
        .arg("-r")
        .arg(rules)
        .arg(sample)
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() && output.status.code() != Some(1) {
        return Vec::new();
    }
    parse_yara_hits(&String::from_utf8_lossy(&output.stdout))
}

fn parse_yara_hits(output: &str) -> Vec<String> {
    let mut hits = output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|rule| !rule.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    hits.sort();
    hits.dedup();
    hits
}

fn run_clamav(sample: &Path) -> ClamAvSummary {
    if env_flag("WINSTDT_DISABLE_CLAMAV") || command_missing("clamscan") {
        return ClamAvSummary {
            status: "not_run".to_string(),
            signature: None,
        };
    }
    let output = ProcessCommand::new("clamscan")
        .arg("--no-summary")
        .arg(sample)
        .output();
    let Ok(output) = output else {
        return ClamAvSummary {
            status: "unavailable".to_string(),
            signature: None,
        };
    };
    match output.status.code() {
        Some(0) => ClamAvSummary {
            status: "clean".to_string(),
            signature: None,
        },
        Some(1) => ClamAvSummary {
            status: "infected".to_string(),
            signature: parse_clamav_signature(&String::from_utf8_lossy(&output.stdout)),
        },
        _ => ClamAvSummary {
            status: "error".to_string(),
            signature: None,
        },
    }
}

fn parse_clamav_signature(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.rsplit_once(": ")
            .and_then(|(_, verdict)| verdict.strip_suffix(" FOUND"))
            .map(ToString::to_string)
    })
}

fn run_vt_hash_lookup(sha256: &str) -> String {
    let Some(api_key) = env::var("VIRUSTOTAL_API_KEY")
        .ok()
        .or_else(|| env::var("VT_API_KEY").ok())
        .filter(|value| !value.trim().is_empty())
    else {
        return "not_configured".to_string();
    };
    if command_missing("curl") {
        return "unavailable".to_string();
    }
    let output = ProcessCommand::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail")
        .arg("--max-time")
        .arg("10")
        .arg("--header")
        .arg(format!("x-apikey: {api_key}"))
        .arg(format!("https://www.virustotal.com/api/v3/files/{sha256}"))
        .output();
    let Ok(output) = output else {
        return "unavailable".to_string();
    };
    if !output.status.success() {
        return "unavailable".to_string();
    }
    summarize_vt_response(&String::from_utf8_lossy(&output.stdout))
}

fn summarize_vt_response(response: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(response) else {
        return "unavailable".to_string();
    };
    let Some(stats) = value
        .pointer("/data/attributes/last_analysis_stats")
        .and_then(Value::as_object)
    else {
        return "not_found".to_string();
    };
    let malicious = stats
        .get("malicious")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let suspicious = stats
        .get("suspicious")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let harmless = stats
        .get("harmless")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    format!("found:malicious={malicious},suspicious={suspicious},harmless={harmless}")
}

fn command_missing(command: &str) -> bool {
    ProcessCommand::new(command)
        .arg("--version")
        .output()
        .is_err()
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "yes" | "true" | "on"
            )
        })
        .unwrap_or(false)
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

fn score_scanner_findings(
    mut hypotheses: Vec<String>,
    mut score: f64,
    yara: &YaraSummary,
    clamav: &ClamAvSummary,
    vt_lookup: &str,
) -> (Vec<String>, f64) {
    if !yara.fast_hits.is_empty() {
        hypotheses.push("yara_fast_hit".to_string());
        score += 40.0;
    }
    if !yara.deep_hits.is_empty() {
        hypotheses.push("yara_deep_hit".to_string());
        score += 25.0;
    }
    if clamav.status == "infected" {
        hypotheses.push("clamav_detected".to_string());
        score += 35.0;
    }
    if vt_lookup_malicious_count(vt_lookup) > 0 {
        hypotheses.push("virustotal_hash_reputation".to_string());
        score += 20.0;
    }
    hypotheses.sort();
    hypotheses.dedup();
    (hypotheses, score)
}

fn vt_lookup_malicious_count(vt_lookup: &str) -> u64 {
    vt_lookup
        .strip_prefix("found:")
        .and_then(|stats| {
            stats.split(',').find_map(|part| {
                part.strip_prefix("malicious=")
                    .and_then(|value| value.parse::<u64>().ok())
            })
        })
        .unwrap_or_default()
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
    validate_capabilities(bundle, &manifest)?;

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
    if !matches!(
        manifest.profile.as_str(),
        "standard" | "deep_static" | "tls_intercept" | "full_memory" | "full_investigation"
    ) {
        return contract_error(format!(
            "unsupported analysis profile: {}",
            manifest.profile
        ));
    }
    if !manifest.resolved_options.is_null() && !manifest.resolved_options.is_object() {
        return contract_error("resolved_options must be an object");
    }
    if !manifest.capabilities.is_null() && !manifest.capabilities.is_object() {
        return contract_error("capabilities must be an object");
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
    if let Some(path) = &manifest.artifact_paths.report_json {
        if path != REPORT_JSON_PATH {
            return contract_error(format!(
                "artifact_paths.report_json must be {REPORT_JSON_PATH}"
            ));
        }
    }
    if let Some(path) = &manifest.artifact_paths.report_html {
        if path != REPORT_HTML_PATH {
            return contract_error(format!(
                "artifact_paths.report_html must be {REPORT_HTML_PATH}"
            ));
        }
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
            ensure_optional_artifact(bundle, manifest.artifact_paths.report_json.as_deref())?;
            ensure_optional_artifact(bundle, manifest.artifact_paths.report_html.as_deref())?;
            ensure_optional_artifact(bundle, manifest.artifact_paths.events_jsonl.as_deref())?;
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

fn ensure_optional_artifact(bundle: &Path, relative: Option<&str>) -> Result<()> {
    if let Some(relative) = relative {
        ensure_non_empty(bundle.join(relative))?;
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
    for path in walk_files(bundle)? {
        let relative = path
            .strip_prefix(bundle)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if relative != MANIFEST_PATH && relative != HASH_MANIFEST_PATH {
            validate_hash_entry(bundle, &expected, &relative)?;
        }
    }
    if manifest.status == SessionStatus::Completed {
        for relative in [SAMPLE_META_PATH, PCAP_PATH, TRACE_ETL_PATH] {
            validate_hash_entry(bundle, &expected, relative)?;
        }
        for relative in [
            manifest.artifact_paths.report_json.as_deref(),
            manifest.artifact_paths.report_html.as_deref(),
            manifest.artifact_paths.events_jsonl.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
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

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).map_err(|source| ValidationError::Read {
            path: dir.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| ValidationError::Read {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn validate_capabilities(bundle: &Path, manifest: &Manifest) -> Result<()> {
    if manifest.capabilities.is_null() {
        return Ok(());
    }
    let root = manifest
        .capabilities
        .as_object()
        .ok_or_else(|| ValidationError::Contract("capabilities must be an object".into()))?;
    for section in ["static", "dynamic"] {
        let values = root
            .get(section)
            .and_then(Value::as_object)
            .ok_or_else(|| ValidationError::Contract(format!("capabilities.{section} missing")))?;
        for (name, capability) in values {
            let requested = capability
                .get("requested")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    ValidationError::Contract(format!("capability {name} requested missing"))
                })?;
            let status = capability
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("");
            if requested && status == "not_requested" {
                return contract_error(format!(
                    "requested capability {name} cannot be not_requested"
                ));
            }
            if !requested && status != "not_requested" {
                return contract_error(format!(
                    "optional capability {name} must be not_requested when disabled"
                ));
            }
            if status.starts_with("completed") {
                let artifact = bundle.join("analysis").join(format!("{name}.json"));
                if matches!(name.as_str(), "capa" | "floss" | "die" | "trid") && !artifact.is_file()
                {
                    return contract_error(format!(
                        "completed capability {name} lacks {}",
                        artifact.display()
                    ));
                }
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

fn collect_regular_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current).map_err(|source| ValidationError::Read {
        path: current.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ValidationError::Read {
            path: current.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ValidationError::Read {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return contract_error(format!(
                "result bundle contains symlink: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_regular_files(root, &path, files)?;
        } else if metadata.is_file() {
            files.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
        }
    }
    Ok(())
}

fn required_identity(
    value: &Value,
    task_id: u64,
    sample: &str,
    pcap: &str,
    label: &str,
) -> Result<()> {
    let actual_task = value.get("task_id").and_then(Value::as_u64);
    let actual_sample = value
        .get("sample_id")
        .and_then(Value::as_str)
        .or_else(|| value.get("sample_sha256").and_then(Value::as_str));
    let actual_pcap = value.get("pcap_sha256").and_then(Value::as_str);
    if actual_task != Some(task_id) || actual_sample != Some(sample) || actual_pcap != Some(pcap) {
        return contract_error(format!("identity mismatch in {label}"));
    }
    Ok(())
}

fn validate_status_map(value: &Value, name: &str, allowed: &[&str]) -> Result<()> {
    let map = value
        .as_object()
        .ok_or_else(|| ValidationError::Contract(format!("provenance.{name} must be an object")))?;
    if map.is_empty() {
        return contract_error(format!(
            "provenance.{name} must explicitly cover every stage/input"
        ));
    }
    for (key, status) in map {
        if !allowed.contains(&status.as_str().unwrap_or("")) {
            return contract_error(format!("invalid status for {name}.{key}"));
        }
    }
    Ok(())
}

fn validate_c2_result(result: &Path, handoff: &Path) -> Result<()> {
    for relative in ["inputs", "output", "output/iocs", "zeek"] {
        if !result.join(relative).is_dir() {
            return contract_error(format!("missing result directory {relative}"));
        }
    }
    for relative in [
        "output/events.json",
        "output/attribution.json",
        "output/timeline.json",
        "analyzer.log",
        "provenance.json",
        HASH_MANIFEST_PATH,
    ] {
        ensure_non_empty(result.join(relative))?;
    }
    let provenance: Value = read_json(&result.join("provenance.json"))?;
    let task_id = provenance
        .get("task_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| ValidationError::Contract("provenance task_id missing".into()))?;
    let sample = provenance
        .get("sample_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| ValidationError::Contract("provenance sample_sha256 missing".into()))?;
    let pcap = provenance
        .get("pcap_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| ValidationError::Contract("provenance pcap_sha256 missing".into()))?;
    if sample.len() != 64
        || pcap.len() != 64
        || result.file_name().and_then(|v| v.to_str()) != Some(&task_id.to_string())
    {
        return contract_error("invalid result identity");
    }
    if provenance.get("fixture_usage").and_then(Value::as_bool) != Some(false) {
        return contract_error("production result declares fixture usage");
    }
    for key in [
        "upstream_repository",
        "upstream_commit",
        "compatibility_patch_hashes",
        "effective_runtime_tree_sha256",
        "dependency_lock_sha256",
        "input_hashes",
        "handoff_hashes",
        "correlation_mode",
        "zeek",
        "feed_revisions",
        "database_schema_version",
        "started_at_utc",
        "ended_at_utc",
        "warnings",
        "degraded_features",
    ] {
        if provenance.get(key).is_none() {
            return contract_error(format!("provenance missing {key}"));
        }
    }
    validate_status_map(
        &provenance["optional_inputs"],
        "optional_inputs",
        &["available", "disabled", "not_available", "invalid"],
    )?;
    validate_status_map(
        &provenance["stages"],
        "stages",
        &["complete", "degraded", "not_available", "failed"],
    )?;
    for relative in [
        "output/events.json",
        "output/attribution.json",
        "output/timeline.json",
    ] {
        required_identity(
            &read_json(&result.join(relative))?,
            task_id,
            sample,
            pcap,
            relative,
        )?;
    }
    required_identity(
        &read_json(&result.join("output/iocs/identity.json"))?,
        task_id,
        sample,
        pcap,
        "IOC export",
    )?;
    if result.join("output/sql-verification.json").is_file() {
        required_identity(
            &read_json(&result.join("output/sql-verification.json"))?,
            task_id,
            sample,
            pcap,
            "SQL verification",
        )?;
    }
    let event_doc: Value = read_json(&result.join("output/events.json"))?;
    let tiers = ["confirmed", "strong", "weak", "unconfirmed", "allowlisted"];
    for event in event_doc
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| ValidationError::Contract("events.json events array missing".into()))?
    {
        required_identity(event, task_id, sample, pcap, "network event")?;
        if !tiers.contains(
            &event
                .get("confidence_tier")
                .and_then(Value::as_str)
                .unwrap_or(""),
        ) {
            return contract_error("invalid event confidence tier");
        }
    }
    let attribution: Value = read_json(&result.join("output/attribution.json"))?;
    for finding in attribution
        .get("findings")
        .and_then(Value::as_array)
        .ok_or_else(|| ValidationError::Contract("attribution findings array missing".into()))?
    {
        if !["confirmed", "likely", "possible"]
            .contains(&finding["confidence"].as_str().unwrap_or(""))
            || !["static_prior", "threat_intel", "behavioural"]
                .contains(&finding["basis"].as_str().unwrap_or(""))
            || finding["evidence"].as_array().map(Vec::is_empty) != Some(false)
        {
            return contract_error("invalid attribution finding");
        }
    }
    let mut files = Vec::new();
    collect_regular_files(result, result, &mut files)?;
    let expected = parse_hash_manifest(&read_to_string(&result.join(HASH_MANIFEST_PATH))?)?;
    let actual: HashSet<String> = files
        .iter()
        .filter(|p| p.as_path() != Path::new(HASH_MANIFEST_PATH))
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    if actual != expected.keys().cloned().collect() {
        return contract_error(
            "hashes.sha256 does not cover every regular result artifact exactly once",
        );
    }
    for relative in &actual {
        validate_hash_entry(result, &expected, relative)?;
    }
    let handoff_hashes = provenance["handoff_hashes"]
        .as_object()
        .ok_or_else(|| ValidationError::Contract("handoff_hashes must be an object".into()))?;
    let mut handoff_files = Vec::new();
    collect_regular_files(handoff, handoff, &mut handoff_files)?;
    for relative in handoff_files {
        let key = relative.to_string_lossy();
        let expected_hash = handoff_hashes
            .get(key.as_ref())
            .and_then(Value::as_str)
            .ok_or_else(|| ValidationError::Contract(format!("handoff hash missing {key}")))?;
        if sha256_file(&handoff.join(&relative))? != expected_hash {
            return contract_error(format!("immutable handoff changed: {key}"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for relative in files {
            if fs::metadata(result.join(relative))
                .map_err(|source| ValidationError::Read {
                    path: result.to_path_buf(),
                    source,
                })?
                .permissions()
                .mode()
                & 0o222
                != 0
            {
                return contract_error("promoted result contains writable artifacts");
            }
        }
    }
    Ok(())
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

fn write_text_file(path: &Path, content: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, content).map_err(|source| ValidationError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn value_at(value: &Value, pointer: &str) -> Value {
    value.pointer(pointer).cloned().unwrap_or(Value::Null)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn residual_anti_evasion_risks() -> Vec<&'static str> {
    vec![
        "Timing/RDTSC side channels require manual anti-evasion validation.",
        "CPUID timing side channels remain a residual risk.",
        "Deep hypervisor introspection cannot be fully hidden by repo-level configuration.",
        "Driver, kernel, and custom-QEMU findings require external engineering decisions.",
    ]
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn bundle_dirs_older_than(root: &Path, cutoff: SystemTime) -> Result<Vec<PathBuf>> {
    let mut bundles = Vec::new();
    for entry in read_dir_sorted(root)? {
        let path = entry.path();
        if !path.is_dir() || !path.join(MANIFEST_PATH).is_file() {
            continue;
        }
        let modified = path
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|source| ValidationError::Read {
                path: path.clone(),
                source,
            })?;
        if modified <= cutoff {
            bundles.push(path);
        }
    }
    Ok(bundles)
}

fn free_gb(path: &Path) -> Result<f64> {
    let output = ProcessCommand::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .map_err(|source| ValidationError::Read {
            path: PathBuf::from("df"),
            source,
        })?;
    if !output.status.success() {
        return Err(ValidationError::CommandFailed {
            program: "df".to_string(),
            args: vec!["-Pk".to_string(), path.display().to_string()],
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(line) = text.lines().nth(1) else {
        return contract_error("df output did not contain a filesystem line");
    };
    let available_kb = line
        .split_whitespace()
        .nth(3)
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| {
            ValidationError::Contract("failed to parse df available space".to_string())
        })?;
    Ok(available_kb / 1024.0 / 1024.0)
}

fn mongo_health() -> MongoHealth {
    let version = command_stdout("mongod", &["--version"])
        .ok()
        .and_then(|stdout| parse_mongod_version(&stdout));
    let bind_addresses = command_stdout("ss", &["-ltnp"])
        .ok()
        .map(|stdout| parse_mongodb_binds(&stdout))
        .unwrap_or_default();
    let exposure_pass = if bind_addresses.is_empty() {
        None
    } else {
        Some(mongodb_local_only(&bind_addresses))
    };
    let packages_held = command_stdout("apt-mark", &["showhold"])
        .ok()
        .map(|stdout| mongodb_packages_held(&stdout));
    MongoHealth {
        version,
        bind_addresses,
        packages_held,
        exposure_pass,
    }
}

fn command_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(program)
        .args(args)
        .output()
        .map_err(|source| ValidationError::Read {
            path: PathBuf::from(program),
            source,
        })?;
    if !output.status.success() {
        return Err(ValidationError::CommandFailed {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_mongod_version(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("db version v")
            .or_else(|| trimmed.strip_prefix("db version "))
            .map(|value| value.trim().to_string())
    })
}

fn parse_mongodb_binds(stdout: &str) -> Vec<String> {
    let mut binds = Vec::new();
    for line in stdout.lines() {
        if !line.contains(":27017") {
            continue;
        }
        if let Some(address) = line.split_whitespace().nth(3) {
            binds.push(address.to_string());
        }
    }
    binds.sort();
    binds.dedup();
    binds
}

fn mongodb_local_only(bind_addresses: &[String]) -> bool {
    bind_addresses
        .iter()
        .all(|address| address == "127.0.0.1:27017" || address == "[::1]:27017")
}

fn mongodb_packages_held(showhold_stdout: &str) -> bool {
    const REQUIRED: &[&str] = &[
        "mongodb-org",
        "mongodb-org-database",
        "mongodb-org-server",
        "mongodb-org-mongos",
        "mongodb-org-shell",
        "mongodb-org-database-tools-extra",
        "mongodb-org-tools",
    ];
    let held: HashSet<&str> = showhold_stdout.lines().map(str::trim).collect();
    REQUIRED.iter().all(|package| held.contains(package))
}

fn bool_word(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn handoff_health(root: &Path) -> Result<HandoffHealth> {
    let mut health = HandoffHealth {
        total_bundles: 0,
        completed: 0,
        capture_error: 0,
        analysis_error: 0,
        timeout: 0,
        degraded: 0,
    };
    for entry in read_dir_sorted(root)? {
        let path = entry.path();
        if !path.is_dir() || !path.join(MANIFEST_PATH).is_file() {
            continue;
        }
        let manifest: Manifest = read_json(&path.join(MANIFEST_PATH))?;
        health.total_bundles += 1;
        match manifest.status {
            SessionStatus::Completed => health.completed += 1,
            SessionStatus::CaptureError => health.capture_error += 1,
            SessionStatus::AnalysisError => health.analysis_error += 1,
            SessionStatus::Timeout => health.timeout += 1,
        }
        if manifest.telemetry.telemetry_degraded {
            health.degraded += 1;
        }
    }
    Ok(health)
}

fn golden_report_age_days(path: &Path) -> Result<u64> {
    let modified = path
        .metadata()
        .and_then(|metadata| metadata.modified())
        .map_err(|source| ValidationError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(SystemTime::now()
        .duration_since(modified)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or_default())
}

fn current_golden_decision(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("| MVP gate decision |") {
            return None;
        }
        let mut cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() < 2 {
            return None;
        }
        Some(cells.swap_remove(1).to_string())
    })
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
    fn parses_scanner_outputs() {
        assert_eq!(
            parse_yara_hits("SuspiciousRule /tmp/sample.exe\nOtherRule /tmp/sample.exe\n"),
            vec!["OtherRule".to_string(), "SuspiciousRule".to_string()]
        );
        assert_eq!(
            parse_clamav_signature("/tmp/sample.exe: Win.Test.EICAR_HDB-1 FOUND"),
            Some("Win.Test.EICAR_HDB-1".to_string())
        );
        assert_eq!(
            summarize_vt_response(
                r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":60}}}}"#
            ),
            "found:malicious=2,suspicious=1,harmless=60"
        );
    }

    #[test]
    fn scanner_findings_increase_static_score() {
        let yara = YaraSummary {
            fast_hits: vec!["FastRule".to_string()],
            deep_hits: vec!["DeepRule".to_string()],
        };
        let clamav = ClamAvSummary {
            status: "infected".to_string(),
            signature: Some("Test.Signature".to_string()),
        };
        let (hypotheses, score) =
            score_scanner_findings(Vec::new(), 0.0, &yara, &clamav, "found:malicious=3");

        assert!(score >= 120.0);
        assert!(hypotheses.contains(&"yara_fast_hit".to_string()));
        assert!(hypotheses.contains(&"yara_deep_hit".to_string()));
        assert!(hypotheses.contains(&"clamav_detected".to_string()));
        assert!(hypotheses.contains(&"virustotal_hash_reputation".to_string()));
    }

    #[test]
    fn report_bundle_writes_json_and_html_from_shared_model() {
        let output_root =
            env::temp_dir().join(format!("winstdt-report-test-{}", now_unix_seconds()));
        fs::create_dir_all(&output_root).expect("create temp output");
        let json_path = output_root.join("report.json");
        let html_path = output_root.join("report.html");

        report_bundle(
            Path::new("tests/fixtures/handoff/valid_complete"),
            &json_path,
            &html_path,
        )
        .expect("report generation should pass");

        let report: Value = read_json(&json_path).expect("read generated report");
        assert_eq!(report["schema_version"], SCHEMA_VERSION);
        assert_eq!(report["session_id"], "1001");
        assert_eq!(report["validation"]["status"], "completed");
        let html = read_to_string(&html_path).expect("read html report");
        assert!(html.contains("WinST/DT Analyst Report"));
        assert!(!html.contains("href=\"network/capture.pcapng\""));

        fs::remove_dir_all(output_root).expect("remove temp output");
    }

    #[test]
    fn mock_consume_watch_mode_requires_streaming_gate() {
        let error = mock_consume(
            Path::new("tests/fixtures/handoff"),
            false,
            Duration::from_millis(1),
        )
        .expect_err("watch mode should require streaming gate");
        assert!(error.to_string().contains("WINSTDT_STREAMING_HANDOFF=1"));
    }

    #[test]
    fn handoff_health_counts_fixture_statuses() {
        let health = handoff_health(Path::new("tests/fixtures/handoff"))
            .expect("fixture handoff root should scan");
        assert_eq!(health.total_bundles, 3);
        assert_eq!(health.completed, 3);
        assert_eq!(health.degraded, 1);
    }

    #[test]
    fn parses_mongodb_health_guardrails() {
        let version = parse_mongod_version("db version v8.0.4\nBuild Info: {}\n")
            .expect("version should parse");
        assert_eq!(version, "8.0.4");

        let ss_output = "LISTEN 0 4096 127.0.0.1:27017 0.0.0.0:* users:((\"mongod\",pid=1,fd=1))\n";
        let binds = parse_mongodb_binds(ss_output);
        assert_eq!(binds, vec!["127.0.0.1:27017".to_string()]);
        assert!(mongodb_local_only(&binds));

        let exposed = vec!["0.0.0.0:27017".to_string()];
        assert!(!mongodb_local_only(&exposed));
    }

    #[test]
    fn checks_mongodb_package_holds() {
        let holds = "\
mongodb-org
mongodb-org-database
mongodb-org-server
mongodb-org-mongos
mongodb-org-shell
mongodb-org-database-tools-extra
mongodb-org-tools
";
        assert!(mongodb_packages_held(holds));
        assert!(!mongodb_packages_held("mongodb-org\nmongodb-org-server\n"));
    }

    #[test]
    fn parses_current_golden_decision() {
        let content = "| MVP gate decision | Accepted |\n";
        assert_eq!(
            current_golden_decision(content),
            Some("Accepted".to_string())
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
