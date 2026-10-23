use clap::{Parser, Subcommand};
use soroban_audit::{AuditConfig, AuditEngine, TtlBoundaryTester, WasmHook};
use soroban_fuzz_core::AuditCertificate;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "soroban-audit",
    author = "OrderStream <healthdecoded77@gmail.com>",
    version = "0.1.0",
    about = "Stellar Soroban WASM Security Audit and Tamper-Evident Invariant Verifier CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Executes a continuous invariant fuzzing campaign, tests TTL eviction boundaries, and generates SHA-256 tamper-evident certificates.
    Audit {
        #[arg(short, long, default_value = "SorobanDeFiProtocol")]
        protocol: String,

        #[arg(short, long, default_value = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC")]
        contract_id: String,

        #[arg(short, long, default_value = "futurenet")]
        network: String,

        #[arg(short, long)]
        wasm: Option<PathBuf>,

        #[arg(long, default_value_t = 150)]
        steps: usize,

        #[arg(long, default_value_t = 75)]
        ledgers: u32,

        #[arg(long, default_value = "audit_certificate.json")]
        out_json: PathBuf,

        #[arg(long, default_value = "AUDIT_REPORT.md")]
        out_md: PathBuf,
    },

    /// Verifies the cryptographic SHA-256 integrity and authenticity of an audit certificate JSON file.
    Verify {
        #[arg(short, long)]
        certificate: PathBuf,
    },

    /// Inspects WASM bytecode, exports, and custom Soroban specification sections.
    InspectWasm {
        #[arg(short, long)]
        wasm: PathBuf,
    },

    /// Simulates storage TTL boundary conditions and records eviction counts.
    TtlSimulate {
        #[arg(short, long, default_value_t = 100)]
        ledgers: u32,

        #[arg(short, long, default_value_t = 20)]
        keys: usize,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            protocol,
            contract_id,
            network,
            wasm,
            steps,
            ledgers,
            out_json,
            out_md,
        } => {
            println!("🚀 Starting Soroban Invariant Security Campaign for '{}'...", protocol);
            let config = AuditConfig {
                protocol_name: protocol,
                contract_id,
                target_network: network,
                total_campaign_steps: steps,
                ledgers_to_simulate: ledgers,
                min_ttl: 16,
                max_ttl: 3110400,
                wasm_path: wasm.map(|p| p.to_string_lossy().to_string()),
            };

            let summary = AuditEngine::execute(config)
                .map_err(|e| format!("Audit engine failed: {}", e))?;

            if let Some(info) = &summary.wasm_info {
                println!("📦 WASM Sha256: {}", info.sha256_hash);
                println!("📦 Exports: {:?}", info.exported_functions);
            }

            println!("✅ Campaign executed successfully!");
            println!("🔒 Certificate ID: {}", summary.certificate.certificate_id);
            println!("🔒 SHA-256 Fingerprint: {}", summary.certificate.cryptographic_fingerprint);
            println!("🛡️  Integrity Valid: {}", summary.certificate.verify_integrity());

            fs::write(&out_json, &summary.json_report)?;
            println!("📄 Exported JSON Certificate to: {}", out_json.display());

            fs::write(&out_md, &summary.markdown_report)?;
            println!("📄 Exported Markdown Report to: {}", out_md.display());
        }

        Commands::Verify { certificate } => {
            let content = fs::read_to_string(&certificate)?;
            let cert: AuditCertificate = AuditCertificate::from_json(&content)?;
            let valid = cert.verify_integrity();

            if valid {
                println!("✅ Certificate verified! Cryptographic fingerprint is untampered.");
                println!("   Certificate ID: {}", cert.certificate_id);
                println!("   Protocol: {}", cert.protocol_name);
                println!("   Status: {:?}", cert.status);
                println!("   Fingerprint: {}", cert.cryptographic_fingerprint);
            } else {
                eprintln!("❌ VERIFICATION FAILED: Fingerprint mismatch or certificate tampered!");
                std::process::exit(1);
            }
        }

        Commands::InspectWasm { wasm } => {
            let bytes = fs::read(&wasm)?;
            let info = WasmHook::inspect(&bytes)
                .map_err(|e| format!("Inspection failed: {}", e))?;
            println!("{:#?}", info);
        }

        Commands::TtlSimulate { ledgers, keys } => {
            let mut tester = TtlBoundaryTester::new(16, 3110400);
            let report = tester.run_boundary_campaign(ledgers, keys);
            println!("{:#?}", report);
        }
    }

    Ok(())
}
