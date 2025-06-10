use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use indexmap::IndexMap;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "simdscan",
    about = "Classify SIMD instructions by ISA extension",
    long_about = "Analyze x86-64 binaries to detect and classify SIMD instructions by their ISA extension (SSE, AVX, etc.)"
)]
struct Args {
    /// Path to the binary file (ELF, Mach-O, or PE)
    binary: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    format: OutputFormat,

    /// Include per-ISA instruction breakdown
    #[arg(long)]
    show_insts: bool,
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Json,
    Yaml,
}

#[derive(Serialize)]
struct Report {
    binary: String,
    has_simd: bool,
    isa_summary: IndexMap<String, usize>,
    total_simd_insts: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    isa_details: Option<IndexMap<String, IsaDetail>>,
}

#[derive(Serialize)]
struct IsaDetail {
    unique_mnemonics: usize,
    occurrences: IndexMap<String, usize>,
}

lazy_static! {
    static ref ISA_TABLE: HashMap<&'static str, HashSet<&'static str>> = {
        let mut table = HashMap::new();

        // SSE
        table.insert("SSE", HashSet::from([
            "addps", "addss", "andnps", "andps", "cmpps", "cmpss", "comiss",
            "cvtpi2ps", "cvtps2pi", "cvtsi2ss", "cvtss2si", "cvttps2pi", "cvttss2si",
            "divps", "divss", "ldmxcsr", "maxps", "maxss", "minps", "minss",
            "movaps", "movhlps", "movhps", "movlhps", "movlps", "movmskps",
            "movntps", "movss", "movups", "mulps", "mulss", "orps", "rcpps",
            "rcpss", "rsqrtps", "rsqrtss", "shufps", "sqrtps", "sqrtss",
            "stmxcsr", "subps", "subss", "ucomiss", "unpckhps", "unpcklps",
            "xorps", "pavgb", "pavgw", "pextrw", "pinsrw", "pmaxsw", "pmaxub",
            "pminsw", "pminub", "pmovmskb", "psadbw", "pshufw"
        ]));

        // SSE2
        table.insert("SSE2", HashSet::from([
            "addpd", "addsd", "andnpd", "andpd", "cmppd", "comisd", "cvtdq2pd",
            "cvtdq2ps", "cvtpd2dq", "cvtpd2pi", "cvtpd2ps", "cvtpi2pd",
            "cvtps2dq", "cvtps2pd", "cvtsd2si", "cvtsd2ss", "cvtsi2sd",
            "cvtss2sd", "cvttpd2dq", "cvttpd2pi", "cvttps2dq", "cvttsd2si",
            "divpd", "divsd", "maxpd", "maxsd", "minpd", "minsd", "movapd",
            "movhpd", "movlpd", "movmskpd", "movupd", "mulpd", "mulsd", "orpd",
            "shufpd", "sqrtpd", "sqrtsd", "subpd", "subsd", "ucomisd",
            "unpckhpd", "unpcklpd", "xorpd", "movdq2q", "movdqa", "movdqu",
            "movq2dq", "paddq", "pmuludq", "pshufhw", "pshuflw", "pshufd",
            "pslldq", "psrldq", "punpckhqdq", "punpcklqdq"
        ]));

        // SSE3
        table.insert("SSE3", HashSet::from([
            "addsubpd", "addsubps", "haddpd", "haddps", "hsubpd", "hsubps",
            "movddup", "movshdup", "movsldup", "lddqu", "fisttp"
        ]));

        // SSSE3
        table.insert("SSSE3", HashSet::from([
            "psignw", "psignd", "psignb", "pshufb", "pmulhrsw", "pmaddubsw",
            "phsubw", "phsubsw", "phsubd", "phaddw", "phaddsw", "phaddd",
            "palignr", "pabsw", "pabsd", "pabsb"
        ]));

        // SSE4
        table.insert("SSE4", HashSet::from([
            "mpsadbw", "phminposuw", "pmulld", "pmuldq", "dpps", "dppd",
            "blendps", "blendpd", "blendvps", "blendvpd", "pblendvb", "pblendw",
            "pblenddw", "pminsb", "pmaxsb", "pminuw", "pmaxuw", "pminud",
            "pmaxud", "pminsd", "pmaxsd", "roundps", "roundss", "roundpd",
            "roundsd", "insertps", "pinsrb", "pinsrd", "pinsrq", "extractps",
            "pextrb", "pextrd", "pextrw", "pextrq", "pmovsxbw", "pmovzxbw",
            "pmovsxbd", "pmovzxbd", "pmovsxbq", "pmovzxbq", "pmovsxwd",
            "pmovzxwd", "pmovsxwq", "pmovzxwq", "pmovsxdq", "pmovzxdq",
            "ptest", "pcmpeqq", "pcmpgtq", "packusdw", "pcmpestri", "pcmpestrm",
            "pcmpistri", "pcmpistrm", "crc32", "popcnt", "movntdqa", "extrq",
            "insertq", "movntsd", "movntss", "lzcnt"
        ]));

        // AVX
        table.insert("AVX", HashSet::from([
            "vaddps", "vaddpd", "vaddss", "vaddsd", "vsubps", "vsubpd", "vsubss",
            "vsubsd", "vmulps", "vmulpd", "vmulss", "vmulsd", "vdivps", "vdivpd",
            "vdivss", "vdivsd", "vmaxps", "vmaxpd", "vmaxss", "vmaxsd", "vminps",
            "vminpd", "vminss", "vminsd", "vxorps", "vxorpd", "vandps", "vandpd",
            "vmovaps", "vmovups", "vmovapd", "vmovupd", "vmovdqa", "vmovdqu",
            "vmovntps", "vmovntpd", "vbroadcastss", "vbroadcastsd", "vinsertf128",
            "vextractf128", "vblendps", "vblendpd", "vblendvps", "vblendvpd",
            "vpermilps", "vpermilpd", "vperm2f128", "vshufps", "vshufpd",
            "vzeroupper", "vpaddd", "vpsubd", "vpmulld", "vpmuludq", "vpackssdw",
            "vpackusdw", "vpcmpeqd", "vpcmpgtd", "vpminud", "vpmaxud", "vpminsd",
            "vpmaxsd", "vgatherdps", "vgatherdpd", "vpgatherdd", "vpgatherdq",
            "vpmaskmovd", "vpmaskmovq", "vmaskmovps", "vmaskmovpd", "vfmadd213pd",
            "vfmadd231pd", "vfmadd132pd", "vfmsub213pd", "vfmsub231pd", "vfmsub132pd",
            "vfnmadd213pd", "vfnmadd231pd", "vfnmadd132pd"
        ]));

        // AVX-512
        table.insert("AVX-512", HashSet::from([
            "kaddd", "kandd", "korw", "kxorq", "vcompresspd", "vexpandps",
            "vpermb", "vpmovm2d", "vpconflictd", "vpternlogd", "vpshldv",
            "vpopcntd", "vscalefpd", "vrndscaleps"
        ]));

        table
    };

    static ref OBJLINE_RE: Regex = Regex::new(r"^\s*[0-9a-f]+:\s+\w").unwrap();
    static ref MNE_RE: Regex = Regex::new(r"\s([a-z][a-z0-9]+\b)").unwrap();
}

fn disassemble(path: &PathBuf) -> Result<Vec<String>> {
    let output = Command::new("objdump")
        .args(["-d", "--no-show-raw-insn"])
        .arg(path)
        .output()
        .context("Failed to execute objdump")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("objdump failed: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout).context("objdump output is not valid UTF-8")?;

    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

fn classify(
    lines: &[String],
) -> (
    IndexMap<String, usize>,
    HashMap<String, HashMap<String, usize>>,
) {
    let mut isa_counts = IndexMap::new();
    let mut inst_detail: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for line in lines {
        if !OBJLINE_RE.is_match(line) {
            continue;
        }

        if let Some(captures) = MNE_RE.captures(line) {
            let mnemonic = captures.get(1).unwrap().as_str().to_lowercase();

            // Check each ISA table
            for (isa, mset) in ISA_TABLE.iter() {
                if mset.contains(mnemonic.as_str()) {
                    *isa_counts.entry(isa.to_string()).or_insert(0) += 1;

                    let isa_detail = inst_detail
                        .entry(isa.to_string())
                        .or_insert_with(HashMap::new);
                    *isa_detail.entry(mnemonic).or_insert(0) += 1;

                    // Stop at first match
                    break;
                }
            }
        }
    }

    // Sort isa_counts by key
    isa_counts.sort_keys();

    (isa_counts, inst_detail)
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.binary.exists() {
        anyhow::bail!("Binary file '{}' not found", args.binary.display());
    }

    let lines = disassemble(&args.binary).context("Failed to disassemble binary")?;

    let (isa_counts, inst_detail) = classify(&lines);

    let total_simd_insts = isa_counts.values().sum();
    let has_simd = total_simd_insts > 0;

    let isa_details = if args.show_insts {
        let mut details = IndexMap::new();
        for (isa, detail_map) in inst_detail {
            let mut occurrences = IndexMap::new();

            // Sort by count (descending) and take top 10
            let mut sorted_pairs: Vec<_> = detail_map.into_iter().collect();
            sorted_pairs.sort_by(|a, b| b.1.cmp(&a.1));

            for (mnemonic, count) in sorted_pairs.into_iter().take(10) {
                occurrences.insert(mnemonic, count);
            }

            details.insert(
                isa,
                IsaDetail {
                    unique_mnemonics: occurrences.len(),
                    occurrences,
                },
            );
        }
        Some(details)
    } else {
        None
    };

    let report = Report {
        binary: args.binary.to_string_lossy().to_string(),
        has_simd,
        isa_summary: isa_counts,
        total_simd_insts,
        isa_details,
    };

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&report)?);
        }
    }

    Ok(())
}
