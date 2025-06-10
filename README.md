# simdscan

[![Crates.io](https://img.shields.io/crates/v/simdscan.svg)](https://crates.io/crates/simdscan)
[![License: Apache-2.0](https://img.shields.io/badge/Apache--2.0-blue.svg)](https://github.com/vimkim/simdscan#license)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A blazingly fast Rust CLI tool that analyzes x86-64 binaries to detect and classify SIMD instructions by their ISA extension. Perfect for performance analysis, compiler optimization verification, and understanding what SIMD features your binaries actually use.

## 🚀 Quick Start

```bash
# Install from crates.io
cargo install simdscan

# Analyze a binary
simdscan ./my_program

# Get detailed breakdown in YAML
simdscan -f yaml --show-insts ./my_program
```

## ✨ Features

- **Fast Analysis** - Written in Rust for maximum performance
- **Comprehensive Detection** - Supports SSE, SSE2, SSE3, SSSE3, SSE4, AVX, AVX2, and AVX-512
- **Multiple Formats** - Output in JSON or YAML
- **Detailed Breakdowns** - See which specific instructions are used most
- **Cross-Platform** - Works on Linux, macOS, and Windows
- **Easy Installation** - Single command install via cargo

## 📋 Requirements

- `objdump` (from GNU binutils) must be available in your PATH
- Rust 1.70+ (for building from source)

## 🛠️ Installation

### From crates.io (Recommended)

```bash
cargo install simdscan
```

### From Source

```bash
git clone https://github.com/yourusername/simdscan
cd simdscan
cargo install --path .
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/vimkim/simdscan/releases).

## 📖 Usage

### Basic Usage

```bash
# Analyze any x86-64 binary (ELF, Mach-O, PE)
simdscan path/to/binary
```

### Advanced Options

```bash
# YAML output with instruction details
simdscan -f yaml --show-insts my_program

# JSON output (default)
simdscan -f json my_program

# Help
simdscan --help
```

### Command Line Options

| Option                  | Description                                    |
| ----------------------- | ---------------------------------------------- |
| `binary`                | Path to the binary file to analyze             |
| `-f, --format <FORMAT>` | Output format: `json` (default) or `yaml`      |
| `--show-insts`          | Include detailed per-ISA instruction breakdown |

## 🎯 Supported ISA Extensions

- **SSE** - Streaming SIMD Extensions (Pentium III)
- **SSE2** - Streaming SIMD Extensions 2 (Pentium 4)
- **SSE3** - Streaming SIMD Extensions 3 (Pentium 4)
- **SSSE3** - Supplemental Streaming SIMD Extensions 3 (Core 2)
- **SSE4** - SSE4.1, SSE4.2, plus POPCNT, LZCNT, CRC32 (Core i7)
- **AVX** - Advanced Vector Extensions, including AVX2 (Sandy Bridge+)
- **AVX-512** - 512-bit Advanced Vector Extensions (Skylake-X+)

## 📊 Example Output

### Basic Analysis

```json
{
  "binary": "./my_program",
  "has_simd": true,
  "isa_summary": {
    "AVX": 156,
    "SSE2": 43,
    "SSE4": 12
  },
  "total_simd_insts": 211
}
```

### Detailed Analysis (with `--show-insts`)

```json
{
  "binary": "./my_program",
  "has_simd": true,
  "isa_summary": {
    "AVX": 156,
    "SSE2": 43,
    "SSE4": 12
  },
  "total_simd_insts": 211,
  "isa_details": {
    "AVX": {
      "unique_mnemonics": 8,
      "occurrences": {
        "vmovaps": 45,
        "vaddps": 32,
        "vmulps": 28,
        "vsubps": 21,
        "vxorps": 15,
        "vdivps": 10,
        "vmovups": 3,
        "vzeroupper": 2
      }
    },
    "SSE2": {
      "unique_mnemonics": 5,
      "occurrences": {
        "movdqa": 18,
        "movdqu": 12,
        "paddq": 8,
        "pshufd": 3,
        "pxor": 2
      }
    }
  }
}
```

## 🔬 How It Works

1. **Disassembly** - Uses `objdump -d` to disassemble the target binary
2. **Parsing** - Efficiently parses assembly output using compiled regex patterns
3. **Classification** - Matches instruction mnemonics against comprehensive ISA tables
4. **Reporting** - Aggregates statistics and generates structured output

## 🎯 Use Cases

- **Performance Analysis** - Verify your compiler is generating the SIMD code you expect
- **Binary Auditing** - Understand what instruction sets a binary requires
- **Optimization Verification** - Confirm auto-vectorization is working
- **Compatibility Checking** - Ensure binaries will run on target hardware
- **Research** - Analyze SIMD usage patterns across different codebases

## 🚀 Performance

Simdscan is designed for speed:

- **Rust Performance** - Zero-overhead abstractions and memory safety
- **Efficient Parsing** - Pre-compiled regex patterns and optimized string processing
- **Minimal Dependencies** - Fast startup and low memory usage
- **Streaming Processing** - Handles large binaries efficiently

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Issues** - Found a bug or have a feature request? [Open an issue](https://github.com/yourusername/simdscan/issues)
2. **Submit PRs** - Fix bugs, add features, or improve documentation
3. **Add ISA Support** - Help expand coverage of instruction sets
4. **Performance** - Optimize parsing or add new output formats

### Development Setup

```bash
git clone https://github.com/vimkim/simdscan
cd simdscan
cargo build
```

## 📈 Roadmap

- [ ] ARM NEON instruction support
- [ ] Intel CET (Control-flow Enforcement Technology) detection
- [ ] Function-level SIMD analysis
- [ ] Integration with popular build systems
- [ ] Web assembly support
- [ ] Instruction frequency heatmaps

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)

## 🙏 Acknowledgments

- Inspired by the original Python version
- Built with the amazing Rust ecosystem
- Thanks to the objdump maintainers for the reliable disassembly foundation

---

**Made with ❤️ and ⚡ by the Rust community**
