# 🔍 Garry's Mod Backdoor Scanner

A high-performance security tool designed to detect potential backdoors and malicious code in Garry's Mod addons.

## ✨ Features

- **Fast Parallel Scanning**: Efficiently scans multiple files simultaneously
- **Comprehensive Detection**: Advanced pattern matching for various types of exploits
- **Smart File Analysis**: Inspects Lua, VMT, VTF, and TTF files for malicious content
- **Colored Output**: Clear, easy-to-read results with color-coded severity levels
- **JSON Pattern Database**: Extensive collection of malicious code patterns
- **Progress Tracking**: Real-time scanning progress and statistics

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/marcodevqc/Go-Gmod-Backdoor-Scanner.git
cd Go-Gmod-Backdoor-Scanner

# Build the project
go build

# Scan the default ./addons folder
./gmodbackdoorchecker -path ./addons

# Write JSON output
./gmodbackdoorchecker -path ./addons -json findings.json
```

## 📋 Requirements

- Go 1.20 or higher
- Garry's Mod addons to scan

## 🛡️ What It Detects

- Code execution attempts (RunString, CompileString)
- Remote code loading (HTTP requests)
- File system manipulation
- Environment tampering
- Network exploits
- Debug/memory manipulation
- Hook system abuse
- SQL injection attempts
- Obfuscated malicious code
- And many more...

## 🎨 Output Example

```
[INFO] Starting scan of addon: my_addon
[WARN] Suspicious pattern found in lua/autorun/init.lua:
       - RunString detected (High Risk)
[CRITICAL] Malicious code found in materials/logo.vtf:
          - Remote code execution attempt
[INFO] Scan completed: 42 files checked, 2 suspicious patterns found
```

## 🔧 Advanced Usage

```bash
# Scan a specific addon folder
./gmodbackdoorchecker -path /path/to/specific/addon

# Scan multiple addons with JSON output
./gmodbackdoorchecker -path /path/to/addons/* -json report.json

# Get help
./gmodbackdoorchecker -h
```

## 📝 Pattern Database

The scanner uses a comprehensive JSON pattern database located in `patterns/patterns.json`. The patterns include:

- Generic patterns (applicable to all files)
- File-specific patterns (.lua, .vmt, .vtf, .ttf)
- Common exploitation techniques
- Obfuscation detection
- Network and file operations
- And more...

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

## ⚠️ Disclaimer

This tool is designed for server administrators and addon developers to check their content for potential security issues. It's heuristic-based and intended as a first-pass scanner — review results manually. Use responsibly and only scan addons you own or have permission to analyze.

## 📜 License

MIT License - See the LICENSE file for details.

---
Made with ❤️ by marcodevqc
