# Checksum Wizard

**Checksum Wizard** is an industrial-grade file checksum utility for generating, validating, and comparing file checksums using a wide range of cryptographic hash algorithms.

It offers robust error handling, support for multiple hashing algorithms, and a command-line interface designed for security-conscious environments.

## 🔍 Features

- Supports industry-standard and modern hash algorithms (SHA2, SHA3, BLAKE2, etc.)
- Warns about usage of weak or deprecated algorithms (e.g., MD5, SHA1)
- Validates file integrity using expected checksum values
- Compares two files for identical hash output
- Outputs in human-readable and JSON formats
- CLI with support for scripting and automation
- Handles interruptions gracefully

---

## 🛠 Installation

1. Clone the repository

2. make the script executable
```
chmod +x checksum.py
```

Requires **Python 3.10+**.

## 🚀 Usage

```bash
python checksum.py <mode> <file> [options]
```

### Modes

* `generate`: Generate checksums for a file
* `validate`: Validate a file against a known checksum
* `compare`: Compare two files using the same algorithm

### Options

| Option         | Description                                               |
| -------------- | --------------------------------------------------------- |
| `--algorithm`  | Hash algorithm for validation/compare (default: `sha256`) |
| `--algorithms` | Hash algorithms for generation (default: `sha256 sha512`) |
| `--checksum`   | Expected checksum value (required for `validate` mode)    |
| `--other-file` | Second file path (required for `compare` mode)            |
| `--output`     | Save result as JSON to file                               |
| `--no-warn`    | Suppress security warnings about weak algorithms          |

### Examples

#### Generate SHA256 and SHA512 checksums

```bash
python checksum.py generate myfile.txt --algorithms sha256 sha512
```

#### Validate a file with SHA256

```bash
python checksum.py validate myfile.txt --algorithm sha256 --checksum <expected_hash>
```

#### Compare two files with SHA3-256

```bash
python checksum.py compare file1.txt --other-file file2.txt --algorithm sha3_256
```

#### Save output to JSON

```bash
python checksum.py generate myfile.txt --output results.json
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational, research, and operational integrity verification purposes only. While it uses standard cryptographic primitives, it **does not replace dedicated digital signature or encryption systems**.

Using weak algorithms like MD5 or SHA1 is strongly discouraged for security-critical applications.

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  

**This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**
