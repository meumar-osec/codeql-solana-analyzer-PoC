# Sealevel Attack Analyzer

**It's just a PoC, so we used CodeQL queries to detect anchor sealevel vulnerabilities.**

### Instal codeql CLI
- [CodeQL CLI](https://github.com/github/codeql-cli-binaries) installed
- Rust toolchain
- `jq` for JSON processing

### Usage

```bash
# Install dependencies
./scripts/install-dependencies.sh
```

```bash
# Example: Analyze sealevel-attacks repository
./scripts/scan-project.sh /path/to/sealevel-attacks/programs/0-signer-authorization/insecure
```
# codeql-solana-analyzer-PoC
