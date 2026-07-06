# DnsForge

DNS zone file parser, validator, analyzer, and converter.

A comprehensive CLI tool and Python library for working with DNS zone files. Parse zone files into structured data, validate against RFC standards, analyze zone health, and convert between formats.

## Features

- **Parse** — Hand-written recursive descent parser for DNS zone files (not regex)
- **Validate** — 20+ RFC compliance and best practice checks
- **Analyze** — Health scoring (0-100), statistics, and recommendations
- **Convert** — Output as text, JSON, or Markdown
- **Format** — Re-format zone files with consistent styling

## Quick Start

```bash
# Install
pip install dnsforge

# Or from source
git clone https://github.com/EdgarOrtegaRamirez/dnsforge.git
cd dnsforge
pip install -e ".[dev]"
```

## Usage

### Validate a zone file
```bash
dnsforge validate zone.db
dnsforge validate zone.db --format json
```

### Analyze zone health
```bash
dnsforge analyze zone.db
dnsforge analyze zone.db --format markdown
```

### View zone info
```bash
dnsforge info zone.db
dnsforge info zone.db --format json
```

### Show statistics
```bash
dnsforge stats zone.db
```

### Parse to JSON AST
```bash
dnsforge parse zone.db
```

### Convert format
```bash
dnsforge convert zone.db --format json --output report.json
dnsforge convert zone.db --format markdown
```

### Re-format zone file
```bash
dnsforge format zone.db
```

### List supported record types
```bash
dnsforge types
```

### Print sample zone file
```bash
dnsforge sample
```

## Supported Record Types

| Type | Description |
|------|-------------|
| A | IPv4 address |
| AAAA | IPv6 address |
| CNAME | Canonical name (alias) |
| MX | Mail exchange |
| NS | Name server |
| TXT | Text record |
| SOA | Start of authority |
| SRV | Service locator |
| PTR | Pointer (reverse DNS) |
| CAA | Certification Authority Authorization |
| TLSA | DANE TLS association |
| SSHFP | SSH fingerprint |
| DS | Delegation Signer |
| DNSKEY | DNSSEC key |
| HTTPS | HTTPS binding |
| SVCB | Service binding |

## Validation Rules

### Errors (score impact: -10)
- `MISSING_SOA` — Zone has no SOA record
- `MISSING_NS` — Zone has no NS records
- `MULTIPLE_SOA` — More than one SOA record
- `SOA_SERIAL_RANGE` — Serial number out of range
- `CNAME_SELF_LOOP` — CNAME points to itself
- `CNAME_COEXIST` — CNAME coexists with other record types
- `A_INVALID_ADDRESS` — Invalid IPv4 address
- `AAAA_INVALID_ADDRESS` — Invalid IPv6 address
- `NS_CNAME` — NS record points to CNAME
- `MX_EMPTY_EXCHANGE` — MX with empty exchange

### Warnings (score impact: -5)
- `NS_REDUNDANCY` — Only 1 NS record
- `SOA_RETRY_GTE_REFRESH` — Retry >= Refresh
- `SOA_EXPIRE_LTE_REFRESH` — Expire <= Refresh
- `A_LOOPBACK` — A record points to loopback
- `MX_CNAME` — MX exchange points to CNAME
- `WILDCARD_CNAME` — Wildcard CNAME record
- `CAA_UNKNOWN_TAG` — Unknown CAA tag

### Info (score impact: -1)
- `A_PRIVATE_ADDRESS` — A record points to private IP
- `TXT_LONG_STRING` — TXT data > 255 chars
- `TTL_VERY_HIGH` — Very high TTL value

## Architecture

```
dnsforge/
├── __init__.py      # Package metadata
├── models.py        # DNS data models (records, zone, issues)
├── parser.py        # Hand-written zone file parser
├── validator.py     # RFC compliance validation
├── analyzer.py      # Health scoring and recommendations
├── reporter.py      # Output formatters (text, JSON, Markdown)
└── cli.py           # Click CLI interface
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=dnsforge --cov-report=term-missing

# Lint
ruff check dnsforge/ tests/
ruff format --check dnsforge/ tests/
```

## License

MIT
