# AGENTS.md — DnsForge

## Project Overview

DnsForge is a Python CLI tool and library for parsing, validating, analyzing, and converting DNS zone files. It features a hand-written recursive descent parser (no regex), 20+ validation rules, health scoring, and multiple output formats.

## Build & Test

```bash
# Install dependencies
cd /root/workspace/dnsforge
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=dnsforge --cov-report=term-missing

# Lint
ruff check dnsforge/ tests/
ruff format --check dnsforge/ tests/

# Format
ruff format dnsforge/ tests/
```

## Architecture

- **`models.py`** — Data models: DNSRecord, ZoneFile, SOARecord, Issue, Severity, ZoneStats, etc.
- **`parser.py`** — Hand-written recursive descent parser with Tokenizer. Parses zone files into ZoneFile AST.
- **`validator.py`** — 20+ validation rules (RFC compliance, best practices). Returns list of Issues.
- **`analyzer.py`** — Health scoring (0-100), statistics, and recommendations.
- **`reporter.py`** — Output formatters: text (with bar chart), JSON, Markdown, and zone file re-serialization.
- **`cli.py`** — Click CLI with 8 commands: validate, analyze, info, stats, parse, convert, format, types, sample.

## Key Design Decisions

1. **Hand-written parser** — No regex, no external parsing libraries. Full control over error messages and recovery.
2. **Newline-separated records** — Tokenizer emits `\n` tokens; parser uses them as record separators (respects parenthesized multiline records).
3. **Severity-weighted scoring** — Errors: -10pts, Warnings: -5pts, Info: -1pt. Bonuses for good practices.
4. **Pure validation functions** — Each rule is a method on ZoneValidator, easy to test in isolation.

## Common Tasks

### Add a new validation rule
1. Add a method `check_<name>()` to `ZoneValidator` in `validator.py`
2. Add it to `validate()` method
3. Add tests in `tests/test_validator.py`

### Add a new record type
1. Add to `RecordType` enum in `models.py`
2. Add rdata parsing in `parser.py` `_parse_rdata()`
3. Add validation in `validator.py` if applicable
4. Add description to `cli.py` `types` command
5. Add tests

## Testing Strategy

- **test_parser.py** — Tokenizer tests, parser tests for each record type, full zone parsing
- **test_validator.py** — Tests for each validation rule (error, warning, info cases)
- **test_analyzer.py** — Stats computation, scoring, recommendations, summary
- **test_reporter.py** — All output formats produce valid output
- **test_cli.py** — Click CliRunner tests for all CLI commands

## CI

GitHub Actions workflow at `.github/workflows/ci.yml` runs lint (ruff) and tests (pytest) on push to main.
