"""Tests for DNS zone file CLI."""

import os
import tempfile

import pytest
from click.testing import CliRunner

from dnsforge.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_zone_file():
    content = """$ORIGIN example.com.
$TTL 3600

@   IN  SOA  ns1.example.com. admin.example.com. (
    2024070601 3600 900 604800 86400
)

@       IN  NS      ns1.example.com.
@       IN  NS      ns2.example.com.
ns1     IN  A       192.0.2.1
ns2     IN  A       192.0.2.2
@       IN  A       192.0.2.10
www     IN  CNAME   @
mail    IN  A       192.0.2.20
@       IN  MX      10 mail.example.com.
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".zone", delete=False) as f:
        f.write(content)
        f.flush()
        yield f.name
    os.unlink(f.name)


class TestCLI:
    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0

    def test_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "DNS zone file" in result.output

    def test_sample(self, runner):
        result = runner.invoke(main, ["sample"])
        assert result.exit_code == 0
        assert "$ORIGIN" in result.output
        assert "SOA" in result.output

    def test_types(self, runner):
        result = runner.invoke(main, ["types"])
        assert result.exit_code == 0
        assert "A" in result.output
        assert "AAAA" in result.output
        assert "MX" in result.output
        assert "SOA" in result.output


class TestParseCommand:
    def test_parse_valid_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["parse", sample_zone_file])
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_parse_invalid_file(self, runner):
        result = runner.invoke(main, ["parse", "/nonexistent/file.zone"])
        assert result.exit_code != 0


class TestValidateCommand:
    def test_validate_valid_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["validate", sample_zone_file])
        assert result.exit_code == 0

    def test_validate_json_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["validate", sample_zone_file, "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "issues" in data

    def test_validate_markdown_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["validate", sample_zone_file, "--format", "markdown"])
        assert result.exit_code == 0
        assert "# DNS Zone Analysis" in result.output


class TestAnalyzeCommand:
    def test_analyze_valid_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["analyze", sample_zone_file])
        assert result.exit_code == 0
        assert "Health:" in result.output or "health" in result.output.lower()

    def test_analyze_json_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["analyze", sample_zone_file, "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "score" in data

    def test_analyze_markdown_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["analyze", sample_zone_file, "--format", "markdown"])
        assert result.exit_code == 0
        assert "# DNS Zone Analysis" in result.output


class TestInfoCommand:
    def test_info_valid_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["info", sample_zone_file])
        assert result.exit_code == 0
        assert "Zone:" in result.output

    def test_info_json_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["info", sample_zone_file, "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "records" in data


class TestStatsCommand:
    def test_stats_valid_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["stats", sample_zone_file])
        assert result.exit_code == 0
        assert "Total records:" in result.output

    def test_stats_json_format(self, runner, sample_zone_file):
        result = runner.invoke(main, ["stats", sample_zone_file, "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "total_records" in data


class TestConvertCommand:
    def test_convert_json(self, runner, sample_zone_file):
        result = runner.invoke(main, ["convert", sample_zone_file, "--format", "json"])
        assert result.exit_code == 0
        import json

        data = json.loads(result.output)
        assert "score" in data

    def test_convert_markdown(self, runner, sample_zone_file):
        result = runner.invoke(main, ["convert", sample_zone_file, "--format", "markdown"])
        assert result.exit_code == 0
        assert "# DNS Zone Analysis" in result.output

    def test_convert_to_file(self, runner, sample_zone_file):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = f.name
        try:
            result = runner.invoke(main, ["convert", sample_zone_file, "--output", output_path, "--format", "json"])
            assert result.exit_code == 0
            assert os.path.exists(output_path)
            with open(output_path) as f:
                import json

                data = json.load(f)
                assert "score" in data
        finally:
            os.unlink(output_path)


class TestFormatCommand:
    def test_format_zone(self, runner, sample_zone_file):
        result = runner.invoke(main, ["format", sample_zone_file])
        assert result.exit_code == 0
        assert "$ORIGIN" in result.output or "SOA" in result.output
