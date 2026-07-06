"""DNS zone file parser — hand-written recursive descent parser."""

from __future__ import annotations

from .models import (
    DNSRecord,
    RecordType,
    SOARecord,
    ZoneFile,
)


class ParseError(Exception):
    """Raised when a zone file cannot be parsed."""

    def __init__(self, message: str, line: int = 0):
        self.line = line
        super().__init__(f"Line {line}: {message}" if line else message)


class Tokenizer:
    """Tokenize DNS zone file text into meaningful tokens."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.tokens: list[tuple[str, int]] = []

    def tokenize(self) -> list[tuple[str, int]]:
        """Tokenize the input text. Returns list of (token, line_number)."""
        while self.pos < len(self.text):
            ch = self.text[self.pos]

            # Skip spaces and tabs
            if ch in (" ", "\t", "\r"):
                self.pos += 1
                continue

            # Newline — emit as NEWLINE token
            if ch == "\n":
                self.pos += 1
                self.line += 1
                self.tokens.append(("\n", self.line - 1))
                continue

            # Comment
            if ch == ";":
                self._skip_comment()
                continue

            # Parenthesis
            if ch in ("(", ")"):
                self.tokens.append((ch, self.line))
                self.pos += 1
                continue

            # Quoted string
            if ch == '"':
                self._read_quoted_string()
                continue

            # Regular token
            self._read_token()

        return self.tokens

    def _skip_comment(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] != "\n":
            self.pos += 1

    def _read_quoted_string(self) -> None:
        start_line = self.line
        self.pos += 1
        start = self.pos
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == "\\":
                self.pos += 2
                continue
            if ch == '"':
                self.tokens.append((self.text[start : self.pos], start_line))
                self.pos += 1
                return
            if ch == "\n":
                self.line += 1
            self.pos += 1
        raise ParseError("Unterminated quoted string", start_line)

    def _read_token(self) -> None:
        start = self.pos
        start_line = self.line
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch in (" ", "\t", "\r", "\n", "(", ")", ";"):
                break
            self.pos += 1
        token = self.text[start : self.pos]
        if token:
            self.tokens.append((token, start_line))


class Parser:
    """Parse a DNS zone file into a ZoneFile object."""

    def __init__(self, text: str, origin: str = ""):
        self.text = text
        self.default_origin = origin
        self.zone = ZoneFile(origin=origin)

    def parse(self) -> ZoneFile:
        """Parse the zone file and return a ZoneFile object."""
        tokenizer = Tokenizer(self.text)
        self.tokens = tokenizer.tokenize()
        self.pos = 0

        while self.pos < len(self.tokens):
            self._skip_newlines()
            if self.pos >= len(self.tokens):
                break
            self._parse_directive_or_record()

        return self.zone

    def _current_token(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos][0]
        return None

    def _current_line(self) -> int:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos][1]
        return 0

    def _advance(self) -> str:
        token = self.tokens[self.pos][0]
        self.pos += 1
        return token

    def _skip_newlines(self) -> None:
        while self.pos < len(self.tokens) and self.tokens[self.pos][0] == "\n":
            self.pos += 1

    def _parse_directive_or_record(self) -> None:
        token = self._current_token()
        if token is None:
            return

        if token.startswith("$"):
            self._parse_directive()
            self._skip_newlines()
            return

        # Empty parentheses (skip)
        if token == "(":
            self._advance()
            depth = 1
            while depth > 0 and self._current_token() is not None:
                t = self._advance()
                if t == "(":
                    depth += 1
                elif t == ")":
                    depth -= 1
            self._skip_newlines()
            return

        self._parse_resource_record(token)

    def _parse_directive(self) -> None:
        line = self._current_line()
        directive = self._advance()

        if directive == "$ORIGIN":
            origin = self._advance()
            self.zone.origin = origin.rstrip(".")
            self.zone.origin_directive = origin
            self.zone.directives["$ORIGIN"] = origin
        elif directive == "$TTL":
            ttl_str = self._advance()
            try:
                int(ttl_str)
            except ValueError:
                raise ParseError(f"Invalid TTL value: {ttl_str}", line) from None
            self.zone.directives["$TTL"] = ttl_str
        elif directive == "$INCLUDE":
            filename = self._advance()
            self.zone.include_directives.append(filename)
        else:
            raise ParseError(f"Unknown directive: {directive}", line)

    def _parse_resource_record(self, first_token: str) -> None:
        """Parse a resource record. Collects tokens until newline outside parens."""
        line = self._current_line()
        fields: list[str] = [first_token]
        self._advance()

        paren_depth = 0
        while self._current_token() is not None:
            token = self._current_token()

            if token == "(":
                paren_depth += 1
                self._advance()
                continue
            if token == ")":
                paren_depth -= 1
                self._advance()
                continue

            # Newline outside parens = end of record
            if token == "\n" and paren_depth == 0:
                break

            # Skip newlines inside parens
            if token == "\n":
                self._advance()
                continue

            fields.append(token)
            self._advance()

        # Skip trailing newlines
        self._skip_newlines()

        self._parse_record_fields(fields, line)

    def _parse_record_fields(self, fields: list[str], line: int) -> None:
        """Parse record fields."""
        if len(fields) < 3:
            raise ParseError(f"Record needs at least 3 fields, got {len(fields)}: {fields}", line)

        idx = 0
        name = fields[idx]
        idx += 1

        name = self._resolve_name(name)

        # Check for TTL
        ttl: int | None = None
        if idx < len(fields) and fields[idx].isdigit():
            ttl = int(fields[idx])
            idx += 1

        # Check for class
        record_class = "IN"
        if idx < len(fields) and fields[idx].upper() in ("IN", "CH", "HS", "NONE", "ANY"):
            record_class = fields[idx].upper()
            idx += 1

        if idx >= len(fields):
            raise ParseError("Missing record type", line)

        type_str = fields[idx].upper()
        idx += 1

        try:
            record_type = RecordType(type_str)
        except ValueError:
            record_type = RecordType.Unknown

        rdata = " ".join(fields[idx:]) if idx < len(fields) else ""
        rdata_parts = self._parse_rdata(record_type, rdata, fields[idx:], line)

        record = DNSRecord(
            name=name,
            ttl=ttl,
            record_class=record_class,
            record_type=record_type,
            rdata=rdata,
            line_number=line,
            rdata_parts=rdata_parts,
        )

        if record_type == RecordType.SOA:
            self.zone.soa = self._parse_soa_rdata(rdata_parts)

        self.zone.records.append(record)

    def _resolve_name(self, name: str) -> str:
        if name == "@":
            return self.zone.origin + "." if self.zone.origin else ""
        if name.endswith("."):
            return name
        if self.zone.origin:
            return f"{name}.{self.zone.origin}."
        return name

    def _parse_rdata(self, record_type: RecordType, rdata: str, parts: list[str], line: int) -> dict:
        if not parts:
            return {}

        try:
            if record_type == RecordType.A or record_type == RecordType.AAAA:
                return {"address": parts[0]}
            elif record_type == RecordType.CNAME:
                target = self._resolve_name(parts[0]).rstrip(".")
                return {"target": target}
            elif record_type == RecordType.MX:
                if len(parts) >= 2:
                    return {
                        "priority": int(parts[0]),
                        "exchange": self._resolve_name(parts[1]).rstrip("."),
                    }
                return {}
            elif record_type == RecordType.NS:
                return {"target": self._resolve_name(parts[0]).rstrip(".")}
            elif record_type == RecordType.TXT:
                txt_data = " ".join(parts)
                if txt_data.startswith('"') and txt_data.endswith('"'):
                    txt_data = txt_data[1:-1]
                return {"txtdata": txt_data}
            elif record_type == RecordType.SOA:
                if len(parts) >= 7:
                    return {
                        "mname": self._resolve_name(parts[0]).rstrip("."),
                        "rname": self._resolve_name(parts[1]).rstrip("."),
                        "serial": int(parts[2]),
                        "refresh": int(parts[3]),
                        "retry": int(parts[4]),
                        "expire": int(parts[5]),
                        "minimum": int(parts[6]),
                    }
                return {}
            elif record_type == RecordType.SRV:
                if len(parts) >= 4:
                    return {
                        "priority": int(parts[0]),
                        "weight": int(parts[1]),
                        "port": int(parts[2]),
                        "target": self._resolve_name(parts[3]).rstrip("."),
                    }
                return {}
            elif record_type == RecordType.PTR:
                return {"target": self._resolve_name(parts[0]).rstrip(".")}
            elif record_type == RecordType.CAA:
                if len(parts) >= 3:
                    return {"flags": int(parts[0]), "tag": parts[1], "value": parts[2].strip('"')}
                return {}
            elif record_type == RecordType.SSHFP:
                if len(parts) >= 3:
                    return {
                        "algorithm": int(parts[0]),
                        "fingerprint_type": int(parts[1]),
                        "fingerprint": parts[2],
                    }
                return {}
            elif record_type == RecordType.TLSA:
                if len(parts) >= 4:
                    return {
                        "cert_usage": int(parts[0]),
                        "selector": int(parts[1]),
                        "matching_type": int(parts[2]),
                        "cert_data": parts[3],
                    }
                return {}
            elif record_type == RecordType.DS:
                if len(parts) >= 4:
                    return {
                        "key_tag": int(parts[0]),
                        "algorithm": int(parts[1]),
                        "digest_type": int(parts[2]),
                        "digest": parts[3],
                    }
                return {}
            elif record_type == RecordType.DNSKEY:
                if len(parts) >= 3:
                    return {
                        "flags": int(parts[0]),
                        "protocol": int(parts[1]),
                        "algorithm": int(parts[2]),
                        "public_key": " ".join(parts[3:]) if len(parts) > 3 else "",
                    }
                return {}
            elif record_type == RecordType.HTTPS or record_type == RecordType.SVCB:
                if len(parts) >= 2:
                    return {
                        "priority": int(parts[0]),
                        "target": parts[1],
                        "params": " ".join(parts[2:]) if len(parts) > 2 else "",
                    }
                return {}
        except (ValueError, IndexError):
            return {"raw": rdata}

        return {"raw": rdata}

    def _parse_soa_rdata(self, rdata_parts: dict) -> SOARecord | None:
        try:
            return SOARecord(
                mname=rdata_parts.get("mname", ""),
                rname=rdata_parts.get("rname", ""),
                serial=int(rdata_parts.get("serial", 0)),
                refresh=int(rdata_parts.get("refresh", 0)),
                retry=int(rdata_parts.get("retry", 0)),
                expire=int(rdata_parts.get("expire", 0)),
                minimum=int(rdata_parts.get("minimum", 0)),
            )
        except (ValueError, TypeError):
            return None


def parse_zone(text: str, origin: str = "") -> ZoneFile:
    """Parse a DNS zone file from text."""
    parser = Parser(text, origin)
    return parser.parse()


def parse_zone_file(filepath: str, origin: str = "") -> ZoneFile:
    """Parse a DNS zone file from a file path."""
    with open(filepath, encoding="utf-8") as f:
        text = f.read()
    return parse_zone(text, origin)
