"""Tests for inscope core."""
from inscope import Scope, parse_entry


def test_bare_domain_in_scope():
    s = Scope.from_lines(["example.com"])
    assert s.is_in_scope("example.com")
    assert not s.is_in_scope("other.com")
    assert not s.is_in_scope("api.example.com")


def test_wildcard_matches_subdomains():
    s = Scope.from_lines(["*.example.com"])
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("deep.api.example.com")
    assert s.is_in_scope("example.com")
    assert not s.is_in_scope("evil.com")
    assert not s.is_in_scope("notexample.com")


def test_exclusion_takes_precedence():
    s = Scope.from_lines(["*.example.com", "!auth.example.com"])
    assert s.is_in_scope("api.example.com")
    assert not s.is_in_scope("auth.example.com")


def test_cidr_range():
    s = Scope.from_lines(["10.0.0.0/24"])
    assert s.is_in_scope("10.0.0.5")
    assert s.is_in_scope("10.0.0.255")
    assert not s.is_in_scope("10.0.1.5")


def test_single_ip():
    s = Scope.from_lines(["192.168.1.10"])
    assert s.is_in_scope("192.168.1.10")
    assert not s.is_in_scope("192.168.1.11")


def test_url_normalization():
    s = Scope.from_lines(["https://api.example.com/v2"])
    assert s.is_in_scope("api.example.com")
    assert s.is_in_scope("https://api.example.com/anything")
    assert s.is_in_scope("api.example.com:443")


def test_target_with_path_and_port():
    s = Scope.from_lines(["example.com"])
    assert s.is_in_scope("https://example.com/admin")
    assert s.is_in_scope("example.com:8080")


def test_comment_and_blank_lines_skipped():
    s = Scope.from_lines(["# this is a comment", "", "example.com"])
    assert s.is_in_scope("example.com")


def test_invalid_lines_ignored():
    s = Scope.from_lines(["not a domain", "example.com"])
    assert s.is_in_scope("example.com")


def test_filter_helper():
    s = Scope.from_lines(["*.example.com", "!auth.example.com"])
    targets = ["api.example.com", "auth.example.com", "evil.com", "deep.example.com"]
    assert s.filter(targets) == ["api.example.com", "deep.example.com"]


def test_excluded_cidr():
    s = Scope.from_lines(["10.0.0.0/16", "!10.0.99.0/24"])
    assert s.is_in_scope("10.0.5.5")
    assert not s.is_in_scope("10.0.99.5")


def test_parse_entry_kinds():
    assert parse_entry("example.com").kind == "domain"
    assert parse_entry("*.example.com").kind == "wildcard"
    assert parse_entry("10.0.0.0/24").kind == "cidr"
    assert parse_entry("192.168.1.1").kind == "ip"
    assert parse_entry("https://example.com").kind == "url"
