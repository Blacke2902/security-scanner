"""Tests for version comparison utilities."""

from repo_security_scanner.version_utils import (
    parse_version, compare_versions, version_in_range, clean_version,
)


class TestParseVersion:
    def test_basic(self):
        assert parse_version("1.2.3") == (1, 2, 3, 1)

    def test_leading_v(self):
        assert parse_version("v1.2.3") == (1, 2, 3, 1)

    def test_two_parts(self):
        assert parse_version("1.2") == (1, 2, 0, 1)

    def test_pre_release_semver(self):
        t = parse_version("1.0.0-beta.1")
        assert t[:3] == (1, 0, 0)
        assert t[3] == 0  # Pre-release sorts lower

    def test_pre_release_pep440(self):
        t = parse_version("1.0.0a1")
        assert t[:3] == (1, 0, 0)
        assert t[3] == 0


class TestCompareVersions:
    def test_equal(self):
        assert compare_versions("1.2.3", "1.2.3") == 0

    def test_greater(self):
        assert compare_versions("2.0.0", "1.9.9") == 1

    def test_less(self):
        assert compare_versions("1.0.0", "1.0.1") == -1

    def test_pre_release_lower(self):
        assert compare_versions("1.0.0-alpha", "1.0.0") == -1

    def test_leading_v(self):
        assert compare_versions("v1.2.3", "1.2.3") == 0


class TestCleanVersion:
    def test_plain(self):
        assert clean_version("1.2.3") == "1.2.3"

    def test_caret(self):
        assert clean_version("^4.18.0") == "4.18.0"

    def test_tilde(self):
        assert clean_version("~1.2.0") == "1.2.0"

    def test_equals(self):
        assert clean_version("==2.31.0") == "2.31.0"

    def test_gte(self):
        assert clean_version(">=1.0.0") == "1.0.0"

    def test_star(self):
        assert clean_version("*") is None

    def test_empty(self):
        assert clean_version("") is None


class TestVersionInRange:
    def test_in_range(self):
        assert version_in_range("1.3.0", ">= 1.0.0, < 1.6.0") is True

    def test_at_upper_boundary(self):
        assert version_in_range("1.6.0", ">= 1.0.0, < 1.6.0") is False

    def test_below_range(self):
        assert version_in_range("0.9.0", ">= 1.0.0, < 1.6.0") is False

    def test_above_range(self):
        assert version_in_range("2.0.0", ">= 1.0.0, < 1.6.0") is False

    def test_less_than_only(self):
        assert version_in_range("1.9.9", "< 2.0.0") is True

    def test_less_than_boundary(self):
        assert version_in_range("2.0.0", "< 2.0.0") is False

    def test_exact_match(self):
        assert version_in_range("1.2.3", "= 1.2.3") is True

    def test_exact_no_match(self):
        assert version_in_range("1.2.4", "= 1.2.3") is False

    def test_caret_version_input(self):
        assert version_in_range("^1.3.0", ">= 1.0.0, < 1.6.0") is True

    def test_empty_range_conservative(self):
        assert version_in_range("1.0.0", "") is True

    def test_gte_only(self):
        assert version_in_range("1.0.0", ">= 1.0.0") is True
        assert version_in_range("0.9.0", ">= 1.0.0") is False
