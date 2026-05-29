"""Guard against the two query defects seen live: non-ISO country codes and
placeholder stand-ins like YOUR_COUNTRY_CODE."""

from __future__ import annotations

from hunter import countries
from hunter.llm import _sanitize_query


def test_valid_query_untouched():
    q = 'port:27017 product:"MongoDB" country:CA'
    clean, warns = _sanitize_query(q)
    assert clean == q
    assert warns == []


def test_two_letter_country_kept():
    for code in ("US", "gb", "DE", "US,CA"):
        clean, warns = _sanitize_query(f"port:80 country:{code}")
        assert f"country:{code}" in clean
        assert warns == []


def test_quoted_country_kept():
    clean, warns = _sanitize_query('country:"US" port:443')
    assert 'country:"US"' in clean and warns == []


def test_usa_mapped_to_code():
    # "USA" is a recognised alias, so it's rescued to the ISO code, not dropped.
    clean, warns = _sanitize_query('port:27017 product:"MongoDB" country:USA')
    assert "country:USA" not in clean
    assert "country:US" in clean
    assert 'port:27017 product:"MongoDB" country:US' == clean
    assert warns and "US" in warns[0]


def test_full_name_mapped_to_code():
    clean, warns = _sanitize_query("port:80 country:Germany")
    assert clean == "port:80 country:DE"
    assert warns and "DE" in warns[0]


def test_quoted_multiword_country_mapped():
    clean, warns = _sanitize_query('country:"United Kingdom" port:443')
    assert "country:GB" in clean
    assert "port:443" in clean
    assert warns and "GB" in warns[0]


def test_unknown_country_name_still_dropped():
    # A name we don't recognise can't be mapped, so it's dropped like before.
    clean, warns = _sanitize_query("port:27017 country:Atlantis")
    assert "Atlantis" not in clean
    assert clean == "port:27017"
    assert warns and "country" in warns[0].lower()


def test_placeholder_country_stripped():
    clean, warns = _sanitize_query("port:27017 country:YOUR_COUNTRY_CODE")
    assert clean == "port:27017"
    assert warns


def test_placeholder_org_stripped():
    clean, warns = _sanitize_query('org:YOUR_ORG port:3389')
    assert "YOUR_ORG" not in clean and "port:3389" in clean
    assert warns


def test_quoted_multiword_value_survives():
    # Tokenizing on spaces must not corrupt quoted values when nothing is dropped.
    clean, warns = _sanitize_query('org:"Acme Industries" port:3389 country:USA')
    assert 'org:"Acme Industries"' in clean
    assert "port:3389" in clean
    assert "country:USA" not in clean


def test_real_value_with_your_substring_kept():
    # "Yourkit" contains "your" but not the "your_" placeholder pattern.
    clean, warns = _sanitize_query('product:"YourKit"')
    assert clean == 'product:"YourKit"'
    assert warns == []


# ── US state handling (the city:"Illinois" → region:IL bug) ──────────────────


def test_state_in_city_filter_becomes_region_with_country():
    # The exact failure observed in the UI: state stuffed into city:.
    clean, warns = _sanitize_query('device:webcam city:"Illinois"')
    assert clean == 'country:US device:webcam region:IL'
    assert any("region:IL" in w for w in warns)
    assert any("country:US" in w for w in warns)


def test_state_full_name_in_region_filter_becomes_code():
    clean, warns = _sanitize_query('region:"California" product:"Apache httpd"')
    assert "region:CA" in clean
    assert "region:California" not in clean
    assert "country:US" in clean


def test_state_unquoted_name_mapped():
    clean, _ = _sanitize_query("device:webcam state:Texas")
    assert "region:TX" in clean
    assert "country:US" in clean


def test_existing_country_not_duplicated():
    clean, _ = _sanitize_query('country:US device:webcam city:"Illinois"')
    assert clean.count("country:US") == 1
    assert "region:IL" in clean


def test_valid_region_code_untouched():
    # An explicit code is already correct — don't rewrite or add country.
    clean, warns = _sanitize_query("device:webcam region:IL")
    assert clean == "device:webcam region:IL"
    assert warns == []


def test_real_city_not_touched():
    clean, warns = _sanitize_query('device:webcam city:"Chicago"')
    assert clean == 'device:webcam city:"Chicago"'
    assert warns == []


def test_ambiguous_city_state_warned_not_rewritten():
    # "New York" in city: is a legit NYC search — warn, but leave it alone.
    clean, warns = _sanitize_query('city:"New York" port:80')
    assert 'city:"New York"' in clean
    assert "region:" not in clean
    assert warns and "region:NY" in warns[0]


def test_resolve_us_state_direct():
    assert countries.resolve_us_state("Illinois") == "IL"
    assert countries.resolve_us_state("  new york ") == "NY"
    assert countries.resolve_us_state("the district of columbia") == "DC"
    assert countries.resolve_us_state("IL") is None      # codes are not names
    assert countries.resolve_us_state("Atlantis") is None
