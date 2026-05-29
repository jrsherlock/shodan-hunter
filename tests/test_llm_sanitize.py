"""Guard against the two query defects seen live: non-ISO country codes and
placeholder stand-ins like YOUR_COUNTRY_CODE."""

from __future__ import annotations

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
