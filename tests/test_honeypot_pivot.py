"""Honeypot detection after Shodan retired the standalone honeyscore lab.

Detection now rides on the `honeypot` tag (free, from InternetDB or the banner);
honeyscore() must fail soft to None on the retirement message.
"""

from __future__ import annotations

import shodan

from hunter import recon, shodan_api


def test_honeypot_from_tags():
    assert recon.honeypot_from_tags(["honeypot"]) is True
    assert recon.honeypot_from_tags(["ICS Honeypot", "vpn"]) is True
    assert recon.honeypot_from_tags(["cloud", "cdn"]) is False
    assert recon.honeypot_from_tags([]) is False
    assert recon.honeypot_from_tags(None) is False


def test_annotate_flags_honeypot_from_idb_tag():
    matches = [{"ip_str": "1.2.3.4"}]
    recon.annotate_matches(
        matches, {"1.2.3.4": {"tags": ["honeypot"], "vulns": [], "ports": [80]}}, {}, 0.5
    )
    assert matches[0]["is_honeypot"] is True
    assert matches[0]["idb_ports"] == [80]


def test_annotate_flags_honeypot_from_match_tag():
    matches = [{"ip_str": "1.2.3.4", "tags": ["honeypot"]}]
    recon.annotate_matches(matches, {}, {}, 0.5)
    assert matches[0]["is_honeypot"] is True


def test_annotate_no_honeypot_without_tag_or_score():
    matches = [{"ip_str": "1.2.3.4", "tags": ["cloud"]}]
    recon.annotate_matches(matches, {"1.2.3.4": {"tags": ["cdn"]}}, {}, 0.5)
    assert matches[0]["is_honeypot"] is False


def test_annotate_legacy_score_still_flags():
    matches = [{"ip_str": "1.2.3.4"}]
    recon.annotate_matches(matches, {}, {"1.2.3.4": 0.9}, 0.5)
    assert matches[0]["is_honeypot"] is True


def test_honeyscore_retirement_message_returns_none(patch_api):
    patch_api.labs.honeyscore.side_effect = shodan.APIError(
        "Honeyscore has been integrated into the regular crawlers."
    )
    assert shodan_api.honeyscore("1.1.1.1") is None
    # Negative result is cached → the second call must not re-hit the client.
    assert shodan_api.honeyscore("1.1.1.1") is None
    assert patch_api.labs.honeyscore.call_count == 1
