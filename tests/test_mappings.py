"""Coverage for the human-readable mapping helpers used by reports.

reports.py renders describe_ref / describe_ai_ref for every reference a
finding carries, so every ref emitted by the rule-to-taxonomy maps must
resolve to a real label rather than falling through to the raw ref string.
"""

from greynoc_nhi.ai_mapping import (
    NIST_AML_CATEGORIES,
    OWASP_AGENTIC_TOP_10,
    OWASP_LLM_TOP_10_2025,
    RULE_TO_AI_RISK,
    describe_ai_ref,
    map_rule_to_ai_risk,
)
from greynoc_nhi.owasp_mapping import OWASP_NHI_TOP_10, RULE_TO_OWASP, describe_ref


def test_describe_ref_labels_every_emitted_owasp_ref():
    emitted = {ref for refs in RULE_TO_OWASP.values() for ref in refs}
    assert emitted
    for ref in emitted:
        label = describe_ref(ref)
        assert label
        assert label != ref, f"{ref} has no human-readable label"


def test_describe_ref_labels_every_top_10_entry():
    for ref, expected in OWASP_NHI_TOP_10.items():
        assert describe_ref(ref) == expected


def test_describe_ref_falls_back_to_raw_ref_for_unknown():
    assert describe_ref("NHI99:2099") == "NHI99:2099"


def test_describe_ref_known_labels():
    assert describe_ref("NHI2:2025") == "Secret Leakage"
    assert describe_ref("NHI7:2025") == "Long-Lived Secrets"


def test_describe_ai_ref_labels_every_emitted_ai_ref():
    emitted = {ref for refs in RULE_TO_AI_RISK.values() for ref in refs}
    assert emitted
    for ref in emitted:
        label = describe_ai_ref(ref)
        assert label
        assert label != ref, f"{ref} has no human-readable label"


def test_describe_ai_ref_covers_all_three_taxonomies():
    assert describe_ai_ref("LLM01:2025") == "Prompt Injection"
    assert describe_ai_ref("ASI02") == "Tool Misuse"
    assert describe_ai_ref("NIST-AML:Privacy") == "Privacy"


def test_describe_ai_ref_labels_every_taxonomy_entry():
    for ref, expected in {**OWASP_LLM_TOP_10_2025, **OWASP_AGENTIC_TOP_10, **NIST_AML_CATEGORIES}.items():
        assert describe_ai_ref(ref) == expected


def test_describe_ai_ref_falls_back_to_raw_ref_for_unknown():
    assert describe_ai_ref("LLM99:2099") == "LLM99:2099"


def test_map_rule_to_ai_risk_unknown_rule_returns_empty_list():
    assert map_rule_to_ai_risk("nhi_rule_that_does_not_exist") == []


def test_all_ai_risk_refs_are_valid_taxonomy_entries():
    valid = set(OWASP_LLM_TOP_10_2025) | set(OWASP_AGENTIC_TOP_10) | set(NIST_AML_CATEGORIES)
    for rule_id, refs in RULE_TO_AI_RISK.items():
        assert refs, f"{rule_id} maps to an empty ref list"
        for ref in refs:
            assert ref in valid, f"{rule_id} maps to unknown ref {ref}"
