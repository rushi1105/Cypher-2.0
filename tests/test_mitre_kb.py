from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.mitre_kb import MitreKnowledgeBase  # noqa: E402


@pytest.fixture(scope="module")
def kb() -> MitreKnowledgeBase:
    knowledge = MitreKnowledgeBase()
    assert knowledge.load(), knowledge.load_error
    return knowledge


def test_knowledge_base_loads(kb: MitreKnowledgeBase) -> None:
    assert kb.technique_count > 500


def test_get_known_technique(kb: MitreKnowledgeBase) -> None:
    technique = kb.get("T1046")
    assert technique is not None
    assert technique["name"] == "Network Service Discovery"
    assert "discovery" in technique["tactics"]


def test_search_port_scan(kb: MitreKnowledgeBase) -> None:
    results = kb.search("port scan", top_k=5)
    assert results
    assert any(result["id"] == "T1046" for result in results)


def test_search_dns_flood(kb: MitreKnowledgeBase) -> None:
    results = kb.search("dns flood", top_k=5)
    assert results
    assert any(result["id"] == "T1498" for result in results)


def test_explain_alert_with_mitre(kb: MitreKnowledgeBase) -> None:
    result = kb.explain_alert({
        "rule": "port_scan",
        "title": "Possible port scan",
        "src": "10.0.0.66",
        "dst": "192.168.1.10",
        "dport": 10019,
        "mitre": {"id": "T1046"},
        "evidence": {"unique_ports": 20, "window_s": 60},
    })
    assert "error" not in result
    assert result["technique"]["id"] == "T1046"
    assert "T1046" in result["explanation"]
    assert result["citations"][0]["url"].startswith("https://attack.mitre.org/")


def test_explain_alert_infers_technique(kb: MitreKnowledgeBase) -> None:
    result = kb.explain_alert({
        "rule": "port_scan",
        "title": "Possible port scan",
        "description": "One source contacted many unique destination ports.",
        "evidence": {"unique_ports": 20},
    })
    assert "error" not in result
    assert result["technique"]["id"] == "T1046"


def test_unknown_technique(kb: MitreKnowledgeBase) -> None:
    assert kb.get("T9999") is None
