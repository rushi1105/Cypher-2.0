"""Retrieval-augmented MITRE ATT&CK knowledge base."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from .rules import RULE_SPECS
except ImportError:
    from rules import RULE_SPECS

logger = logging.getLogger(__name__)

RULE_TECHNIQUE_HINTS = {spec["id"]: spec["mitre"] for spec in RULE_SPECS}

TECHNIQUE_KEYWORDS = {
    "T1046": "port scan portscan network service discovery scanning reconnaissance",
    "T1498": "syn flood dns flood denial of service dos ddos traffic flood",
    "T1110": "brute force password login attempts credential access",
    "T1571": "suspicious port non-standard port backdoor command and control",
    "T1071": "beaconing command and control application layer protocol c2",
    "T1071.001": "blocked domain web protocols http https command and control",
    "T1071.004": "dns tunneling dns command and control",
    "T1048": "data exfiltration exfil outbound transfer alternative protocol",
}

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INDEX = ROOT / "data" / "mitre" / "attack_techniques.json"


def clean_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = text.replace("\ufffd", "'")
    return re.sub(r"\s+", " ", text).strip()


def first_sentences(text: str, count: int = 2, max_chars: int = 520) -> str:
    text = clean_text(text)
    sentences = re.split(r"(?<=[.!?])\s+", text)
    summary = " ".join(sentences[:count]).strip()
    if len(summary) > max_chars:
        summary = summary[: max_chars - 3].rstrip() + "..."
    return summary


class MitreKnowledgeBase:
    def __init__(self, index_path: Optional[Path] = None) -> None:
        self.index_path = Path(os.getenv("CYPHER_MITRE_INDEX", str(DEFAULT_INDEX)))
        if index_path is not None:
            self.index_path = Path(index_path)
        self._techniques: dict[str, dict] = {}
        self._documents: list[dict] = []
        self._vectorizer: Optional[TfidfVectorizer] = None
        self._matrix = None
        self._loaded = False
        self._load_error: Optional[str] = None

    def load(self) -> bool:
        if self._loaded:
            return True
        try:
            if not self.index_path.exists():
                raise FileNotFoundError(
                    f"Missing ATT&CK index: {self.index_path}. Run scripts/download_mitre_attack.py."
                )
            techniques = json.loads(self.index_path.read_text(encoding="utf-8"))
            self._techniques = {item["id"]: item for item in techniques}
            self._documents = techniques
            corpus = [
                " ".join(
                    [
                        item.get("id", ""),
                        item.get("name", ""),
                        item.get("name", ""),
                        item.get("name", ""),
                        " ".join(item.get("tactics", [])),
                        " ".join(item.get("tactics", [])),
                        TECHNIQUE_KEYWORDS.get(item.get("id", ""), ""),
                        TECHNIQUE_KEYWORDS.get(item.get("id", ""), ""),
                        TECHNIQUE_KEYWORDS.get(item.get("id", ""), ""),
                        clean_text(item.get("description", "")),
                        clean_text(item.get("detection", "")),
                    ]
                )
                for item in techniques
            ]
            self._vectorizer = TfidfVectorizer(
                stop_words="english",
                ngram_range=(1, 2),
                max_features=25000,
                sublinear_tf=True,
            )
            self._matrix = self._vectorizer.fit_transform(corpus)
            self._loaded = True
            logger.info("MITRE ATT&CK knowledge base loaded: %d techniques", len(techniques))
            return True
        except Exception as exc:
            self._load_error = str(exc)
            logger.error("Failed to load ATT&CK knowledge base: %s", exc)
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    @property
    def technique_count(self) -> int:
        return len(self._techniques)

    def get(self, technique_id: str) -> Optional[dict]:
        technique = self._techniques.get(technique_id)
        if not technique:
            return None
        return {
            **technique,
            "summary": first_sentences(technique.get("description", "")),
            "detection_summary": first_sentences(technique.get("detection", "")),
        }

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not self._loaded or self._vectorizer is None or self._matrix is None:
            return []
        if not query.strip():
            return []
        vector = self._vectorizer.transform([query])
        scores = cosine_similarity(vector, self._matrix)[0]
        ranked = scores.argsort()[::-1][: max(1, min(top_k, 20))]
        results = []
        for index in ranked:
            if scores[index] <= 0:
                continue
            technique = self._documents[int(index)]
            results.append(
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "tactics": technique.get("tactics", []),
                    "url": technique.get("url", ""),
                    "score": float(round(float(scores[index]), 4)),
                    "summary": first_sentences(technique.get("description", "")),
                }
            )
        return results

    def explain_alert(self, alert: dict) -> dict:
        technique = None
        mitre = alert.get("mitre") or {}
        if mitre.get("id"):
            technique = self.get(str(mitre["id"]))
        if technique is None and alert.get("rule") in RULE_TECHNIQUE_HINTS:
            technique = self.get(RULE_TECHNIQUE_HINTS[alert["rule"]])
        if technique is None:
            query = " ".join(
                str(alert.get(key, ""))
                for key in ("title", "rule", "description", "app", "sni")
            )
            results = self.search(query, top_k=1)
            if results:
                technique = self.get(results[0]["id"])

        if technique is None:
            return {
                "error": "No matching ATT&CK technique found.",
                "citations": [],
            }

        evidence = alert.get("evidence") or {}
        evidence_text = ", ".join(f"{key}={value}" for key, value in evidence.items())
        observed = (
            f"{alert.get('rule', 'rule')} matched "
            f"{alert.get('src', '?')} -> {alert.get('dst', '?')}:{alert.get('dport', '?')}"
        )
        if evidence_text:
            observed += f" ({evidence_text})"

        tactics = ", ".join(technique.get("tactics", [])) or "unmapped tactic"
        detection = technique.get("detection_summary") or (
            "ATT&CK does not provide a dedicated detection section for this technique."
        )
        explanation = (
            f"Observed: {observed}. "
            f"ATT&CK {technique['id']} ({technique['name']}) is associated with {tactics}. "
            f"{technique.get('summary', '')} "
            f"This is a mapping based on the retrieved ATT&CK description, not proof of compromise. "
            f"Detection guidance: {detection}"
        )
        return {
            "technique": {key: technique[key] for key in ("id", "name", "tactics", "url")},
            "explanation": explanation,
            "citations": [
                {
                    "source": "MITRE ATT&CK",
                    "title": f"{technique['id']} {technique['name']}",
                    "url": technique.get("url", ""),
                }
            ],
            "related": self.search(
                f"{technique['name']} {' '.join(technique.get('tactics', []))}",
                top_k=3,
            ),
        }


mitre_kb = MitreKnowledgeBase()
