# MITRE ATT&CK knowledge base

The compact technique index in `attack_techniques.json` is generated from the MITRE ATT&CK Enterprise STIX bundle:

- Source: https://github.com/mitre-attack/attack-stix-data
- Raw bundle: `enterprise-attack/enterprise-attack.json`
- Generate: `python scripts/download_mitre_attack.py`

The raw 55 MB STIX bundle is ignored by Git. The compact index is committed so the server can build its retrieval layer without network access.

MITRE ATT&CK is a trademark of The MITRE Corporation. The ATT&CK STIX data is distributed under the terms of the upstream repository. See the upstream repository for the current license and attribution requirements.

Do not describe ATT&CK itself as a packet dataset. It is a knowledge base of adversary tactics and techniques; Cypher maps observed behavior to those techniques.
