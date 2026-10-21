# Dataset workspace

The ML pipeline uses the **CIC-IDS2017** dataset from the Canadian Institute for Cybersecurity.

- Official page: https://www.unb.ca/cic/datasets/ids-2017.html
- Mirror used by the download script: https://huggingface.co/datasets/c01dsnap/CIC-IDS2017
- Paper: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.

## Download

```powershell
.\.venv\Scripts\python.exe scripts\download_cicids2017.py
```

Raw files are written to `data/raw/cicids2017/` and are ignored by Git. Do not commit the dataset.

## Expected files

- `Monday-WorkingHours.pcap_ISCX.csv` — benign traffic
- `Tuesday-WorkingHours.pcap_ISCX.csv` — brute force
- `Wednesday-workingHours.pcap_ISCX.csv` — DoS
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` — web attacks
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` — infiltration
- `Friday-WorkingHours-Morning.pcap_ISCX.csv` — botnet
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` — DDoS
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` — port scan

## Label groups

The raw `Label` column is mapped to a smaller set for modelling:

| Group | Raw labels |
|---|---|
| Normal | BENIGN |
| Scan | PortScan |
| DoS/DDoS | DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest, DDoS, Heartbleed |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attack | Web Attack - Brute Force, Web Attack - XSS, Web Attack - SQL Injection |
| Bot/C2 | Bot |
| Infiltration | Infiltration |
| Other | anything not mapped above |

## MITRE ATT&CK

The compact ATT&CK technique index lives in `data/mitre/attack_techniques.json`. See `data/mitre/README.md` for generation and attribution.

## Provenance and limits

- The dataset is from 2017 and has known quality and labeling issues.
- Random splits can leak near-duplicate flows. The training pipeline must use deduplication and a time-based split.
- The dataset is flow-level, so serving must use a feature extractor with matching semantics.
- Do not advertise recall/F1 numbers until the evaluation report is generated from a held-out split.
