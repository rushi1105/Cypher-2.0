"""Shared feature contract for CIC-IDS2017 training and Cypher serving."""

from __future__ import annotations

import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "duration_s",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "fwd_packet_size_mean",
    "bwd_packet_size_mean",
    "packet_size_mean",
    "packet_size_std",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "iat_mean",
    "iat_std",
    "flow_packets_per_sec",
    "flow_bytes_per_sec",
    "down_up_ratio",
    "syn_ratio",
    "dst_port",
    "is_well_known_port",
]

LABEL_NAMES = [
    "Normal",
    "Scan",
    "DoS/DDoS",
    "Brute Force",
    "Web Attack",
    "Bot/C2",
    "Infiltration",
    "Other",
]

CIC_COLUMNS = {
    "destination_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "fwd_packets": "Total Fwd Packets",
    "bwd_packets": "Total Backward Packets",
    "fwd_bytes": "Total Length of Fwd Packets",
    "bwd_bytes": "Total Length of Bwd Packets",
    "fwd_packet_size_mean": "Fwd Packet Length Mean",
    "bwd_packet_size_mean": "Bwd Packet Length Mean",
    "packet_size_mean": "Packet Length Mean",
    "packet_size_std": "Packet Length Std",
    "flow_bytes_per_sec": "Flow Bytes/s",
    "flow_packets_per_sec": "Flow Packets/s",
    "iat_mean": "Flow IAT Mean",
    "iat_std": "Flow IAT Std",
    "syn_count": "SYN Flag Count",
    "ack_count": "ACK Flag Count",
    "fin_count": "FIN Flag Count",
    "rst_count": "RST Flag Count",
    "psh_count": "PSH Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "label": "Label",
}


def group_label(raw_label: object) -> str:
    label = str(raw_label).strip()
    if label == "BENIGN":
        return "Normal"
    if "PortScan" in label:
        return "Scan"
    if any(token in label for token in ("DoS", "DDoS", "Heartbleed")):
        return "DoS/DDoS"
    if "Patator" in label:
        return "Brute Force"
    if "Web Attack" in label:
        return "Web Attack"
    if "Bot" in label:
        return "Bot/C2"
    if "Infiltration" in label:
        return "Infiltration"
    return "Other"


def cic_frame_to_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Convert raw CIC-IDS2017 columns into the shared feature contract."""

    missing = [column for column in CIC_COLUMNS.values() if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing CIC columns: {missing}")

    raw = frame.rename(columns={value: key for key, value in CIC_COLUMNS.items()})
    features = pd.DataFrame(index=raw.index)

    features["duration_s"] = raw["flow_duration"].astype(float) / 1_000_000.0
    features["fwd_packets"] = raw["fwd_packets"].astype(float)
    features["bwd_packets"] = raw["bwd_packets"].astype(float)
    features["total_packets"] = features["fwd_packets"] + features["bwd_packets"]
    features["fwd_bytes"] = raw["fwd_bytes"].astype(float)
    features["bwd_bytes"] = raw["bwd_bytes"].astype(float)
    features["total_bytes"] = features["fwd_bytes"] + features["bwd_bytes"]
    features["fwd_packet_size_mean"] = raw["fwd_packet_size_mean"].astype(float)
    features["bwd_packet_size_mean"] = raw["bwd_packet_size_mean"].astype(float)
    features["packet_size_mean"] = raw["packet_size_mean"].astype(float)
    features["packet_size_std"] = raw["packet_size_std"].astype(float)
    features["syn_count"] = raw["syn_count"].astype(float)
    features["ack_count"] = raw["ack_count"].astype(float)
    features["fin_count"] = raw["fin_count"].astype(float)
    features["rst_count"] = raw["rst_count"].astype(float)
    features["psh_count"] = raw["psh_count"].astype(float)
    features["iat_mean"] = raw["iat_mean"].astype(float) / 1_000_000.0
    features["iat_std"] = raw["iat_std"].astype(float) / 1_000_000.0
    features["flow_packets_per_sec"] = raw["flow_packets_per_sec"].astype(float)
    features["flow_bytes_per_sec"] = raw["flow_bytes_per_sec"].astype(float)
    features["down_up_ratio"] = raw["down_up_ratio"].astype(float)
    features["syn_ratio"] = features["syn_count"] / features["total_packets"].clip(lower=1)
    features["dst_port"] = raw["destination_port"].astype(float)
    features["is_well_known_port"] = (features["dst_port"] <= 1023).astype(float)

    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.fillna(0.0)
    features = features.clip(lower=0.0)

    features["label"] = raw["label"].map(group_label)
    features["raw_label"] = raw["label"].astype(str)
    return features


def validate_feature_frame(frame: pd.DataFrame) -> None:
    missing = [name for name in FEATURE_NAMES if name not in frame.columns]
    if missing:
        raise ValueError(f"Missing features: {missing}")
    if not np.isfinite(frame[FEATURE_NAMES].to_numpy(dtype=np.float64)).all():
        raise ValueError("Feature frame contains non-finite values")
