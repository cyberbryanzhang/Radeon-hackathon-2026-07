from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


DEFAULT_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
]


def safe_number(value: Any) -> float | int | None:
    """Convert NumPy values into JSON-safe Python values."""
    if pd.isna(value) or np.isinf(value):
        return None

    if isinstance(value, (np.integer, int)):
        return int(value)

    if isinstance(value, (np.floating, float)):
        return round(float(value), 3)

    return value


def summarize_flows(
    csv_path: Path,
    sample_count: int,
    filter_label: str | None,
) -> dict[str, Any]:
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    total_rows = len(df)

    if filter_label:
        if "Label" not in df.columns:
            raise ValueError("The CSV does not contain a Label column.")

        df = df[df["Label"].astype(str).str.strip() == filter_label]

        if df.empty:
            available = sorted(df["Label"].dropna().unique().tolist())
            raise ValueError(
                f"No rows found for label {filter_label!r}. "
                f"Available labels: {available}"
            )

    sample = df.head(sample_count).copy()

    # Replace values that are not valid JSON numbers.
    sample.replace([np.inf, -np.inf], np.nan, inplace=True)

    available_features = [
        feature for feature in DEFAULT_FEATURES
        if feature in sample.columns
    ]

    numeric_features = sample[available_features].apply(
        pd.to_numeric,
        errors="coerce",
    )

    feature_statistics: dict[str, dict[str, float | int | None]] = {}

    for column in numeric_features.columns:
        series = numeric_features[column].dropna()

        if series.empty:
            continue

        feature_statistics[column] = {
            "mean": safe_number(series.mean()),
            "median": safe_number(series.median()),
            "minimum": safe_number(series.min()),
            "maximum": safe_number(series.max()),
        }

    destination_ports: list[dict[str, int]] = []

    if "Destination Port" in sample.columns:
        ports = pd.to_numeric(
            sample["Destination Port"],
            errors="coerce",
        ).dropna().astype(int)

        destination_ports = [
            {
                "port": int(port),
                "flow_count": int(count),
            }
            for port, count in ports.value_counts().head(10).items()
        ]

    summary = {
        "dataset": "CICIDS2017",
        "source_file": csv_path.name,
        "source_row_count": total_rows,
        "analyzed_sample_count": len(sample),
        "destination_port_count": (
            int(sample["Destination Port"].nunique())
            if "Destination Port" in sample.columns
            else None
        ),
        "top_destination_ports": destination_ports,
        "feature_statistics": feature_statistics,
    }

    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an LLM-friendly summary from CICIDS2017 flows."
    )
    parser.add_argument(
        "csv_path",
        type=Path,
        help="Path to a CICIDS2017 CSV file.",
    )
    parser.add_argument(
        "--sample-count",
        type=int,
        default=200,
        help="Number of matching rows to summarize.",
    )
    parser.add_argument(
        "--filter-label",
        help=(
            "Optionally select rows using a known dataset label. "
            "The label is not included in the generated summary."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/flow_summary.json"),
        help="Destination JSON path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {args.csv_path}")

    if args.sample_count < 1:
        raise ValueError("--sample-count must be greater than zero.")

    summary = summarize_flows(
        csv_path=args.csv_path,
        sample_count=args.sample_count,
        filter_label=args.filter_label,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2))
    print(f"\nSummary saved to: {args.output}")


if __name__ == "__main__":
    main()
