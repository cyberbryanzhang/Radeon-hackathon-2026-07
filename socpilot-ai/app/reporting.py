
from __future__ import annotations

from typing import Any

ATTACK_MAPPINGS = {

    "port scan": {

        "technique_id": "T1046",

        "technique_name": "Network Service Scanning",

    },

    "port scanning": {

        "technique_id": "T1046",

        "technique_name": "Network Service Scanning",

    },

    "network scanning": {

        "technique_id": "T1046",

        "technique_name": "Network Service Scanning",

    },

    "network service scanning": {

        "technique_id": "T1046",

        "technique_name": "Network Service Scanning",

    },

    "brute force": {

        "technique_id": "T1110",

        "technique_name": "Brute Force",

    },

}

def normalize_report(report: dict[str, Any]) -> dict[str, Any]:

    """Normalize model output and correct supported MITRE mappings."""

    attack_type = str(report.get("attack_type", "")).strip()

    normalized_attack = attack_type.lower()

    for keyword, mapping in ATTACK_MAPPINGS.items():

        if keyword in normalized_attack:

            report["mitre_attack"] = [mapping]

            break

    return report

def report_to_markdown(report: dict[str, Any]) -> str:

    """Convert a structured incident report into readable Markdown."""

    severity = report.get("severity", "Unknown")

    confidence = report.get("confidence", "Unknown")

    attack_type = report.get("attack_type", "Unknown")

    summary = report.get("summary", "No summary was generated.")

    lines = [

        "# SOCPilot Incident Report",

        "",

        "## Incident Overview",

        "",

        f"- **Severity:** {severity}",

        f"- **Confidence:** {confidence}%",

        f"- **Likely Activity:** {attack_type}",

        "",

        "## Summary",

        "",

        str(summary),

        "",

        "## MITRE ATT&CK Mapping",

        "",

    ]

    mitre_entries = report.get("mitre_attack", [])

    if mitre_entries:

        for entry in mitre_entries:

            technique_id = entry.get("technique_id", "Unknown")

            technique_name = entry.get("technique_name", "Unknown")

            lines.append(f"- **{technique_id} — {technique_name}**")

    else:

        lines.append("- No reliable MITRE ATT&CK mapping was identified.")

    lines.extend(

        [

            "",

            "## Evidence",

            "",

        ]

    )

    evidence_entries = report.get("evidence", [])

    if evidence_entries:

        for evidence in evidence_entries:

            feature = evidence.get("feature", "Unknown feature")

            value = evidence.get("observed_value", "Unknown")

            interpretation = evidence.get(

                "interpretation",

                "No interpretation provided.",

            )

            lines.extend(

                [

                    f"### {feature}",

                    "",

                    f"- **Observed value:** {value}",

                    f"- **Interpretation:** {interpretation}",

                    "",

                ]

            )

    else:

        lines.append("No supporting evidence was provided.")

        lines.append("")

    lines.extend(

        [

            "## Recommendations",

            "",

        ]

    )

    recommendations = report.get("recommendations", [])

    if recommendations:

        for recommendation in recommendations:

            lines.append(f"- {recommendation}")

    else:

        lines.append("- Continue monitoring and collect additional evidence.")

    lines.extend(

        [

            "",

            "---",

            "",

            "Generated locally by SOCPilot using AMD ROCm inference.",

            "",

        ]

    )

    return "\n".join(lines)

