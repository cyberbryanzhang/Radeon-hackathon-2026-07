from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import gradio as gr


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "outputs"

OUTPUT_JSON = OUTPUT_DIR / "web_incident_report.json"
OUTPUT_MARKDOWN = OUTPUT_DIR / "web_incident_report.md"
OUTPUT_PERFORMANCE = OUTPUT_DIR / "web_incident_report_performance.json"


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("JSON input must contain one object.")

    return data


def analyze(summary_file: str | None):
    if not summary_file:
        return (
            "Please upload a network-flow summary JSON file.",
            "Unknown",
            "Unknown",
            "Unknown",
            {},
            {},
            "",
            None,
        )

    summary_path = Path(summary_file)

    try:
        load_json(summary_path)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return (
            f"Invalid input: {error}",
            "Unknown",
            "Unknown",
            "Unknown",
            {},
            {},
            "",
            None,
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(PROJECT_ROOT / "app" / "analyze_flow.py"),
        str(summary_path),
        "--output",
        str(OUTPUT_JSON),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        details = error.stderr.strip() or error.stdout.strip()

        return (
            f"Analysis failed:\n\n```text\n{details}\n```",
            "Failed",
            "Unknown",
            "Unknown",
            {},
            {},
            "",
            None,
        )

    try:
        report = load_json(OUTPUT_JSON)
        performance = load_json(OUTPUT_PERFORMANCE)
        markdown = OUTPUT_MARKDOWN.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        return (
            f"Could not read generated output: {error}",
            "Failed",
            "Unknown",
            "Unknown",
            {},
            {},
            "",
            None,
        )

    severity = str(report.get("severity", "Unknown"))
    confidence = report.get("confidence", "Unknown")
    attack_type = str(report.get("attack_type", "Unknown"))

    confidence_text = (
        f"{confidence}%"
        if confidence != "Unknown"
        else "Unknown"
    )

    status = (
        "## Analysis complete\n\n"
        f"**Severity:** {severity}  \n"
        f"**Confidence:** {confidence_text}  \n"
        f"**Attack type:** {attack_type}"
    )

    return (
        status,
        severity,
        confidence_text,
        attack_type,
        report,
        performance,
        markdown,
        str(OUTPUT_MARKDOWN),
    )


CSS = """
.gradio-container {
    max-width: 1200px !important;
    margin: auto !important;
}

#header {
    text-align: center;
    margin-bottom: 16px;
}

footer {
    display: none !important;
}
"""


with gr.Blocks(
    title="SOCPilot AI",
) as demo:
    gr.Markdown(
        """
# SOCPilot AI

### Local SOC Assistant powered by Meta Llama 3.1 and AMD ROCm

Upload a summarized network-flow JSON file to generate a structured incident
report, MITRE ATT&CK mapping, recommendations, and ROCm performance metrics.
""",
        elem_id="header",
    )

    with gr.Row():
        with gr.Column(scale=1):
            summary_input = gr.File(
                label="Network-flow summary JSON",
                file_types=[".json"],
                type="filepath",
            )

            analyze_button = gr.Button(
                "Run Local Analysis",
                variant="primary",
            )

        with gr.Column(scale=2):
            status_output = gr.Markdown(
                "Upload a JSON file to begin."
            )

            with gr.Row():
                severity_output = gr.Textbox(
                    label="Severity",
                    value="Unknown",
                    interactive=False,
                )

                confidence_output = gr.Textbox(
                    label="Confidence",
                    value="Unknown",
                    interactive=False,
                )

                attack_output = gr.Textbox(
                    label="Attack Type",
                    value="Unknown",
                    interactive=False,
                )

    with gr.Tabs():
        with gr.Tab("Incident Report"):
            markdown_output = gr.Markdown()

        with gr.Tab("Structured JSON"):
            report_output = gr.JSON()

        with gr.Tab("Performance"):
            performance_output = gr.JSON()

        with gr.Tab("Download"):
            download_output = gr.File(
                label="Download Markdown Report"
            )

    analyze_button.click(
        fn=analyze,
        inputs=summary_input,
        outputs=[
            status_output,
            severity_output,
            confidence_output,
            attack_output,
            report_output,
            performance_output,
            markdown_output,
            download_output,
        ],
    )


if __name__ == "__main__":

    demo.queue().launch(

        server_name="0.0.0.0",

        server_port=7860,

        share=False,

        show_error=True,

        css=CSS,

    )