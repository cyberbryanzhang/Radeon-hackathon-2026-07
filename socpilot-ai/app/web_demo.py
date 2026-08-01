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


def analyze(summary_file: Any):
    if summary_file is None:
        return (
            "Please upload a network-flow summary JSON file.",
            {},
            {},
            None,
            None,
        )

    summary_path = Path(summary_file)

    try:
        json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return (
            f"Invalid JSON file: {error}",
            {},
            {},
            None,
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
            {},
            {},
            None,
            None,
        )

    try:
        report = json.loads(OUTPUT_JSON.read_text(encoding="utf-8"))
        performance = json.loads(
            OUTPUT_PERFORMANCE.read_text(encoding="utf-8")
        )
        markdown = OUTPUT_MARKDOWN.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as error:
        return (
            f"Analysis completed, but generated files could not be read: {error}",
            {},
            {},
            None,
            None,
        )

    terminal_summary = result.stdout.strip()

    status = (
        "## Analysis complete\n\n"
        f"**Severity:** {report.get('severity', 'Unknown')}  \n"
        f"**Confidence:** {report.get('confidence', 'Unknown')}%  \n"
        f"**Attack type:** {report.get('attack_type', 'Unknown')}\n\n"
        "<details><summary>Terminal output</summary>\n\n"
        f"```text\n{terminal_summary}\n```\n"
        "</details>"
    )

    return (
        status,
        report,
        performance,
        markdown,
        str(OUTPUT_MARKDOWN),
    )


with gr.Blocks(title="SOCPilot AI") as demo:
    gr.Markdown(
        """
# SOCPilot AI

Local Security Operations Center incident analysis using  
**Meta Llama 3.1 8B** and **AMD ROCm**.

Upload a flow-summary JSON file to generate a structured incident report,
MITRE ATT&CK mapping, recommendations, and performance measurements.
"""
    )

    with gr.Row():
        summary_input = gr.File(
            label="Network-flow summary JSON",
            file_types=[".json"],
            type="filepath",
        )

        analyze_button = gr.Button(
            "Analyze locally",
            variant="primary",
        )

    status_output = gr.Markdown()

    with gr.Tab("Incident Report"):
        report_output = gr.JSON(label="Structured JSON report")
        markdown_output = gr.Markdown(label="Readable incident report")
        download_output = gr.File(label="Download Markdown report")

    with gr.Tab("Performance"):
        performance_output = gr.JSON(label="ROCm inference metrics")

    analyze_button.click(
        fn=analyze,
        inputs=summary_input,
        outputs=[
            status_output,
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
    )
