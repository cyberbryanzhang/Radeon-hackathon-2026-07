import ipaddress
import json
import time
from typing import Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL_ID = "meta-llama/Llama-3.1-8B-Instruct"

ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def validate_analysis(data: Any) -> list[str]:
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["Top-level response must be a JSON object."]

    required_fields = {
        "severity",
        "confidence",
        "attack_type",
        "summary",
        "mitre_attack",
        "iocs",
        "recommendations",
    }

    missing = required_fields - data.keys()
    if missing:
        errors.append(f"Missing fields: {sorted(missing)}")

    if data.get("severity") not in ALLOWED_SEVERITIES:
        errors.append("severity must be Low, Medium, High, or Critical.")

    confidence = data.get("confidence")
    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
        errors.append("confidence must be an integer from 0 to 100.")

    if not isinstance(data.get("attack_type"), str):
        errors.append("attack_type must be a string.")

    if not isinstance(data.get("summary"), str):
        errors.append("summary must be a string.")

    mitre_items = data.get("mitre_attack")
    if not isinstance(mitre_items, list):
        errors.append("mitre_attack must be an array.")
    else:
        for index, item in enumerate(mitre_items):
            if not isinstance(item, dict):
                errors.append(f"mitre_attack[{index}] must be an object.")
                continue

            technique_id = item.get("technique_id")
            technique_name = item.get("technique_name")

            if not isinstance(technique_id, str) or not technique_id.startswith("T"):
                errors.append(
                    f"mitre_attack[{index}].technique_id must start with T."
                )

            if not isinstance(technique_name, str) or not technique_name.strip():
                errors.append(
                    f"mitre_attack[{index}].technique_name must be non-empty."
                )

    iocs = data.get("iocs")
    if not isinstance(iocs, list):
        errors.append("iocs must be an array.")
    else:
        for index, item in enumerate(iocs):
            if not isinstance(item, dict):
                errors.append(f"iocs[{index}] must be an object.")
                continue

            ioc_type = item.get("type")
            value = item.get("value")

            if ioc_type != "IP":
                errors.append(f"iocs[{index}].type currently supports only IP.")

            if not isinstance(value, str):
                errors.append(f"iocs[{index}].value must be a string.")
                continue

            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(
                    f"iocs[{index}].value is not a concrete valid IP address."
                )

    recommendations = data.get("recommendations")
    if not isinstance(recommendations, list) or not all(
        isinstance(item, str) for item in recommendations
    ):
        errors.append("recommendations must be an array of strings.")

    return errors


def main() -> None:
    if not torch.cuda.is_available():
        raise RuntimeError("AMD GPU was not detected by PyTorch.")

    print(f"Loading model: {MODEL_ID}")
    print(f"GPU: {torch.cuda.get_device_name(0)}")
    print(f"PyTorch: {torch.__version__}")
    print(f"HIP: {torch.version.hip}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        dtype=torch.float16,
        device_map="auto",
    )
    model.eval()

    messages = [
        {
            "role": "system",
            "content": """
You are SOCPilot, an expert cybersecurity SOC analyst.

Return ONLY one valid JSON object using exactly this schema:

{
  "severity": "Low | Medium | High | Critical",
  "confidence": 0,
  "attack_type": "",
  "summary": "",
  "mitre_attack": [
    {
      "technique_id": "",
      "technique_name": ""
    }
  ],
  "iocs": [
    {
      "type": "IP",
      "value": ""
    }
  ],
  "recommendations": []
}

Rules:
- Do not output Markdown or code fences.
- Do not output commentary outside the JSON.
- Confidence must be an integer from 0 to 100.
- Only include IOC values explicitly present in the event.
- Never use placeholders such as "attacker IP" or "unknown IP."
- If no concrete IOC is provided, return "iocs": [].
- Do not invent evidence.
""".strip(),
        },
        {
            "role": "user",
            "content": """
A server recorded 250 failed SSH login attempts from 203.0.113.45
within five minutes, followed by one successful login from the same IP.

Analyze the event.
""".strip(),
        },
    ]

    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    torch.cuda.reset_peak_memory_stats()
    torch.cuda.synchronize()
    start = time.perf_counter()

    with torch.inference_mode():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=450,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )

    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start

    generated_ids = output_ids[0, inputs["input_ids"].shape[1]:]
    answer = tokenizer.decode(
        generated_ids,
        skip_special_tokens=True,
    ).strip()

    print("\n--- Raw model output ---")
    print(answer)

    try:
        parsed = json.loads(answer)
    except json.JSONDecodeError as error:
        print("\nJSON syntax validation: FAILED")
        print(f"Reason: {error}")
    else:
        print("\nJSON syntax validation: PASSED")

        validation_errors = validate_analysis(parsed)

        if validation_errors:
            print("Schema validation: FAILED")
            for error in validation_errors:
                print(f"- {error}")
        else:
            print("Schema validation: PASSED")

        print("\n--- Parsed result ---")
        print(json.dumps(parsed, indent=2))

    print("\n--- Performance ---")
    print(f"Generation time: {elapsed:.2f} seconds")
    print(f"Model device: {next(model.parameters()).device}")
    print(
        "Peak GPU memory:",
        f"{torch.cuda.max_memory_allocated() / 1024**3:.2f} GiB",
    )


if __name__ == "__main__":
    main()
