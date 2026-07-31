import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL_ID = "meta-llama/Llama-3.1-8B-Instruct"


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
        torch_dtype=torch.float16,
        device_map="auto",
    )
    model.eval()

    messages = [
        {
            "role": "system",
            "content": (
                "You are SOCPilot, a concise cybersecurity analysis assistant. "
                "Do not invent evidence. Clearly distinguish observations from conclusions."
            ),
        },
        {
            "role": "user",
            "content": (
                "A server recorded 250 failed SSH login attempts from one IP "
                "within five minutes, followed by one successful login. "
                "Give a short initial assessment."
            ),
        },
    ]

    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    torch.cuda.synchronize()
    start = time.perf_counter()

    with torch.inference_mode():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=220,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )

    torch.cuda.synchronize()
    elapsed = time.perf_counter() - start

    generated_ids = output_ids[0, inputs["input_ids"].shape[1]:]
    answer = tokenizer.decode(generated_ids, skip_special_tokens=True)

    print("\n--- SOCPilot response ---")
    print(answer.strip())
    print("\n--- Performance ---")
    print(f"Generation time: {elapsed:.2f} seconds")
    print(f"Model device: {next(model.parameters()).device}")
    print(
        "Peak GPU memory:",
        f"{torch.cuda.max_memory_allocated() / 1024**3:.2f} GiB",
    )


if __name__ == "__main__":
    main()
