from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_NAME = "Qwen/Qwen3.5-0.8B"

print("Loading SnapSecure AI model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)

prompt = """You are SnapSecure AI, a cybersecurity assistant.
Explain in simple language why users should be careful when opening suspicious URLs."""

inputs = tokenizer(prompt, return_tensors="pt")

outputs = model.generate(
    **inputs,
    max_new_tokens=150,
    do_sample=False
)

response = tokenizer.decode(
    outputs[0],
    skip_special_tokens=True
)

print("\n--- SnapSecure AI Response ---")
print(response)