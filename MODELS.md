# Supported AI Models

This project uses [Ollama](https://ollama.com) to run AI models locally on the Raspberry Pi. Ollama is the engine — the model is what runs inside it. You can change the model at any time without changing any code.

---

## How it works

- **Ollama** is the software installed on your Pi that manages and runs AI models. Think of it like a media player.
- **The model** (e.g., `qwen2.5:3b`) is the actual AI brain that does the categorization and generates next steps. Think of it like the video file you play in that media player.
- You always need Ollama. The model running inside it is what you can swap.

---

## Supported Models for Raspberry Pi 4

All models below run entirely on the Pi's CPU — no GPU required.

| Model | Download Size | RAM Usage | Speed (Pi 4) | Best For |
|---|---|---|---|---|
| `qwen2.5:3b` | ~1.9GB | ~2GB | 5–8 tok/sec | **Recommended** — best balance of speed and structured JSON output quality |
| `gemma2:2b` | ~1.6GB | ~1.8GB | 8–12 tok/sec | Fastest option — good if you want shorter run times and can accept slightly less accurate categorization |
| `phi3.5:mini` | ~2.2GB | ~2.5GB | 4–6 tok/sec | Strong reasoning for its size — good alternative to qwen2.5:3b |
| `llama3.2:3b` | ~2.0GB | ~2.2GB | 4–7 tok/sec | Good general-purpose model — slightly less optimized for structured output than qwen2.5 |

---

## Larger Models (for Apple Silicon Mac or Pi 5)

If you run this project on a Mac or a more powerful device, larger models give better categorization quality.

| Model | Download Size | RAM Usage | Best For |
|---|---|---|---|
| `qwen2.5:7b` | ~4.7GB | ~5GB | Noticeably better than 3b; good on machines with 8GB+ RAM |
| `llama3.1:8b` | ~4.7GB | ~5GB | Strong general-purpose model; good on Apple Silicon |
| `qwen2.5:14b` | ~9GB | ~10GB | High quality; requires 16GB+ RAM |

---

## How to Change the Model

**1. Download the new model** (one-time, on the Pi):
```bash
ollama pull <model-name>
```
For example:
```bash
ollama pull gemma2:2b
```

**2. Update `config.yaml`:**
```yaml
ollama:
  model: gemma2:2b
```

**3. Restart the app:**
```bash
sudo systemctl restart security-automation
```

The change takes effect on the next pipeline run. The old model stays downloaded on your Pi — you can switch back at any time by updating `config.yaml` again. To free up space, remove a model you no longer use:
```bash
ollama rm qwen2.5:3b
```

---

## How to Check What Models Are Downloaded

```bash
ollama list
```
