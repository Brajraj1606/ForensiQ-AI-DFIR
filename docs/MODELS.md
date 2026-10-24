# ForensiQ AI: Model Provenance & Local Inference Guide

ForensiQ AI is designed to run entirely locally without paid cloud APIs. It connects to **Ollama** (`http://localhost:11434`) for local, open-weight language model inference.

---

## 1. Supported Open-Weight Models

| Model | Parameters | Quantization | Size on Disk | Min RAM / VRAM | Provenance & Creator | License | Recommended Use Case |
|---|---|---|---|---|---|---|---|
| **Llama 3.2** | 3.2B | Q4_K_M | ~2.0 GB | 4 GB RAM / 2 GB VRAM | Meta AI | Llama 3.2 Community License | **Default recommendation**: Fast, highly capable on standard laptops |
| **Mistral 7B** | 7.3B | Q4_0 | ~4.1 GB | 8 GB RAM / 6 GB VRAM | Mistral AI | Apache 2.0 | Complex log correlation and threat actor attribution |
| **DeepSeek R1** | 7B / 14B | Q4_K_M | ~4.7 GB | 8 GB RAM / 8 GB VRAM | DeepSeek AI | MIT License | Deep step-by-step reasoning and forensic hypothesis testing |
| **Phi-3.5 Mini** | 3.8B | Q4_K_M | ~2.2 GB | 4 GB RAM / 2 GB VRAM | Microsoft | MIT License | Low-resource / edge forensic field kits |

---

## 2. Ollama Installation & Setup

### Step 1: Install Ollama
- **Linux:** `curl -fsSL https://ollama.com/install.sh | sh`
- **macOS:** Download from [ollama.com/download](https://ollama.com/download)
- **Windows:** Download executable installer from [ollama.com/download](https://ollama.com/download)

### Step 2: Download Recommended Model
```bash
# Pull Llama 3.2 (Default)
ollama pull llama3.2

# Run and verify
ollama run llama3.2 "Confirm model is ready for DFIR assistance"
```

### Step 3: Connect ForensiQ AI
ForensiQ AI automatically checks `http://localhost:11434/api/tags`.
- If Ollama is running, the green status indicator lights up.
- If Ollama is offline or not installed, **ForensiQ AI seamlessly activates its deterministic rule engine with zero disruption.**

---

## 3. Third-Party Library & Model License Verification

Before claiming an open-source distribution, all library and model licenses have been verified:
- **Core Forensic Engine:** Apache 2.0
- **Python Standard Library (hashlib, sqlite3, unittest, json, re):** Python Software Foundation (PSF) License (Permissive)
- **Pandas:** BSD 3-Clause (Permissive)
- **Streamlit:** Apache 2.0 (Permissive)
- **Ollama Client:** MIT License (Permissive)
- **ReportLab:** BSD License (Permissive)
- **Llama 3.2 Model:** Meta Llama 3.2 Community License (Free for research & commercial use under 700M active monthly users)
