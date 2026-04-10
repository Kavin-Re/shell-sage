# 🤖 AI-Powered Offline Linux Terminal

A local, context-aware AI assistant integrated directly into the Linux Mint terminal. This tool intercepts unknown commands and provides natural-language assistance using a local LLM.

## 🌟 Features
* **100% Offline:** Runs entirely on your hardware using Ollama; no data ever leaves your machine.
* **Context-Aware:** The AI knows your current directory, your username, and your recent command history to provide smarter answers.
* **Two Ways to Use:**
    1.  **Direct Hijack:** Type a sentence (e.g., `make a folder`) and the terminal intercepts the error to give you the code.
    2.  **Explicit Ask:** Use the `askme` keyword for direct questions (e.g., `askme how to check RAM usage`).
* **Safety Guardrails:** Automatically detects dangerous commands (like `rm` or `mkfs`) and issues a warning before showing the code.
* **Clean Output:** Strips away AI "chatter" and markdown, providing only the raw command you need.

## 🛠️ Technical Stack
* **Engine:** Ollama
* **Model (Brain):** Qwen 2.5 Coder 3B (Optimized for Ryzen 3 / 8GB RAM)
* **Messenger:** Python 3 (using `requests` and `os` libraries)
* **Shell Integration:** Bash (`.bashrc` hook)

## 📥 Installation
1. **Install Ollama:** `curl -fsSL https://ollama.com/install.sh | sh`
2. **Download the Brain:** `ollama pull qwen2.5-coder:3b`
3. **Setup Messenger:** Save `asklinux.py` to your home directory.
4. **Link to Terminal:** Add the `command_not_found_handle` and `askme` function to your `~/.bashrc`.

## 🚀 How to Use
Simply type your request in plain English if the command is unknown:
`k@123:~$ generate a list of all images in my home folder`

Or use the trigger:
`k@123:~$ askme how to update my system`

## ⚠️ Safety Disclaimer
This tool includes a `DANGER_ZONE` filter. If a suggested command has the potential to delete data or modify system partitions, a warning message will be displayed. Always review commands before execution.
