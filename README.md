# ShellSage: Context-Aware Offline Terminal Intelligence

ShellSage is a privacy-first, CLI-native assistant that transforms natural language intent into executable bash commands. By utilizing local LLM inference, it provides an intelligent shell interface while ensuring 100% data residency on the host machine.

---

## Technical Features
*   Localized Inference: Operates via local Ollama server; zero external API dependencies.
*   Contextual Analysis: Injects working directory, user identity, and terminal history into the inference pipeline for path-accurate suggestions.
*   Security Logic: Integrated sensitive-operation filter identifies potentially destructive commands (e.g., rm, dd, mkfs) and triggers a warning.
*   Deterministic Output: Optimized to return raw shell commands without conversational metadata.

---

## Technical Specifications
*   Inference Backend: Ollama
*   LLM Architecture: Qwen 2.5 Coder 3B (Optimized for Ryzen 3 / 8GB RAM)
*   Language: Python 3.12+ (Class-based modular architecture)
*   Shell Integration: Bash command_not_found_handle

---

## Deployment and Setup

1. Configure Local Inference:
   ```bash
   curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh
   ollama pull qwen2.5-coder:3b
   ```

2. Environment Integration:
   Add the following to the ~/.bashrc configuration:
   ```bash
   # ShellSage Terminal Hook
   command_not_found_handle() {
       python3 ~/shell-sage/src/main.py "$@"
   }
   # Manual Invocation
   alias sage='python3 ~/shell-sage/src/main.py'
   ```

---

## Operational Usage
Input natural language when a command is unrecognized by the shell:
k@DA05:~$ find all log files larger than 50MB

Manual query via alias:
k@DA05:~$ sage how to monitor system temperatures

---

## Safety Disclaimer
The system includes a sensitive operations monitor. If a generated command possesses the potential to modify system partitions or delete critical data, ShellSage will issue a high-visibility warning. Always perform a manual review of AI-generated output.

---
**Author: Kavin-Re**
*Embedded Systems Engineer | DevOps Tooling*
