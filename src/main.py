import sys
import os
import requests

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5-coder:3b"

class ShellSage:
    def __init__(self, model=DEFAULT_MODEL):
        self.model = model
        self.SENSITIVE_OPS = ['rm', 'dd', 'mkfs', 'shutdown', 'reboot', '>', 'format', 'sudo']

    def get_system_context(self):
        history_file = os.path.expanduser("~/.bash_history")
        try:
            with open(history_file, "r") as f:
                recent_history = "".join(f.readlines()[-5:])
        except Exception:
            recent_history = "Unavailable"
        
        return {
            "user": os.getlogin(),
            "cwd": os.getcwd(),
            "history": recent_history
        }

    def check_safety(self, command):
        return any(op in command.lower() for op in self.SENSITIVE_OPS)

    def generate_command(self, user_query):
        ctx = self.get_system_context()
        
        prompt = (
            f"SYSTEM CONTEXT:\nUser: {ctx['user']}\nDir: {ctx['cwd']}\nLast Cmds: {ctx['history']}\n\n"
            f"INSTRUCTION: You are a Linux expert. Output ONLY the raw bash command for the user task. "
            f"No markdown, no explanations, no chat.\n"
            f"USER TASK: {user_query}\n"
            f"COMMAND:"
        )

        try:
            payload = {"model": self.model, "prompt": prompt, "stream": False}
            response = requests.post(OLLAMA_URL, json=payload, timeout=10)
            raw_response = response.json().get('response', '').strip()
            clean_cmd = raw_response.split('\n')[0].replace('`', '').strip()
            
            if self.check_safety(clean_cmd):
                print(f"\nWARNING: Potential risk detected: {clean_cmd}")
                print("Review command carefully before execution.\n")
            else:
                print(clean_cmd)
        except Exception:
            print("Notice: ShellSage local AI engine (Ollama) is offline.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        sage = ShellSage()
        sage.generate_command(query)
