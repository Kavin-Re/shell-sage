import sys, requests, os

def get_context():
    history_file = os.path.expanduser("~/.bash_history")
    try:
        with open(history_file, "r") as f:
            history = "".join(f.readlines()[-5:])
    except:
        history = "None"
    return f"User: {os.getlogin()}\nFolder: {os.getcwd()}\nRecent History:\n{history}"

def ask_ai(mode, user_input):
    url = "http://localhost:11434/api/generate"
    context = get_context()
    model = "qwen2.5-coder:3b"
    
    # The "Scary List"
    DANGER_ZONE = ['rm ', 'dd ', 'mkfs', 'shutdown', 'reboot', '>', 'overwrite', 'format']
    
    prompt = (
        f"CONTEXT:\n{context}\n\n"
        f"INSTRUCTION: You are a Linux terminal. Provide the SINGLE most relevant bash command. "
        f"Absolutely NO explanations, NO chat, NO markdown, NO preamble.\n"
        f"USER TASK: {user_input}\n"
        f"COMMAND:"
    )
    
    payload = {"model": model, "prompt": prompt, "stream": False}

    try:
        response = requests.post(url, json=payload)
        full_text = response.json()['response'].strip()
        first_line = full_text.split('\n')[0].replace('`', '').strip()
        
        # --- Safety Check Logic ---
        is_dangerous = any(word in first_line for word in DANGER_ZONE)
        
        if is_dangerous:
            print("\n  DANGER: This command can delete data or system files!")
            print(f" {first_line}\n")
        else:
            print(first_line)
            
    except:
        print("Error: AI engine is offline.")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        ask_ai(sys.argv[1], " ".join(sys.argv[2:]))
