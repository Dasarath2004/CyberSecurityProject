import psutil
import tkinter as tk
from tkinter import messagebox

# Load threat signatures from a file
def load_signatures(filename="threat_signatures.txt"):
    try:
        with open(filename, "r") as file:
            return [line.strip().lower() for line in file if line.strip()]
    except FileNotFoundError:
        return []

# Check running processes for threats
def detect_keyloggers(signatures):
    detected = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            for signature in signatures:
                if signature in name:
                    detected.append((proc.info['pid'], name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return detected

# GUI Functions
def scan():
    output.delete(1.0, tk.END)
    signatures = load_signatures()
    results = detect_keyloggers(signatures)

    if results:
        output.insert(tk.END, "⚠️ Keylogger(s) detected:\n\n")
        for pid, name in results:
            output.insert(tk.END, f"PID: {pid}  |  Process: {name}\n")
    else:
        output.insert(tk.END, "✅ No keyloggers detected.\n")

# GUI Setup
root = tk.Tk()
root.title("Keylogger Detector")
root.geometry("500x300")

frame = tk.Frame(root)
frame.pack(pady=10)

btn = tk.Button(frame, text="Scan for Keyloggers", command=scan, bg="red", fg="white", padx=20, pady=5)
btn.pack()

output = tk.Text(root, wrap=tk.WORD, height=10, width=60)
output.pack(padx=10, pady=10)

root.mainloop()
