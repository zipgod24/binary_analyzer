import os
import base64
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def open_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    with open(file_path, 'rb') as file:
        content = file.read()
    file_label.config(text=f"Loaded File: {file_path}")
    file_output.delete(1.0, tk.END)
    file_output.insert(tk.END, content)

def save_results():
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if not save_path:
        return
    with open(save_path, 'w') as file:
        file.write(file_output.get(1.0, tk.END))
    messagebox.showinfo("Success", f"Results saved to {save_path}")

def decode_base64():
    try:
        data = file_output.get(1.0, tk.END).strip()
        decoded_data = base64.b64decode(data).decode('utf-8', errors='ignore')
        file_output.delete(1.0, tk.END)
        file_output.insert(tk.END, decoded_data)
    except Exception as e:
        debug_output.insert(tk.END, f"Error decoding Base64: {e}\n")

def encode_base64():
    try:
        data = file_output.get(1.0, tk.END).strip()
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        file_output.delete(1.0, tk.END)
        file_output.insert(tk.END, encoded_data)
    except Exception as e:
        debug_output.insert(tk.END, f"Error encoding Base64: {e}\n")

def sanitize_input(data):
    """Remove any embedded null bytes from the input data."""
    return data.replace('\0', '')

def analyze_with_ai():
    try:
        content = file_output.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "No data to analyze!")
            return
        
        debug_output.insert(tk.END, "Sending data to DeepSeek-R1:1.5B for analysis...\n")
        
        # Sanitize the content to remove embedded null bytes
        sanitized_content = sanitize_input(content)

        # Run DeepSeek-R1:1.5B via Ollama
        result = subprocess.run(
            ["ollama", "run", "deepseek-r1:1.5b", sanitized_content],
            capture_output=True,
            text=True
        )

        # Get the AI's response
        response_text = result.stdout.strip()

        # Display AI response in the debug log instead of replacing file content
        debug_output.insert(tk.END, f"\nAI Response:\n{response_text}\n\n")

    except Exception as e:
        debug_output.insert(tk.END, f"Failed to analyze with AI: {e}\n")

def compare_files():
    file1 = filedialog.askopenfilename(title="Select First File")
    if not file1:
        return
    file2 = filedialog.askopenfilename(title="Select Second File")
    if not file2:
        return
    try:
        with open(file1, 'r') as f1, open(file2, 'r') as f2:
            content1 = set(f1.read().splitlines())
            content2 = set(f2.read().splitlines())
        common = content1.intersection(content2)
        file_output.delete(1.0, tk.END)
        file_output.insert(tk.END, "\n".join(common))
    except Exception as e:
        debug_output.insert(tk.END, f"Error comparing files: {e}\n")

def validate_certificates():
    try:
        data = file_output.get(1.0, tk.END).strip()
        cert = x509.load_pem_x509_certificate(data.encode(), default_backend())
        cert_info = f"Certificate Subject: {cert.subject}\nIssuer: {cert.issuer}\nValid From: {cert.not_valid_before}\nValid To: {cert.not_valid_after}"
        file_output.delete(1.0, tk.END)
        file_output.insert(tk.END, cert_info)
    except Exception as e:
        debug_output.insert(tk.END, f"Error validating certificate: {e}\n")

# GUI Setup
root = tk.Tk()
root.title("Swiss Army File Analyzer")

# File Display
file_label = tk.Label(root, text="No file loaded", fg="blue")
file_label.pack()

file_output = scrolledtext.ScrolledText(root, height=20, width=100, wrap=tk.WORD)
file_output.pack()

# Buttons
button_frame = tk.Frame(root)
button_frame.pack()

tk.Button(button_frame, text="Open File", command=open_file).grid(row=0, column=0, padx=5, pady=5)
tk.Button(button_frame, text="Save Results", command=save_results).grid(row=0, column=1, padx=5, pady=5)
tk.Button(button_frame, text="Decode Base64", command=decode_base64).grid(row=0, column=2, padx=5, pady=5)
tk.Button(button_frame, text="Encode Base64", command=encode_base64).grid(row=0, column=3, padx=5, pady=5)
tk.Button(button_frame, text="Analyze with AI", command=analyze_with_ai).grid(row=1, column=0, padx=5, pady=5)
tk.Button(button_frame, text="Compare Files", command=compare_files).grid(row=1, column=1, padx=5, pady=5)
tk.Button(button_frame, text="Validate Certificates", command=validate_certificates).grid(row=1, column=2, padx=5, pady=5)

# Debugging Section
debug_label = tk.Label(root, text="Debugging Log", fg="red")
debug_label.pack()

debug_output = scrolledtext.ScrolledText(root, height=10, width=100, wrap=tk.WORD, fg="red")
debug_output.pack()

# Footer
footer = tk.Label(root, text="Made by @ZipGod24", fg="green")
footer.pack()

root.mainloop()

