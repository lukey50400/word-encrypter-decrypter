import secrets
import random
import tkinter as tk
from tkinter import messagebox

FONT = ("Segoe UI", 11)
BG_COLOR = "#222222"  # Dark gray

def get_shifts(length, key):
    random.seed(int(key, 16))
    return [random.randint(1, 25) for _ in range(length)]

def encrypt_word(word, key):
    shifts = get_shifts(len(word), key)
    encrypted = ""
    for i, char in enumerate(word):
        if char.isalpha():
            shift = shifts[i]
            base = ord('A') if char.isupper() else ord('a')
            offset = (ord(char) - base + shift) % 26
            encrypted += chr(base + offset)
        else:
            encrypted += char
    return encrypted

def decrypt_word(encrypted_word, key):
    shifts = get_shifts(len(encrypted_word), key)
    decrypted = ""
    for i, char in enumerate(encrypted_word):
        if char.isalpha():
            shift = shifts[i]
            base = ord('A') if char.isupper() else ord('a')
            offset = (ord(char) - base - shift) % 26
            decrypted += chr(base + offset)
        else:
            decrypted += char
    return decrypted

def handle_encrypt():
    word = entry_word.get()
    if not word:
        messagebox.showwarning("Input Error", "Please enter a word to encrypt.")
        return
    key = secrets.token_hex(16)
    encrypted = encrypt_word(word, key)
    entry_encrypted.delete(0, tk.END)
    entry_encrypted.insert(0, encrypted)
    entry_key.delete(0, tk.END)
    entry_key.insert(0, key)

def handle_decrypt():
    encrypted = entry_encrypted.get()
    key = entry_key.get()
    if not encrypted or not key:
        messagebox.showwarning("Input Error", "Please enter both the encrypted word and key.")
        return
    try:
        decrypted = decrypt_word(encrypted, key)
        entry_decrypted.delete(0, tk.END)
        entry_decrypted.insert(0, decrypted)
    except Exception:
        messagebox.showerror("Error", "Invalid key or encrypted word.")

root = tk.Tk()
root.title("Word Encrypter")
root.configure(bg=BG_COLOR)

# Set background for all widgets
label_opts = {"font": FONT, "bg": BG_COLOR, "fg": "white"}
entry_opts = {"font": FONT, "bg": "#333333", "fg": "white", "insertbackground": "white"}
button_opts = {"font": FONT, "bg": "#444444", "fg": "white", "activebackground": "#555555", "activeforeground": "white"}

tk.Label(root, text="Word to Encrypt:", **label_opts).grid(row=0, column=0, sticky="e", padx=5, pady=5)
entry_word = tk.Entry(root, width=30, **entry_opts)
entry_word.grid(row=0, column=1, padx=5, pady=5)

btn_encrypt = tk.Button(root, text="Encrypt", command=handle_encrypt, **button_opts)
btn_encrypt.grid(row=0, column=2, padx=5, pady=5)

tk.Label(root, text="Encrypted Word:", **label_opts).grid(row=1, column=0, sticky="e", padx=5, pady=5)
entry_encrypted = tk.Entry(root, width=30, **entry_opts)
entry_encrypted.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Key:", **label_opts).grid(row=2, column=0, sticky="e", padx=5, pady=5)
entry_key = tk.Entry(root, width=30, **entry_opts)
entry_key.grid(row=2, column=1, padx=5, pady=5)

btn_decrypt = tk.Button(root, text="Decrypt", command=handle_decrypt, **button_opts)
btn_decrypt.grid(row=2, column=2, padx=5, pady=5)

tk.Label(root, text="Decrypted Word:", **label_opts).grid(row=3, column=0, sticky="e", padx=5, pady=5)
entry_decrypted = tk.Entry(root, width=30, **entry_opts)
entry_decrypted.grid(row=3, column=1, padx=5, pady=5)

root.mainloop()