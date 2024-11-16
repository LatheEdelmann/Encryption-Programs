# Author Lathe Edelmann
import tkinter as tk
import base64
import hashlib
import os
from tkinter import filedialog, messagebox

def encrypt(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()
    encoded_data = base64.b64encode(data)
    encrypted_data = encoded_data + hashlib.sha256(password.encode()).digest()
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt(file_path, password):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    hash = encrypted_data[-32:]
    encoded_data = encrypted_data[:-32]
    if hashlib.sha256(password.encode()).digest() == hash:
        decoded_data = base64.b64decode(encoded_data)
        with open(file_path, 'wb') as f:
            f.write(decoded_data)
        messagebox.showinfo("Decryption", "File decrypted successfully")
        return True
    else:
        messagebox.showerror("Decryption", "Incorrect password")
        return False

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    encrypt(file_path, password)
    messagebox.showinfo("Encryption", "File encrypted successfully")

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    password = password_entry.get()
    attempts = 3
    while attempts > 0:
        if decrypt(file_path, password):
            break
        else:
            attempts -= 1
            if attempts == 0:
                messagebox.showerror("Decryption", "Too many incorrect password attempts")
                break
            password = tk.simpledialog.askstring("Password", "Incorrect password, enter again:", show='*')


root = tk.Tk()
root.title("Encrypt/Decrypt File")
root.geometry("300x100")

password_label = tk.Label(text="Password:")
password_label.pack()

password_entry = tk.Entry(show="*")
password_entry.pack()

encrypt_button = tk.Button(text="Encrypt File", command=encrypt_file)
encrypt_button.pack()

decrypt_button = tk.Button(text="Decrypt File", command=decrypt_file)
decrypt_button.pack()

root.mainloop()
