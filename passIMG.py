# Author: Lathe Edelmann
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import numpy as np
import os

# Encryption and Decryption Functions
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Steganography Functions
def encode_password_in_image(image_path, password, output_path):
    image = Image.open(image_path)
    image_array = np.array(image)
    key = load_key()
    encrypted_password = encrypt_message(password, key)
    password_bits = ''.join(format(byte, '08b') for byte in encrypted_password)
    height, width, _ = image_array.shape
    idx = 0
    for i in range(height):
        for j in range(width):
            if idx < len(password_bits):
                image_array[i, j, 0] = (image_array[i, j, 0] & ~1) | int(password_bits[idx])
                idx += 1
    encoded_image = Image.fromarray(image_array)
    encoded_image.save(output_path)
    messagebox.showinfo("Success", f"Password encoded and saved to {output_path}")

def decode_password_from_image(image_path):
    image = Image.open(image_path)
    image_array = np.array(image)
    password_bits = []
    height, width, _ = image_array.shape
    for i in range(height):
        for j in range(width):
            password_bits.append(image_array[i, j, 0] & 1)
    password_bytes = bytearray()
    for i in range(0, len(password_bits), 8):
        byte = password_bits[i:i+8]
        byte = ''.join(map(str, byte))
        password_bytes.append(int(byte, 2))
    key = load_key()
    encrypted_password = bytes(password_bytes)
    try:
        password = decrypt_message(encrypted_password, key)
        messagebox.showinfo("Decoded Password", f"Decoded Password: {password}")
    except:
        messagebox.showerror("Error", "Failed to decode password. Invalid key or image.")

# GUI Application
class SteganographyApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganography Password Manager")
        self.geometry("600x400")
        self.create_widgets()

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self)
        self.encode_tab = ttk.Frame(self.tab_control)
        self.decode_tab = ttk.Frame(self.tab_control)
        
        self.tab_control.add(self.encode_tab, text='Encode')
        self.tab_control.add(self.decode_tab, text='Decode')
        self.tab_control.pack(expand=1, fill='both')

        # Encode Section
        encode_label = ttk.Label(self.encode_tab, text="Encode Password into Image")
        encode_label.pack(pady=10)

        self.encode_image_frame = tk.Frame(self.encode_tab, width=150, height=150, borderwidth=2, relief="sunken")
        self.encode_image_frame.pack(pady=5)
        self.encode_image_frame.pack_propagate(False)
        
        self.encode_image_display = tk.Label(self.encode_image_frame)
        self.encode_image_display.pack(expand=True)
        self.encode_image_frame.drop_target_register(DND_FILES)
        self.encode_image_frame.dnd_bind('<<Drop>>', self.drop_image_for_encoding)
        
        self.encode_image_label = tk.Label(self.encode_tab, text="Drag and drop an image or click to select", borderwidth=2, relief="groove", anchor="center")
        self.encode_image_label.pack(pady=5)
        self.encode_image_label.bind("<Button-1>", lambda e: self.select_image_for_encoding())
        
        self.password_entry = ttk.Entry(self.encode_tab, show="*")
        self.password_entry.pack(pady=5)
        
        encode_button = ttk.Button(self.encode_tab, text="Encode Password", command=self.encode_password)
        encode_button.pack(pady=5)

        # Decode Section
        decode_label = ttk.Label(self.decode_tab, text="Decode Password from Image")
        decode_label.pack(pady=10)

        self.decode_image_frame = tk.Frame(self.decode_tab, width=250, height=250, borderwidth=2, relief="sunken")
        self.decode_image_frame.pack(pady=5)
        self.decode_image_frame.pack_propagate(False)
        
        self.decode_image_display = tk.Label(self.decode_image_frame)
        self.decode_image_display.pack(expand=True)
        self.decode_image_frame.drop_target_register(DND_FILES)
        self.decode_image_frame.dnd_bind('<<Drop>>', self.drop_image_for_decoding)
        
        self.decode_image_label = tk.Label(self.decode_tab, text="Drag and drop an image or click to select", borderwidth=2, relief="groove", anchor="center")
        self.decode_image_label.pack(pady=5)
        self.decode_image_label.bind("<Button-1>", lambda e: self.select_image_for_decoding())
        
        decode_button = ttk.Button(self.decode_tab, text="Decode Password", command=self.decode_password)
        decode_button.pack(pady=5)

    def display_image(self, image_path, label):
        image = Image.open(image_path)
        image.thumbnail((250, 250), Image.LANCZOS)
        photo = ImageTk.PhotoImage(image)
        label.config(image=photo)
        label.image = photo

        # Get the size of the image
        width = image.width
        height = image.height

        # Calculate the new size (50% smaller)
        new_width = int(width * 0.5)
        new_height = int(height * 0.5)

        # Set the size of the label to the new size
        label.config(width=new_width, height=new_height)
        label.pack(expand=True, fill='both')

    def select_image_for_encoding(self):
        self.image_path_for_encoding = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if self.image_path_for_encoding:
            self.display_image(self.image_path_for_encoding, self.encode_image_display)
            self.encode_image_label.config(text=f"Selected: {self.image_path_for_encoding}")

    def select_image_for_decoding(self):
        self.image_path_for_decoding = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
        if self.image_path_for_decoding:
            self.display_image(self.image_path_for_decoding, self.decode_image_display)
            self.decode_image_label.config(text=f"Selected: {self.image_path_for_decoding}")

    def drop_image_for_encoding(self, event):
        self.image_path_for_encoding = event.data.strip('{}')
        self.display_image(self.image_path_for_encoding, self.encode_image_display)
        self.encode_image_label.config(text=f"Selected: {self.image_path_for_encoding}")

    def drop_image_for_decoding(self, event):
        self.image_path_for_decoding = event.data.strip('{}')
        self.display_image(self.image_path_for_decoding, self.decode_image_display)
        self.decode_image_label.config(text=f"Selected: {self.image_path_for_decoding}")

    def encode_password(self):
        if not hasattr(self, 'image_path_for_encoding'):
            messagebox.showerror("Error", "Please select an image first.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if output_path:
            encode_password_in_image(self.image_path_for_encoding, password, output_path)

    def decode_password(self):
        if not hasattr(self, 'image_path_for_decoding'):
            messagebox.showerror("Error", "Please select an image first.")
            return

        decode_password_from_image(self.image_path_for_decoding)

if __name__ == "__main__":
    # Generate a key if it doesn't exist (only need to do this once)
    if not os.path.exists("secret.key"):
        generate_key()

    app = SteganographyApp()
    app.mainloop()
