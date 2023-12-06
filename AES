from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog


def open_file_dialog():
    global selected_file_path
    selected_file_path = filedialog.askopenfilename(title="Select a File")
    if selected_file_path:
        label.config(text=f"Selected File: {selected_file_path}")


# Create the main window
root = tk.Tk()
root.title("File Selection Demo")

# Create a button to trigger the file dialog
button = tk.Button(root, text="Select File", command=open_file_dialog)
button.pack(pady=20)

# Create a label to display the selected file path
label = tk.Label(root, text="Selected File: ")
label.pack()

# Start the main loop
root.mainloop()

# Start the main loop
root.mainloop()
###############################################################################################

# generate a simple key
simple_key = get_random_bytes(32)
with open("salt.txt", 'wb') as f:
    f.write(simple_key)

with open("salt.txt", 'rb') as f:
    salt = f.read()

# same salt same password result in the same KEY
password = input("Please enter your password: ")

# key used to encrypt a message
key = PBKDF2(password, salt, dkLen=32)
# print(key)

#Encryption
with open(selected_file_path, "rb") as f:
    message = f.read()

iv = input("Enter your initialization vector (16 characters are required: ")


cipher = AES.new(key, AES.MODE_CBC)

if iv == "":
    cipher = AES.new(key, AES.MODE_CBC)
elif len(iv) == 16:
    print(len(iv))
    cipher = AES.new(key, AES.MODE_CBC, iv.encode())
else:
    print("Error in initialization vector")

ciphered_data = cipher.encrypt(pad(message, AES.block_size))

if iv == "":
        with open('Encrypted.txt', 'wb') as f:
            f.write(cipher.iv)
            f.write(ciphered_data)
else:
    with open('Encrypted.txt', 'wb') as f:
            f.write(iv.encode())
            f.write(ciphered_data)

#Decryption
password = input("Enter your password")
dec_key = PBKDF2(password, salt, dkLen=32)

dec_iv = input("Enter your initialization vector (16 characters): ")

if dec_iv == "":
    with open('Encrypted.txt', 'rb') as f:
        dec_iv = f.read(16)
        decrypt_data = f.read()
else:
    with open('Encrypted.txt', 'rb') as f:
        f.read(16)
        decrypt_data = f.read()

cipher = AES.new(dec_key, AES.MODE_CBC, iv=dec_iv.encode())
original = unpad(cipher.decrypt(decrypt_data), AES.block_size)

with open('Decrypted.txt', 'wb') as f:
    f.write(original)
