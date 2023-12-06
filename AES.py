from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog


def choose_file():
    global file_path
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        # Perform your operation with the selected file
        result_label.config(text=f"Selected File: {file_path}")
        # Add your custom logic here using the 'file_path'


# Create the main window
root = tk.Tk()
root.title("File Selection Example")

# Create a button to trigger the file dialog
button = tk.Button(root, text="Choose File", command=choose_file)
button.pack(pady=20)

# Create a label to display the selected file path
result_label = tk.Label(root, text="Selected File: ")
result_label.pack()


#
# def open_file_dialog():
#     global selected_file_path
#     selected_file_path = filedialog.askopenfilename(title="Select a File")
#     if selected_file_path:
#         label.config(text=f"Selected File: {selected_file_path}")
#
#
# # Create the main window
# root = tk.Tk()
# root.title("File Selection Demo")
#
# # Create a button to trigger the file dialog
# button = tk.Button(root, text="Select File", command=open_file_dialog)
# button.pack(pady=20)
#
# # Create a label to display the selected file path
# label = tk.Label(root, text="Selected File: ")
# label.pack()


def on_button_click():
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

    # Encryption
    with open(file_path, "rb") as f:
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


root.title("Button Template")

# Create a button with a callback to on_button_click
button1 = tk.Button(root, text="Encrypt", command=on_button_click)
button1.pack(side= "left",pady=20, padx=20)


#Decryot
def on_button_click():
    password = input("Enter your password")
    with open("salt.txt", 'rb') as f:
        salt = f.read()

    dec_key = PBKDF2(password, salt, dkLen=32)

    dec_iv = input("Enter your initialization vector (16 characters): ")
    try:
        with open('Encrypted.txt', 'rb') as f:
            original_iv = f.read(16)
            decrypt_data = f.read()

        if dec_iv == "":
            cipher = AES.new(dec_key, AES.MODE_CBC)
        else:
            cipher = AES.new(dec_key, AES.MODE_CBC, iv=dec_iv.encode())

        original = unpad(cipher.decrypt(decrypt_data), AES.block_size)
        with open('Decrypted.txt', 'wb') as f:
            f.write(original)
    except Exception as e:
        print("Decryption error:", e)
        return None




root.title("Button Template")

# Create a button with a callback to on_button_click
button2 = tk.Button(root, text="Decrypt", command=on_button_click)
button2.pack(side = "right",pady=20, padx=10)

root.mainloop()
