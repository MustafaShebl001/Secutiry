from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog,ttk
from tkinter import simpledialog, filedialog, messagebox




# Constants
SALT_FILE = "salt.txt"
file_path = ""
IV = b'0000000000000000'
ENCRYPTED_FILE = "Encrypted.txt"
DECRYPTED_FILE = "Decrypted.txt"
AES_BLOCK_SIZE = AES.block_size
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

#Normal functions
def generate_salt_file():
    simple_key = get_random_bytes(32)
    with open(SALT_FILE, 'wb') as f:
        f.write(simple_key)


def derive_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=32)


def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        message = f.read()

    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphered_data = cipher.encrypt(pad(message, AES_BLOCK_SIZE))

    with open(ENCRYPTED_FILE, 'wb') as f:
        f.write(IV)
        f.write(ciphered_data)


def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            original_iv = f.read(16)
            decrypt_data = f.read()
            cipher = AES.new(key, AES.MODE_CBC, IV)
            original = unpad(cipher.decrypt(decrypt_data), AES_BLOCK_SIZE)
            with open(DECRYPTED_FILE, 'wb') as f:
                f.write(original)

            messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        tk.messagebox.showerror(title="Decryption Error" ,message="Incorrect password, please try again!" )


def choose_file():
    global file_path
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        result_label.config(text=f"Selected File: {file_path}")
    else:
        tk.messagebox.showerror(title="file path",message="Please choose a file to do operations on")

#Generate RSA key pairs and save them to files
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key)
        
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key)

def verify_and_decrypt_file(file_path, signature_file, key):
    try:
        # Load RSA public key
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = RSA.import_key(f.read())

        # Verify the signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
        with open(file_path, 'rb') as f:
            data_to_verify = f.read()
        public_key.verify(data_to_verify, signature)

        # Decrypt the file
        decrypt_file(file_path, key)

        messagebox.showinfo("Success", "Verification and Decryption completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification and Decryption error: {e}")

#On_click functions



def on_encrypt_button_click():
    # force the user to specify the file
    if file_path == "":
        tk.messagebox.showinfo(title="file path",message="Please choose a file to do operations on")
        choose_file()

    generate_salt_file()

    # GUI prompts for password and initialization vector
    # taking password form user and checking its validity
    while True:
        password = simpledialog.askstring("Password", "Enter your encryption password:", show="*")
        if password == "":
            tk.messagebox.showerror(title="Empty password", message="Please enter a Password")
        else:
            break

    # taking iv from user and checking its validity
    # while True:
    #     iv = simpledialog.askstring("Initialization vector", "Enter your initialization vector (16 characters):" , show="*")
    #     if iv == "" or len(iv) != 16:
    #         tk.messagebox.showerror(title="Invalid IV", message="Please enter a valid IV as described")
    #     else:
    #         break

    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_key_from_password(password, salt)

    try:
        encrypt_file(file_path, key)
        messagebox.showinfo("Success", "Encryption completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption error: {e}")

def on_decrypt_button_click():
    # GUI prompts for password and initialization vector
    password = simpledialog.askstring("Input", "Enter your decryption password:", show="*")
    # dec_iv = simpledialog.askstring("Input", "Enter your initialization vector (16 characters):", show="*")
    # if not password or not dec_iv or len(dec_iv) != 16:
    #     messagebox.showerror("Error", "Invalid password or initialization vector.")
    #     return

    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_key_from_password(password, salt)

    try:
        decrypt_file(ENCRYPTED_FILE, key)
        # messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        messagebox.showinfo("Error", f"Decryption error: {e}")

#
# def on_sign_button_click():
#     # GUI prompt for private key path
#     private_key_path = filedialog.askopenfilename(title="Select Private Key File")
#
#     if not private_key_path:
#         messagebox.showerror("Error", "Invalid private key path.")
#         return
#
#     with open(private_key_path, 'rb') as f:
#         private_key = f.read()
#
#     try:
#         sign_file(file_path, private_key)
#         messagebox.showinfo("Success", "File signed successfully.")
#     except Exception as e:
#         messagebox.showerror("Error", f"Signing error: {e}")
#
#
# def on_verify_button_click():
#     # GUI prompt for public key path
#     public_key_path = filedialog.askopenfilename(title="Select Public Key File")
#
#     if not public_key_path:
#         messagebox.showerror("Error", "Invalid public key path.")
#         return
#
#     with open(public_key_path, 'rb') as f:
#         public_key = f.read()
#
#     try:
#         verify_signature(file_path, public_key)
#         messagebox.showinfo("Success", "Signature verified successfully.")
#     except Exception as e:
#         messagebox.showerror("Error", f"Verification error: {e}")



def on_sign_and_encrypt_button_click():
    # Prompt for password
    password = simpledialog.askstring("Password", "Enter your encryption password:", show="*")
    if not password:
        messagebox.showerror("Empty password", "Please enter a Password")
        return

    # Load RSA private key
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Prompt for user input (file to sign and encrypt)
    file_to_sign_and_encrypt = filedialog.askopenfilename(title="Select a File to Sign and Encrypt")
    if not file_to_sign_and_encrypt:
        messagebox.showerror("File not selected", "Please choose a file to sign and encrypt.")
        return

    # Generate salt and derive AES key from password
    generate_salt_file()
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    key = derive_key_from_password(password, salt)

    # Sign the file
    with open(file_to_sign_and_encrypt, 'rb') as f:
        data_to_sign = f.read()
    signature = private_key.sign(data_to_sign, '')

    # Encrypt the file
    encrypt_file(file_to_sign_and_encrypt, key)

    # Save the signature to a file
    signature_file = file_to_sign_and_encrypt + ".sig"
    with open(signature_file, 'wb') as f:
        f.write(signature)

    messagebox.showinfo("Success", "Sign and Encrypt completed successfully.")


def on_verify_and_decrypt_button_click():
    # Prompt for password
    password = simpledialog.askstring("Password", "Enter your decryption password:", show="*")
    if not password:
        messagebox.showerror("Empty password", "Please enter a Password")
        return

    # Generate salt and derive AES key from password
    generate_salt_file()
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    key = derive_key_from_password(password, salt)

    # Prompt for user input (file to verify and decrypt)
    file_to_verify_and_decrypt = filedialog.askopenfilename(title="Select a File to Verify and Decrypt")
    if not file_to_verify_and_decrypt:
        messagebox.showerror("File not selected", "Please choose a file to verify and decrypt.")
        return

    # Prompt for user input (signature file)
    signature_file = filedialog.askopenfilename(title="Select Signature File")
    if not signature_file:
        messagebox.showerror("Signature file not selected", "Please choose a signature file.")
        return

    # Verify and decrypt the file
    verify_and_decrypt_file(file_to_verify_and_decrypt, signature_file, key)



# GUI
root = tk.Tk()
root.title("File Encryption/Decryption")
frm = ttk.Frame(root, padding=10)
frm.grid()

# File Selection Section
button_select_file = tk.Button(frm, text="Choose File", command=choose_file)
button_select_file.grid(row=0, column=0, pady=20)

result_label = tk.Label(frm, text="Selected File: ")
result_label.grid(row=1, column=0)

# Encryption Section
button_encrypt = tk.Button(frm, text="Encrypt", command=on_encrypt_button_click)
button_encrypt.grid(row=2, column=0, pady=20, padx=20)

# Decryption Section
button_decrypt = tk.Button(frm, text="Decrypt", command=on_decrypt_button_click)
button_decrypt.grid(row=2, column=1, pady=20, padx=10)

# Digital Signature Section
# button_sign = tk.Button(frm, text="Sign", command=on_sign_button_click)
# button_sign.grid(row=3, column=0, pady=20)
#
# button_verify = tk.Button(frm, text="Verify Signature", command=on_verify_button_click)
# button_verify.grid(row=3, column=1, pady=20)

button_sign_and_encrypt = tk.Button(frm, text="Sign and Encrypt", command=on_sign_and_encrypt_button_click)
button_sign_and_encrypt.grid(row=4, column=0, columnspan=2, pady=20)
# Verify and Decrypt Section
button_verify_and_decrypt = tk.Button(frm, text="Verify and Decrypt", command=on_verify_and_decrypt_button_click)
button_verify_and_decrypt.grid(row=5, column=0, columnspan=2, pady=20)

root.mainloop()
