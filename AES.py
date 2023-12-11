from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog,ttk
from tkinter import simpledialog, filedialog, messagebox
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA



# Constants
SALT_FILE = "salt.txt"
SIGNATURE_FILE = "signature.pem"
file_path = ""
IV = b'0000000000000000'
ENCRYPTED_FILE = "Encrypted.txt"
DECRYPTED_FILE = "Decrypted.txt"
AES_BLOCK_SIZE = AES.block_size


def generate_salt_file():
    simple_key = get_random_bytes(32)
    with open(SALT_FILE, 'wb') as f:
        f.write(simple_key)


def generate_Signature_file(signature):
        with open(SIGNATURE_FILE, 'wb') as f:
            f.write(signature)

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

def sign_file(file_path,private_key):

        with open(file_path, "rb") as f:
            message = f.read() 

        hash_value = SHA256.new(message)
        key = RSA.import_key(private_key)

        # Get the signature
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(hash_value)
        generate_Signature_file(signature)


def verify_signature(file_path, public_key):
    
        with open(file_path, "rb") as f:
            message = f.read() 

        # Open the recieved signature file:
        with open('signature.pem', "rb") as f:
            signature = f.read() 
        key = RSA.importKey(public_key)

        generated_hash_value = SHA256.new(message)
        # Check if the generated and recieved values are the same
        PKCS1_v1_5.new(key).verify(generated_hash_value,signature)
        
        

def on_sign_button_click():
    # GUI prompt for private key path
    global  private_key_path 
    private_key_path = filedialog.askopenfilename(title="Select Private Key File")

    if not private_key_path:
        messagebox.showerror("Error", "Invalid private key path.")
        return

    with open(private_key_path, 'rb') as f:
        private_key = f.read()

    try:
        sign_file(file_path, private_key)
        messagebox.showinfo("Success", "File signed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Signing error: {e}")


def on_verify_button_click():
    # GUI prompt for public key path
    public_key_path = filedialog.askopenfilename(title="Select Public Key File")

    if not public_key_path:
        messagebox.showerror("Error", "Invalid public key path.")
        return

    with open(public_key_path, 'rb') as f:
        public_key = f.read()

    try:
        verify_signature(file_path, public_key)
        messagebox.showinfo("Success", "Signature verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")


def on_sign_and_encrypt_button_click():
    # Include the logic for signing and encrypting here
    pass

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

root.mainloop()
