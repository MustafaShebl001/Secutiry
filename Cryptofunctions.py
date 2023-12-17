from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from Crypto.Cipher import DES3
from hashlib import  md5
from tkinter import filedialog,ttk
from tkinter import simpledialog, filedialog, messagebox


# Constants
SALT_FILE = "salt.txt"
SALT_des3_FILE = "desSalt.txt"
nonce = b'0'
SIGNATURE_FILE = "signature.pem"
IV = b'0000000000000000'
ENCRYPTED_AES_FILE = "EncryptedAES.txt"
DECRYPTED_AES_FILE = "DecryptedAES.txt"
ENCRYPTED_DES_FILE = "EncryptedDES.txt"
DECRYPTED_DES_FILE = "DecryptedDES.txt"
AES_BLOCK_SIZE = AES.block_size
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

#Normal functions
def generate_salt_file():
    simple_key = get_random_bytes(32)
    with open(SALT_FILE, 'wb') as f:
        f.write(simple_key)

def generate_des_salt_file():
    simple_key = get_random_bytes(8)
    with open(SALT_des3_FILE, 'wb') as f:
        f.write(simple_key)


def generate_Signature_file(signature):
        with open(SIGNATURE_FILE, 'wb') as f:
            f.write(signature)

def derive_aes_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def derive_des3_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=16)

#Triple Des encryption
def triple_des_enc(file_path, des3_key):
    with open(file_path,'rb')as f:
        message = f.read()

    cipher = DES3.new(des3_key,DES3.MODE_EAX,nonce)
    ciphered_data = cipher.encrypt(message)

    with open(ENCRYPTED_DES_FILE , 'wb') as f:
        f.write(ciphered_data)

def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:
        message = f.read()

    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphered_data = cipher.encrypt(pad(message, AES_BLOCK_SIZE))

    with open(ENCRYPTED_AES_FILE, 'wb') as f:
        f.write(IV)
        f.write(ciphered_data)


# Triple Des decryption
def triple_des_dec(file_path, des3_key):
    try:
        with open(file_path,'rb') as f:
            decrypted_data = f.read()
            cipher = DES3.new(des3_key,DES3.MODE_EAX,nonce)
            decrypted_file = cipher.decrypt(decrypted_data)
            with open(DECRYPTED_DES_FILE,'wb') as f:
                f.write(decrypted_file)
        messagebox.showinfo("Success", "Decryption completed successfully.")

    except Exception as e:
        tk.messagebox.showerror(title="Decryption Error" ,message="Incorrect password, please try again!" )


def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            original_iv = f.read(16)
            decrypt_data = f.read()
            cipher = AES.new(key, AES.MODE_CBC, IV)
            original = unpad(cipher.decrypt(decrypt_data), AES_BLOCK_SIZE)
            with open(DECRYPTED_AES_FILE, 'wb') as f:
                f.write(original)

            messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        tk.messagebox.showerror(title="Decryption Error" ,message="Incorrect password, please try again!" )


#Generate RSA key pairs and save them to files
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key)
        
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key)

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


