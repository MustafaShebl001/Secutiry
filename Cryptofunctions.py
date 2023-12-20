from Crypto.Signature import PKCS1_v1_5, pkcs1_15
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from Crypto.Cipher import DES3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import *
from tkinter import simpledialog, filedialog, messagebox
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# from main import flag


def generate_self_signed_certificate(public_key_pem):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    try:
        # Create a self-signed certificate
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "My Certificate")]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "My Certificate")]))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # Valid for one year
        )
        # Sign the certificate with a dummy private key (self-signed)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # certificate = builder.sign(private_key, x509.CertificateBuilder.)
        certificate = builder.sign(private_key, hashes.SHA256(), default_backend())

        # Serialize the certificate to PEM format
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        # Get the public key from the private key
        public_key = private_key.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open("certificate_pubK.pem", 'wb') as f:
            f.write(public_key_pem)
        messagebox.showinfo("Authority public key", "Authority public key file is created")
        with open("certificate.crt", 'wb') as f:
            f.write(certificate_pem)
        messagebox.showinfo("Cert Created","Certificate is created successfully")
    except Exception as e:
        messagebox.showerror("Cert can't be created","Error in certificate creation")

def verify_certificate(certificate_pem, issuer_public_key_pem):
    # Load the certificate and issuer's public key
    certificate = x509.load_pem_x509_certificate(certificate_pem, default_backend())
    issuer_public_key = serialization.load_pem_public_key(issuer_public_key_pem, backend=default_backend())

    # Verify the certificate
    try:
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        messagebox.showinfo("Valid cert","This certificate is verified")
    except Exception as e:
        messagebox.showerror("Invalid cert", "This certificate is not verified")

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
Flag = False



# Normal functions
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


# Triple Des encryption
def triple_des_enc(file_path, des3_key):
    with open(file_path, 'rb') as f:
        message = f.read()

    cipher = DES3.new(des3_key, DES3.MODE_EAX, nonce)
    ciphered_data = cipher.encrypt(message)

    with open(ENCRYPTED_DES_FILE, 'wb') as f:
        f.write(ciphered_data)


def encrypt_file(file_path, key):
    global Flag
    with open(file_path, "rb") as f:
        message = f.read()

    cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphered_data = cipher.encrypt(pad(message, AES_BLOCK_SIZE))
    if Flag == False:
        with open(ENCRYPTED_AES_FILE, 'wb') as f:
            f.write(IV)
            f.write(ciphered_data)
    else:
        with open("Encrypted_signed_file.txt", 'wb') as f:
            f.write(IV)
            f.write(ciphered_data)
            Flag = False



# Triple Des decryption
def triple_des_dec(file_path, des3_key):
    try:
        with open(file_path, 'rb') as f:
            decrypted_data = f.read()
            cipher = DES3.new(des3_key, DES3.MODE_EAX, nonce)
            decrypted_file = cipher.decrypt(decrypted_data)
            with open(DECRYPTED_DES_FILE, 'wb') as f:
                f.write(decrypted_file)
        messagebox.showinfo("Success", "Decryption completed successfully.")

    except Exception as e:
        tk.messagebox.showerror(title="Decryption Error", message="Incorrect password, please try again!")


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
        tk.messagebox.showerror(title="Decryption Error", message="Incorrect password, please try again!")


# Generate RSA key pairs and save them to files
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key)

    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key)


def sign_file(file_path, private_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    with open("Signed_File.sgn",'wb')as signed_file:
        signed_file.write(data)

    key = RSA.import_key(private_key)
    h = SHA512.new(data)
    signature = pkcs1_15.new(key).sign(h)

    with open('Signed_File.sgn', 'ab') as file:
        file.write(b'\nSIGNATURE\n')
        file.write(signature)
        file.write(b'\nEND OF SIGNATURE\n')  # Add a delimiter

    Flag = True


def verify_signature(file_path, public_key):

    with open(file_path, 'rb') as file:
        data = file.read()

        # Find the signature start and end positions
        signature_start = data.rfind(b'\nSIGNATURE\n')
        signature_end = data.rfind(b'\nEND OF SIGNATURE\n')

        if signature_start == -1 or signature_end == -1 or signature_start >= signature_end:
            print("Signature not found or invalid format.")
            return False

        signature = data[signature_start + len(b'\nSIGNATURE\n'):signature_end]

        # Extract the original content (excluding the signature) for verification
        original_content = data[:signature_start] + data[signature_end + len(b'\nEND OF SIGNATURE\n'):]

        # Verify the signature against the original content
        key = RSA.import_key(public_key)
        h = SHA512.new(original_content)

        try:
            pkcs1_15.new(key).verify(h, signature)
            messagebox.showinfo("Verified","This file is verified successfully")
        except (ValueError, TypeError):
            messagebox.showerror("Unverified","This file is not verified")

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

