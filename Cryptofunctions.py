import datetime
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import filedialog,ttk
from tkinter import simpledialog, filedialog, messagebox
from Crypto import Random
from cryptography.x509 import X509
import os

# Constants
SALT_FILE = "salt.txt"
SIGNATURE_FILE = "signature.pem"
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


def generate_Signature_file(signature):
        with open(SIGNATURE_FILE, 'wb') as f:
            f.write(signature)

def derive_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=32)


def encrypt_file(file_path, key):
    with open(file_path, "rb") as f:    
        message = f.read()  # read the file to encrypt

    iv = Random.new().read(AES.block_size)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, IV)     # create a cipher object using the random secret
    ciphered_data = cipher.encrypt(pad(message, AES_BLOCK_SIZE)) # pad the message and encrypt

    with open(ENCRYPTED_FILE, 'wb') as f:
        f.write(iv) # write the iv first to file
        f.write(ciphered_data) # write the ciphered data


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

def create_self_signed_certificate(subject_name, private_key):
    issuer_name = subject_name
    public_key = RSA.import_key(private_key).publickey()

    #build a certificate
    builder = X509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(public_key)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365))
    builder = builder.serial_number(X509.random_serial_number())
    builder = builder.add_extension(X509.BasicConstraints(ca=False,path_length=None), critical = True)
    cert = builder.sign(private_key, algorithm = SHA256())
    
    
    # Get the current directory
    current_dir = os.getcwd()
    # Define the path for the certificates folder
    certificates_dir = os.path.join(current_dir, "certificates")
    # Check if the certificates folder already exists
    if not os.path.exists(certificates_dir):
        # Create the certificates folder
        os.makedirs(certificates_dir)
    
    
    # Define the certificate file path
    certificate_file_path = os.path.join(certificates_dir, f"{subject_name}_certificate.pem")
    # Save the certificate to the file
    with open(certificate_file_path, "wb") as f:
        f.write(cert)

    messagebox.showinfo("Success", "Certificate saved successfully.")

        

#def load_certificate():
#    try:
#        with open(CERTIFIFCATE_FILE, "rb") as f:
#            certificate = X509.load_pem_x509_certificate(f.read())
#            messagebox.showinfo("Success", "Certificate loaded successfully.")
#            return certificate
#    except Exception as e:
#        messagebox.showerror("Error", f"Certificate loading error: {e}")

def verify_using_certificate(signature_file, data_file,subject_name):
    try:

        # load certificate
        certificate_file_path = os.path.join("certificates", f"{subject_name}_certificate.pem")
        with open(certificate_file_path, "rb") as f:
            certificate = X509.load_pem_x509_certificate(f.read())

        #get public key from certificate
        public_key = certificate.public_key()
        
        # load signature
        with open(signature_file, 'rb') as f:
            signature = f.read()
        
        # load original data
        with open(data_file, 'rb') as f:
            data = f.read()
        
        #verify signature
        public_key.verify(signature, data)
        messagebox.showinfo("Success", "Signature verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")









