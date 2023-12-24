import tkinter as tk
from tkinter import filedialog, ttk
from tkinter import simpledialog, filedialog, messagebox
from Cryptofunctions import *

# On_click functions
# Generate a self-signed certificate with the passed public key


def on_generate_certificate():
    with open("public_key.pem", 'rb')as f:
        public_key_cert = f.read()
    generate_self_signed_certificate(public_key_cert)


def on_verify_certificate():
    Cert_file_path = filedialog.askopenfilename(
        title="Select Certificate to verify")
    if not Cert_file_path:
        messagebox.showerror("Error", "Invalid Certificate Selection.")
        return
    with open(Cert_file_path, 'rb')as f:
        certificate = f.read()

    Authority_key_file = filedialog.askopenfilename(
        title="Select Authority public key")
    if not Authority_key_file:
        messagebox.showerror("Error", "Invalid Public key.")
        return

    with open(Authority_key_file, 'rb')as f:
        certificate_pub_key = f.read()

    try:
        verify_certificate(certificate, certificate_pub_key)
    except Exception as e:
        messagebox.showerror("Error Cert is unverified",
                             "This certificate is not verified")
        return


def on_aes_encrypt_button_click():
    AES_file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    if not AES_file_path:
        messagebox.showerror("Error", "Invalid file path.")
        return
    # force the user to specify the file
    # if file_path == "":
    #     tk.messagebox.showinfo(title="file path", message="Please choose a file to do operations on")
    #     choose_file()

    generate_salt_file()
    # GUI prompts for password and initialization vector
    # taking password form user and checking its validity
    while True:
        password = simpledialog.askstring(
            "Password", "Enter your encryption password:", show="*")
        if password == "":
            tk.messagebox.showerror(
                title="Empty password", message="Please enter a Password")
        else:
            break

    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_aes_key_from_password(password, salt)

    try:
        encrypt_file(AES_file_path, key)
        messagebox.showinfo("Success", "Encryption completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption error: {e}")


def on_des_encrypt_button_click():
    DES_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if not DES_file_path:
        messagebox.showerror("Error", "Invalid file path.")
        return
    # force the user to specify the file
    # if file_path == "":
    #     tk.messagebox.showinfo(title="file path", message="Please choose a file to do operations on")
    #     choose_file()

    generate_des_salt_file()

    # GUI prompts for password and initialization vector
    # taking password form user and checking its validity
    while True:
        password = simpledialog.askstring(
            "3Des Password", "Enter 3Des encryption password:", show="*")
        if password == "":
            tk.messagebox.showerror(
                title="Empty password", message="Please enter a Password")
        else:
            break

    with open(SALT_des3_FILE, 'rb') as f:
        salt = f.read()

    key = derive_des3_key_from_password(password, salt)

    try:
        triple_des_enc(DES_file_path, key)
        messagebox.showinfo("Success", "Encryption completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption error: {e}")


def on_aes_decrypt_button_click():
    AES_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if not AES_file_path:
        messagebox.showerror("Error", "Invalid file path.")
        return
    # GUI prompts for password and initialization vector
    password = simpledialog.askstring(
        "Input", "Enter your decryption password:", show="*")

    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_aes_key_from_password(password, salt)

    try:
        decrypt_file(AES_file_path, key)
        # messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        messagebox.showinfo("Error", f"Decryption error: {e}")


def on_des_decrypt_button_click():
    DES_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    if not DES_file_path:
        messagebox.showerror("Error", "Invalid file path.")
        return
    # GUI prompts for password and initialization vector
    password = simpledialog.askstring(
        "Input", "Enter your decryption password:", show="*")

    with open(SALT_des3_FILE, 'rb') as f:
        salt = f.read()

    key = derive_des3_key_from_password(password, salt)

    try:
        triple_des_dec(DES_file_path, key)
        # messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        messagebox.showinfo("Error", f"Decryption error: {e}")


# def on_sign_and_encrypt_button_click():
#     file_path_to_sign = filedialog.askopenfilename(title="Select File to Sign then Encrypt")
#     if not file_path_to_sign:
#         messagebox.showerror("Error", "Invalid file path.")
#         return
#     on_sign_button_click()
#     # force the user to specify the file
#     # file_path = 'signature.pem'
#     generate_salt_file()
#
#     # GUI prompts for password
#     # taking password form user and checking its validity
#     while True:
#         password = simpledialog.askstring("Password", "Enter your encryption password:", show="*")
#         if password == "":
#             tk.messagebox.showerror(title="Empty password", message="Please enter a Password")
#         else:
#             break
#
#     with open('salt.txt', 'rb') as f:
#         salt = f.read()
#
#     key = derive_aes_key_from_password(password, salt)
#
#     try:
#         # encrypt_file(file_path_to_sign, key)
#         messagebox.showinfo("Success", "Encryption and signature completed successfully.")
#     except Exception as e:
#         messagebox.showerror("Error", f"Encryption error: {e}")

def on_sign_and_encrypt_button_click():
    # flag = False
    file_path_to_sign = filedialog.askopenfilename(
        title="Select File to Sign then Encrypt")
    if not file_path_to_sign:
        messagebox.showerror("Error", "Invalid file path.")
        return

    private_key_path = filedialog.askopenfilename(
        title="Select Private Key File")

    if not private_key_path:
        messagebox.showerror("Error", "Invalid private key path.")
        return

    with open(private_key_path, 'rb') as f:
        private_key = f.read()
    try:
        sign_file(file_path_to_sign, private_key)
        messagebox.showinfo("File Signed", "File Signed Successfully")
    except Exception as e:
        messagebox.showerror("File not signed", "File is not signed ")
        return

    generate_salt_file()

    # GUI prompts for password and initialization vector
    # taking password form user and checking its validity
    while True:
        password = simpledialog.askstring(
            "Password", "Enter your encryption password:", show="*")
        if password == "":
            tk.messagebox.showerror(
                title="Empty password", message="Please enter a Password")
        else:
            break

    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_aes_key_from_password(password, salt)
    try:
        encrypt_file("Signed_File.sgn", key)
        messagebox.showinfo("File is Encrypted",
                            "File is encrypted successfully")
    except Exception as e:
        messagebox.showerror("File is not Encrypted", "File is not encrypted")
        return


def on_sign_button_click():
    # global file_path_to_sign
    file_path_to_sign = filedialog.askopenfilename(title="Select File to Sign")
    if not file_path_to_sign:
        messagebox.showerror("Error", "Invalid file path.")
        return

    # GUI prompt for private key path
    # global private_key_path
    private_key_path = filedialog.askopenfilename(
        title="Select Private Key File")

    if not private_key_path:
        messagebox.showerror("Error", "Invalid private key path.")
        return

    with open(private_key_path, 'rb') as f:
        private_key = f.read()

    try:
        sign_file(file_path_to_sign, private_key)
        messagebox.showinfo("Success", "File signed successfully.")
    except Exception as e:
        messagebox.showinfo("Error", f"Signing error: {e}")


def on__generate_keys_button_click():
    try:
        generate_rsa_key_pair()
        messagebox.showinfo("Success", "Keys generated sucessfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Signing error: {e}")


def on_verify_button_click():
    # global file_path_to_verify
    file_path_to_verify = filedialog.askopenfilename(
        title="Select File to Verify")
    if not file_path_to_verify:
        messagebox.showerror("Error", "Invalid file path.")
        return
    # GUI prompt for public key path
    public_key_path = filedialog.askopenfilename(
        title="Select Public Key File")

    if not public_key_path:
        messagebox.showerror("Error", "Invalid public key path.")
        return

    with open(public_key_path, 'rb') as f:
        public_key = f.read()

    try:
        verify_signature(file_path_to_verify, public_key)
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")

# def on_sign_and_encrypt_button_click():
#     generate_salt_file()
#     while True:
#         password = simpledialog.askstring("Password", "Enter your encryption password:", show="*")
#         if password == "":
#             tk.messagebox.showerror(title="Empty password", message="Please enter a Password")
#         else:
#             break
#
#     with open('salt.txt', 'rb') as f:
#         salt = f.read()
#
#     key = derive_aes_key_from_password(password, salt)
#
#     private_key = filedialog.askopenfilename(title="Select Private Key File")
#
#     if not private_key:
#         messagebox.showerror("Error", "Invalid private key path.")
#         return
#
#
#     sign_and_encrypt(file_path,private_key,key)


def on_verify_and_decrypt_button_click():
    on_aes_decrypt_button_click()
    # GUI prompt for public key path
    public_key_path = filedialog.askopenfilename(
        title="Select Public Key File")

    if not public_key_path:
        messagebox.showerror("Error", "Invalid public key path.")
        return

    with open(public_key_path, 'rb') as f:
        public_key = f.read()

    try:
        verify_signature('DecryptedAES.txt', public_key)
        messagebox.showinfo(
            "Success", "Signature and decryption verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")


# GUI
root = tk.Tk()
root.title("Security App")
root.resizable(False, False)
# Configure a style with border radius
style = ttk.Style()
style.configure("Rounded.TButton", borderwidth=5,
                relief="ridge", padding=(10, 5))

frm = ttk.Frame(root, padding=10, style="Rounded.TButton")
frm.grid()

# Encryption Section
button_encrypt = tk.Button(frm, text="AES 256 Encrypt",
                           command=on_aes_encrypt_button_click, bg="#4CAF50", fg="white", borderwidth=3)
button_encrypt.grid(row=2, column=0, pady=20, padx=20)

# Decryption Section
button_decrypt = tk.Button(frm, text="AES 256 Decrypt",
                           command=on_aes_decrypt_button_click, bg="#008CBA", fg="white", borderwidth=3)
button_decrypt.grid(row=2, column=1, pady=20, padx=10)

# Triple Des encryption
button_des3_enc = tk.Button(
    frm, text="DES3 Enc", command=on_des_encrypt_button_click, bg="#4CAF50", fg="white", borderwidth=3)
button_des3_enc.grid(row=3, column=0, pady=20)

# Triple Des decryption
button_des3_dec = tk.Button(
    frm, text="DES3 Dec", command=on_des_decrypt_button_click, bg="#008CBA", fg="white", borderwidth=3)
button_des3_dec.grid(row=3, column=1, pady=20)

# Key Pair Generation Section
button_generate_keys = tk.Button(
    frm, text="Generate Keys", command=on__generate_keys_button_click, bg="#FFC107", fg="black", borderwidth=3)
button_generate_keys.grid(row=4, column=0, columnspan=2, pady=20)

# Digital Signature Section
button_sign = tk.Button(frm, text="Sign A Document",
                        command=on_sign_button_click, bg="#673AB7", fg="white", borderwidth=3)
button_sign.grid(row=5, column=0, pady=20)

button_verify = tk.Button(frm, text="Verify Signature",
                          command=on_verify_button_click, bg="#FF5722", fg="white", borderwidth=3)
button_verify.grid(row=5, column=1, pady=20)

button_sign_and_encrypt = tk.Button(
    frm, text="Sign and Encrypt", command=on_sign_and_encrypt_button_click, bg="#E91E63", fg="white", borderwidth=3)
button_sign_and_encrypt.grid(row=6, column=0, columnspan=2, pady=20)

# Verify and Decrypt Section
button_verify_and_decrypt = tk.Button(
    frm, text="Verify and Decrypt", command=on_verify_and_decrypt_button_click, bg="#795548", fg="white", borderwidth=3)
button_verify_and_decrypt.grid(row=7, column=0, columnspan=2, pady=20)

button_cert = tk.Button(frm, text="Generate self-signed cert",
                        command=on_generate_certificate, bg="#FFEB3B", fg="black", borderwidth=3)
button_cert.grid(row=8, column=0, pady=20)

button_verify_cert = tk.Button(
    frm, text="Verify Cert.", command=on_verify_certificate, bg="#607D8B", fg="white")
button_verify_cert.grid(row=8, column=1, pady=20)

root.mainloop()
