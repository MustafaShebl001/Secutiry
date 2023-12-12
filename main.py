import tkinter as tk
from tkinter import filedialog,ttk
from tkinter import simpledialog, filedialog, messagebox
from Cryptofunctions import *



#On_click functions

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
    
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()

    key = derive_key_from_password(password, salt)

    try:
        decrypt_file(ENCRYPTED_FILE, key)
        # messagebox.showinfo("Success", "Decryption completed successfully.")
    except Exception as e:
        messagebox.showinfo("Error", f"Decryption error: {e}")


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
    on_sign_button_click()
    # force the user to specify the file
    file_path='signature.pem'
    generate_salt_file()

    # GUI prompts for password
    # taking password form user and checking its validity
    while True:
        password = simpledialog.askstring("Password", "Enter your encryption password:", show="*")
        if password == "":
            tk.messagebox.showerror(title="Empty password", message="Please enter a Password")
        else:
            break

    with open('salt.txt', 'rb') as f:
        salt = f.read()

    key = derive_key_from_password(password, salt)

    try:
        encrypt_file(file_path, key)
        messagebox.showinfo("Success", "Encryption and signature completed successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption error: {e}")


def on_verify_and_decrypt_button_click():
    on_decrypt_button_click()
    # GUI prompt for public key path
    public_key_path = filedialog.askopenfilename(title="Select Public Key File")

    if not public_key_path:
        messagebox.showerror("Error", "Invalid public key path.")
        return

    with open(public_key_path, 'rb') as f:
        public_key = f.read()

    try:
        verify_signature('Decrypted.txt', public_key)
        messagebox.showinfo("Success", "Signature and decryption verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")

    
def on_Create_certificate_button_click(): 
    # GUI prompt for subject name
    subject_name = simpledialog.askstring("Subject Name", "Enter your subject name:")
    if subject_name == "":
        tk.messagebox.showerror(title="Empty subject name", message="Please enter a subject name")
        return
    # GUI prompt for private key path
    private_key_path = filedialog.askopenfilename(title="Select Private Key File")

    if not private_key_path:
        messagebox.showerror("Error", "Invalid private key path.")
        return

    with open(private_key_path, 'rb') as f:
        private_key = f.read()

    try:
        create_self_signed_certificate(subject_name, private_key)
        messagebox.showinfo("Success", "Certificate created successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Certificate creation error: {e}")

def on_Verify_using_certificate_button_click():
    #GUI prompt for data file path
    data_file_path = filedialog.askopenfilename(title="Select data File")
    if not data_file_path:
        messagebox.showerror("Error", "Invalid data file path.")
        return

    #GUI prompt for signature file path
    signature_file_path = filedialog.askopenfilename(title="Select signature File")
    if not signature_file_path:
        messagebox.showerror("Error", "Invalid signature file path.")
        return

    #GUI prompt for subject name
    subject_name = simpledialog.askstring("Subject Name", "Enter your subject name:")
    if subject_name == "":
        tk.messagebox.showerror(title="Empty subject name", message="Please enter a subject name")
        return
    
    try:
        verify_using_certificate(data_file_path, signature_file_path, subject_name)
        messagebox.showinfo("Success", "Signature verified successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification error: {e}")

    



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
button_sign = tk.Button(frm, text="Sign", command=on_sign_button_click)
button_sign.grid(row=3, column=0, pady=20)
#
button_verify = tk.Button(frm, text="Verify Signature", command=on_verify_button_click)
button_verify.grid(row=3, column=1, pady=20)

button_sign_and_encrypt = tk.Button(frm, text="Sign and Encrypt", command=on_sign_and_encrypt_button_click)
button_sign_and_encrypt.grid(row=4, column=0, columnspan=2, pady=20)
# Verify and Decrypt Section
button_verify_and_decrypt = tk.Button(frm, text="Verify and Decrypt", command=on_verify_and_decrypt_button_click)
button_verify_and_decrypt.grid(row=5, column=0, columnspan=2, pady=20)

# Certificate Section
button_create_certificate = tk.Button(frm, text="Create Certificate", command=on_Create_certificate_button_click)
button_create_certificate.grid(row=6, column=0, columnspan=2, pady=20)

# Verify using Certificate Section
button_verify_using_certificate = tk.Button(frm, text="Verify using Certificate", command=on_Verify_using_certificate_button_click)
button_verify_using_certificate.grid(row=7, column=0, columnspan=2, pady=20)


root.mainloop()
