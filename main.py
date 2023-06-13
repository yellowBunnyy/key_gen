import re
import subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk

ENCRYPTEDPASS = b"Ilik32Cod3"
# PRIVATE_KEY_NAME = "rsa_key.pem"
# PUBLIC_KEY_NAME = "csr.pem"
REGEX_CERT_DETAILS = re.compile(r"([\s\S]*)Modulus:")


def generate_private_key(encryptedpass):
    """Generate the private key (RSA)"""
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=2048, backend=default_backend())
    with open(PRIVATE_KEY_NAME, "wb") as f:
        f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(encryptedpass)))
    return key

def generate_public_key(private_key, **kwargs):
    # Generowanie żądania podpisu certyfikatu (CSR)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs.get("country")),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs.get("state")),
        x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs.get("locality")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs.get("organization")),
        x509.NameAttribute(NameOID.COMMON_NAME, kwargs.get("common_name"))])).add_extension(
        x509.SubjectAlternativeName([
        x509.DNSName(kwargs.get("common_name")),
        ]),
        critical=False,).sign(private_key, hashes.SHA256(), default_backend())
    with open(PUBLIC_KEY_NAME, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        print('Private key and public key was created!!')
        

def show_generatet_public_key_details():
    output = subprocess.check_output(f"openssl req -in {PUBLIC_KEY_NAME} -noout -text",
                                     shell=True, universal_newlines=True)
    match = re.search(REGEX_CERT_DETAILS, output)
    if match:
        text = match.group()
        return text[:-9].strip()
    else:
        return "No match found"
    

def main(private_key_name, public_key_name, country, state, locality, organization, common_name, encrypted_pass=b"Ilik32Cod3"):
    global PRIVATE_KEY_NAME
    global PUBLIC_KEY_NAME
    PRIVATE_KEY_NAME = private_key_name
    PUBLIC_KEY_NAME = public_key_name

    private_key = generate_private_key(encrypted_pass)
    generate_public_key(private_key, country=country,
                        state=state, locality=locality,
                        organization=organization, common_name=common_name)
    cert_inf = show_generatet_public_key_details()

    # Insert the private key and CSR strings into the text fields
    with open(PRIVATE_KEY_NAME, "r") as f:
        private_key_str = f.read()
    with open(PUBLIC_KEY_NAME, "r") as f:
        public_key_str = f.read()

    private_key_text.delete('1.0', tk.END)
    private_key_text.insert(tk.END, private_key_str)
    csr_text.delete('1.0', tk.END)
    csr_text.insert(tk.END, public_key_str)
    details_text.delete('1.0', tk.END)
    details_text.insert(tk.END, cert_inf)


bg_color = "#FFD1DC" # Pink
input_color = "#D1FFD6" # Green
button_color = "#FFFFD1" # Yellow
text_field_color = "#D1D4FF" # Blue

def create_label(root, text, row, column):
    label = ttk.Label(root, text=text)
    label.grid(row=row, column=column, padx=(20, 0), pady=10, sticky="w")
    return label

def create_entry(root, row, column):
    entry = ttk.Entry(root)
    entry.grid(row=row, column=column, padx=20, pady=10, ipadx=10, sticky="we")
    return entry

def create_text(root, row, column):
    text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=30, height=10)
    text.grid(row=row, column=column, padx=20, pady=10)
    return text

def submit():
    main(e1.get(), e2.get(), e3.get(), e4.get(), e5.get(), e6.get(), e7.get())
    messagebox.showinfo("Success", "Operation completed successfully.")

root = tk.Tk()
root.geometry('920x800')
root.title("SSL Key Generator")
root.config(bg=bg_color)

style = ttk.Style()
style.configure("TLabel", background=bg_color)
style.configure("TEntry", fieldbackground=input_color)
style.configure("TButton", background=button_color)

create_label(root, "Private Key Name:", 0, 0)
create_label(root, "Public Key Name:", 1, 0)
create_label(root, "Country:", 2, 0)
create_label(root, "State:", 3, 0)
create_label(root, "Locality:", 4, 0)
create_label(root, "Organization:", 5, 0)
create_label(root, "Common Name:", 6, 0)

e1 = create_entry(root, 0, 1)
e2 = create_entry(root, 1, 1)
e3 = create_entry(root, 2, 1)
e4 = create_entry(root, 3, 1)
e5 = create_entry(root, 4, 1)
e6 = create_entry(root, 5, 1)
e7 = create_entry(root, 6, 1)

create_label(root, "Private Key:", 8, 0)
private_key_text = create_text(root, 9, 0)
private_key_text.config(background=text_field_color, width=50)

create_label(root, "CSR:", 8, 1)
csr_text = create_text(root, 9, 1)
csr_text.config(background=text_field_color, width=50)

create_label(root, "Details:", 10, 0)
details_text = create_text(root, 11, 0)
details_text.config(background=text_field_color, width=50)

submit_button = ttk.Button(root, text='Submit', command=submit)
submit_button.grid(row=11, column=1, padx=20, pady=20)

root.mainloop()