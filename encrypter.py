import zipfile
import os
import tkinter as tk
from tkinter import filedialog
import hashlib
from Crypto.Cipher import AES

def zip_directory(directory_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                zip_file.write(file_path, os.path.relpath(file_path, directory_path))
def unzip_directory(zip_path, directory_path):
    with zipfile.ZipFile(zip_path, 'r') as zip_file:
        zip_file.extractall(directory_path)

def encrypt_file(file_path, password):
    # Hash password using SHA-256
    password_hash = hashlib.sha256(password.encode()).digest()

    # Generate 256-bit AES key from hashed password
    key = password_hash[:32]

    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_EAX)

    # Encrypt and decrypt file using the key
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Encrypt plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Save encrypted file
    parent_dir = os.path.dirname(file_path)
    with open(parent_dir + '/encrypted_file.CKE', 'wb+') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    return parent_dir + '/encrypted_file.CKE'

def decrypt_file(file_path, password):
    # Hash password using SHA-256
    password_hash = hashlib.sha256(password.encode()).digest()

    # Generate 256-bit AES key from hashed password
    key = password_hash[:32]

    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_EAX)
    # Decrypt file
    with open(file_path, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

    # Initialize cipher using the same key and nonce
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    # Verify tag and decrypt ciphertext
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Save decrypted file
    parent_dir = os.path.dirname(file_path)
    with open(parent_dir + '/decrypted_file.zip', 'wb+') as f:
        f.write(plaintext)
    return parent_dir + '/decrypted_file.zip'
    
    # get parent directory of encrypted file

def main():
    root = tk.Tk()
    root.withdraw()
    user_password = input('Enter your password:\n')
    while True:
        action = input('choose action:\n\t1. encrypt\n\t2. decrypt\n\t3. enter new password\n\t4. exit\n')
        if action == '1':
            # Open folder selection dialog
            folder_selected = filedialog.askdirectory()
            zip_directory(folder_selected, folder_selected + '.zip')
            encrypt_file(folder_selected + '.zip', user_password)
            os.remove(folder_selected + '.zip')
        elif action == '2': #
            # Open file selection dialog
            file_selected = filedialog.askopenfilename()
            zip_name = decrypt_file(file_selected, user_password)
            # remove file type from selected file
            file_selected = file_selected[:-4]
            unzip_directory(zip_name, file_selected)
            os.remove(zip_name)
            os.remove(file_selected+ '/desktop.ini')
        elif action == '3':
            user_password = input('Enter new password:')
        elif action == '4':
            break
main()