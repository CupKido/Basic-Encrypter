import zipfile
import os
import tkinter as tk
from tkinter import filedialog
import hashlib
from Crypto.Cipher import AES
import argparse

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
    # get name of zip file
    file_name = os.path.basename(file_path)[:-4]


    with open(parent_dir + '/' + file_name +'.CKE', 'wb+') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    return parent_dir + '/' + file_name +'.CKE'


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
    # get name of encrypted file
    file_name = os.path.basename(file_path)[:-4]
    with open(parent_dir + '/' + file_name + '.zip', 'wb+') as f:
        f.write(plaintext)
    return parent_dir + '/' + file_name + '.zip'
    
    # get parent directory of encrypted file


def encrypt_folder(folder_selected, user_password):
    print('Zipping...')
    zip_directory(folder_selected, folder_selected + '.zip')
    print('Encrypting...')
    encrypt_file(folder_selected + '.zip', user_password)
    print('Cleaning up...')
    os.remove(folder_selected + '.zip')
    print('Done!')


def decrypt_folder(file_selected, user_password):
    print('Decrypting...')
    try:
        zip_name = decrypt_file(file_selected, user_password)
    except Exception as e:
        print('Incorrect password, please change password and try again, or choose matching file')
        return
    # remove file type from selected file
    file_selected = file_selected[:-4]
    print('Unzipping...')
    try:
        os.makedirs(file_selected)
    except FileExistsError:
        # directory already exists
        pass
    try:
        unzip_directory(zip_name, file_selected)
        print('Cleaning up...')
        os.remove(zip_name)
        os.remove(file_selected + '/desktop.ini')
        print('Done!')
    except Exception as e:
        print('Error while unzipping, the zipped file has been decrypted and saved as ' + zip_name)
    


def main():
    parser = argparse.ArgumentParser(description='Client for the VPN')
    parser.add_argument('-e','--encrypt', type=bool, help='whether to encrypt')
    parser.add_argument('-d','--decrypt', type=bool, help='whether to decrypt')
    parser.add_argument('-pa','--path', type=str, help='path to file or folder')
    parser.add_argument('-p','--password', type=str, help='password to encrypt/decrypt with')
    args = parser.parse_args()
    #args.server = '127.0.0.1'
    #args.tester = 'saar'
    #if -pi was given, print all interfaces and exit
    #check if arguments are valid
    if args.encrypt is not None or args.decrypt is not None:
        if args.password is None: 
            print('please enter password with flag -p')
            return
        if args.path is None:
            print('please enter path with flag -pa')
            return
        if args.encrypt is not None:
            encrypt_folder(args.path, args.password)
        elif args.decrypt is not None:
            decrypt_folder(args.path, args.password)
        return
    
    root = tk.Tk()
    root.withdraw()
    user_password = input('Enter your password:\n')
    while True:
        action = input('choose action:\n\t1. encrypt\n\t2. decrypt\n\t3. enter new password\n\t4. exit\n')
        if action == '1':
            # Open folder selection dialog
            folder_selected = filedialog.askdirectory()
            if folder_selected == '':
                print('No folder selected')
                continue
            encrypt_folder(folder_selected, user_password)
        elif action == '2': #
            # Open file selection dialog
            file_selected = filedialog.askopenfilename()
            if file_selected == '':
                print('No file selected')
                continue
            decrypt_folder(file_selected, user_password)
        elif action == '3':
            user_password = input('Enter new password:')
        elif action == '4':
            break
main()