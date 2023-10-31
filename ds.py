import getpass
import pickle
import re
import os
import hashlib
import bcrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode




# Function to get a hidden password with an option to reveal it
def get_hidden_password(reveal=False):
    if reveal:
        return getpass.getpass("Enter a password: ")
    else:
        password = getpass.getpass("Enter a password: ")
        return password

# Functions to register a user
def validate_email(email):
    # Regular expression to validate email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

def validate_password(password):
    # Validate password: 1 uppercase, 1 lowercase, 1 digit, 1 special character, length 8
    if re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!*@#$%^&+=])[A-Za-z\d@#$%^&+*!=]{8,}$', password):
        return True
    return False

  

def register():
    email = input("Enter your email: ")
    if not validate_email(email):
        print("Invalid email address. Registration failed.")
        return

    password = input("Enter a password: ")
    if not validate_password(password):
        print("Invalid password. Registration failed.")
        return

    # Save email and password to Enregistrement.txt
    with open("Enregistrement.txt", "a") as file:
        file.write(f"{email}:{password}\n")
    print("Registration successful!")
    

# Functions for user authentication
def authenticate():
    email = input("Enter your email: ")
    reveal_password = input("Do you want to reveal the password (y/n)? ").lower()
    password = get_hidden_password(reveal=reveal_password == 'y')

    # Check if the credentials exist in Enregistrement.txt
    with open("Enregistrement.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            stored_email, stored_password = line.strip().split(':')
            if email == stored_email and password == stored_password:
                return True
    return False



def main_menu():
    while True:
        print("\033[1;37;40m  \n")
        print("\033[1;37;40m ╔════════════════════════════════════════════════╗ ")
        print("\033[1;37;40m ║      \033[1;32;40mWelcome to my project      \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;32;40mChoose an operation to perform:          \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ║      \033[1;34;40mA - Hash Operations                     \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mB - RSA Encryption/Decryption            \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mC - RSA Certificate Operations            \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;31;40mQ - Quit                                \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ╚════════════════════════════════════════════════╝\033[1;37;40m ")

        choice = input("\033[1;37;40mEnter your choice: ").upper()

        if choice == 'A':
            hash_menu()
        elif choice == 'B':
            rsa_menu()
        elif choice == 'C':
            certificate_menu()
        elif choice == 'Q':
            print("\033[1;37;40mGoodbye! Stay secure.\033[0;0;0m")
            break
        else:
            print("\033[1;31;40mInvalid choice. Please select a valid option.\033[0;0;0m")
def hash_menu():
    while True:
        print("\033[1;37;40m  \n")
        print("\033[1;37;40m ╔══════════════════════════════════════════════╗ ")
        print("\033[1;37;40m ║      \033[1;32;40mHash Operations Menu                    \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;32;40mSelect a hashing operation:             \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ║      \033[1;34;40ma - Hash a word by SHA256                \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mb - Hash a word with salt using bcrypt    \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mc - Perform a Dictionary Attack          \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;31;40md - Back to the main menu               \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ╚══════════════════════════════════════════════╝\033[1;37;40m ")

        choice = input("\033[1;37;40mEnter your choice: ").lower()

        if choice == 'a':
            word = input("Enter a word to hash: ")
            sha256_hash = hashlib.sha256(word.encode()).hexdigest()
            print(f"SHA256 Hash: {sha256_hash}")
        elif choice == 'b':
            word = input("Enter a word to hash: ")
            salt = bcrypt.gensalt()
            hashed_word = bcrypt.hashpw(word.encode(), salt)
            print(f"Bcrypt Hash: {hashed_word.decode()}")
        elif choice == 'c':
            # Perform a dictionary attack
            hashed_word_to_crack = input("Enter the hashed passphrase you want to crack: ")
            common_passwords_file_path = "C:/Users/MEHDI CHERIF/Desktop/common_passwords.txt"

            with open(common_passwords_file_path, "r") as file:
                common_passwords = [line.strip() for line in file]

            for common_password in common_passwords:
                if hashlib.sha256(common_password.encode()).hexdigest() == hashed_word_to_crack:
                    print(f"Passphrase found in the dictionary: {common_password}")
                    break
            else:
                print("Passphrase not found in the dictionary.")
        elif choice == 'd':
            break
        else:
            print("\033[1;31;40mInvalid choice. Please select a valid option.\033[0;0;0m")





def rsa_menu():
    while True:
        print("\033[1;37;40m  \n")
        print("\033[1;37;40m ╔══════════════════════════════════════════════╗ ")
        print("\033[1;37;40m ║      \033[1;32;40mRSA Operations Menu                     \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;32;40mSelect an RSA operation:                \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ║      \033[1;34;40ma - Generate RSA key pair              \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mb - Encrypt a message with RSA          \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mc - Decrypt a message with RSA          \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40md - Sign a message with RSA             \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40me - Verify a signature with RSA         \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;31;40mf - Back to main menu                    \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ╚══════════════════════════════════════════════╝\033[1;37;40m ")

        choice = input("\033[1;37;40mEnter your choice: ").lower()

        if choice == 'a':
            generate_rsa_key_pair()
        elif choice == 'b':
            encrypted_message = encrypt_rsa()
        elif choice == 'c':
            if 'encrypted_message' not in locals():
                print("\033[1;31;40mPlease encrypt a message first.\033[0;0;0m")
            else:
                decrypt_rsa(encrypted_message)
        elif choice == 'd':
            sign_rsa()
        elif choice == 'e':
            verify_rsa_signature()
        elif choice == 'f':
            break
        else:
            print("\033[1;31;40mInvalid choice. Please select a valid option.\033[0;0;0m")

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)

    print("RSA key pair generated and saved as private_key.pem and public_key.pem")

def encrypt_rsa():
    with open("public_key.pem", "rb") as public_file:
        public_key = RSA.import_key(public_file.read())
        cipher = PKCS1_OAEP.new(public_key)
        message = input("Enter the message to encrypt: ")
        encrypted_message = cipher.encrypt(message.encode())
        print(f"Encrypted message: {b64encode(encrypted_message).decode()}")
        return encrypted_message

def decrypt_rsa(encrypted_message):
    with open("private_key.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(encrypted_message)
        print(f"Decrypted message: {decrypted_message.decode()}")


def sign_rsa():
    with open("private_key.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
        message = input("Enter the message to sign: ")
        h = SHA256.new(message.encode())
        signature = PKCS1_v1_5.new(private_key).sign(h)
        print(f"Signature: {b64encode(signature).decode()}")

def verify_rsa_signature():
    with open("public_key.pem", "rb") as public_file:
        public_key = RSA.import_key(public_file.read())
        message = input("Enter the message: ")
        signature = input("Enter the signature to verify: ")
        h = SHA256.new(message.encode())
        if PKCS1_v1_5.new(public_key).verify(h, b64decode(signature)):
            print("Signature is valid.")
        else:
            print("Signature is invalid.")


def certificate_menu():
    while True:
        print("\033[1;37;40m  \n")
        print("\033[1;37;40m ╔══════════════════════════════════════════════╗ ")
        print("\033[1;37;40m ║      \033[1;32;40mRSA Certificate Operations Menu           \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;32;40mSelect a certificate operation:         \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ║      \033[1;34;40ma - Generate RSA key pair              \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mb - Generate a self-signed certificate   \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40mc - Encrypt a message with the certificate \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;31;40md - Back to main menu                    \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ╚══════════════════════════════════════════════╝\033[1;37;40m ")

        choice = input("\033[1;37;40mEnter your choice: ").lower()

        if choice == 'a':
            generate_rsa_key_pair()
        elif choice == 'b':
            generate_certificate()
        elif choice == 'c':
            encrypt_with_certificate()
        elif choice == 'd':
            break
        else:
            print("\033[1;31;40mInvalid choice. Please select a valid option.\033[0;0;0m")

# Function to generate a self-signed certificate
def generate_certificate():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    
    cert = {
        "subject": "CN=My Certificate",
        "issuer": "CN=My Certificate",
        "notBefore": 0,
        "notAfter": 365 * 24 * 60 * 60,
        "serialNumber": 1000,
        "public_key": public_key.export_key().decode(),
        "private_key": private_key.export_key().decode(),
    }

    cert_bytes = cert_to_bytes(cert)
    with open("certificate.pem", "wb") as cert_file:
        cert_file.write(cert_bytes)
    print("Self-signed certificate generated and saved as certificate.pem")

# Function to encrypt a message with a certificate
def encrypt_with_certificate():
    with open("certificate.pem", "rb") as cert_file:
        cert_bytes = cert_file.read()
    recipient_cert = bytes_to_cert(cert_bytes)
    recipient_key = RSA.import_key(recipient_cert["public_key"])
    cipher = PKCS1_OAEP.new(recipient_key)

    message = input("Enter the message to encrypt with the certificate: ")
    encrypted_message = cipher.encrypt(message.encode())
    print(f"Encrypted message: {b64encode(encrypted_message).decode()}")

# Function to convert certificate to bytes
def cert_to_bytes(cert):
    return pickle.dumps(cert)

# Function to convert bytes to a certificate
def bytes_to_cert(cert_bytes):
    return pickle.loads(cert_bytes)



if __name__ == "__main__":
    if not os.path.exists("Enregistrement.txt"):
        with open("Enregistrement.txt", "w"):
            pass

    while True:
        print("\033[1;37;40m  \n")
        print("\033[1;37;40m ╔════════════════════════════════════════════════╗ ")
        print("\033[1;37;40m ║      \033[1;32;40mWelcome to the Cybersecurity System      \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;32;40mWhat would you like to do today?          \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ║      \033[1;34;40m1 - Register                             \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;34;40m2 - Login                                \033[1;37;40m║ ")
        print("\033[1;37;40m ║      \033[1;31;40mQ - Quit                                \033[1;37;40m║ ")
        print("\033[1;37;40m ║                                            ║ ")
        print("\033[1;37;40m ╚════════════════════════════════════════════════╝\033[1;37;40m ")

        choice = input("\033[1;37;40mEnter your choice: ").upper()

        if choice == '1':
            register()
        elif choice == '2':
            if authenticate():
                main_menu()
            else:
                print("\033[1;31;40mAuthentication failed. Please register or check your credentials.\033[0;0;0m")
        elif choice == 'Q':
            print("\033[1;37;40mGoodbye! Stay secure.\033[0;0;0m")
            break
        else:
            print("\033[1;31;40mInvalid choice. Please select a valid option.\033[0;0;0m")