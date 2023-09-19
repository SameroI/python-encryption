from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to generate a random AES encryption key


def generate_key():
    return get_random_bytes(16)  # AES-128 encryption key


def pad(text):
    # Pad the input text to be a multiple of 16 bytes (AES block size)
    padding = 16 - (len(text) % 16)
    return text + bytes([padding] * padding)


def unpad(text):
    # Remove padding from decrypted text
    padding = text[-1]
    return text[:-padding]


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message.encode("utf-8")))
    return base64.b64encode(cipher.iv + encrypted_message).decode("utf-8")


# decrypt an AES message
def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message.encode("utf-8"))
    iv = encrypted_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]))
    return decrypted_message.decode("utf-8")


# user input

if __name__ == "__main__":
    key = generate_key()
    print("AES Encryption Program")
    user_input = input("Enter a message to encrypt: ")
    # encrypt message
    encrypted_message = encrypt_message(user_input, key)
    print("Encrypted Message:", encrypted_message)
    # Decrypt message
    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted Message:", decrypted_message)
