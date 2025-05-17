import argparse
import os
import binascii
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# AES encryption function
def aes_encrypt(message, key):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message

# AES decryption function
def aes_decrypt(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

# Convert bytes to binary string
def bytes_to_binary(data):
    return ''.join(format(byte, '08b') for byte in data)

# Convert binary string to bytes
def binary_to_bytes(binary_str):
    byte_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return bytes(int(b, 2) for b in byte_list)

# Hide message in image
def hide_message(image_path, message_bytes, output_path):
    binary_message = bytes_to_binary(message_bytes) + '1111111111111110'
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    pixel_index = 0

    for row in range(height):
        for col in range(width):
            if pixel_index >= len(binary_message):
                break
            pixel = list(pixels[col, row])
            for i in range(3):
                if pixel_index < len(binary_message):
                    pixel[i] = (pixel[i] & 0xFE) | int(binary_message[pixel_index])
                    pixel_index += 1
            pixels[col, row] = tuple(pixel)
        if pixel_index >= len(binary_message):
            break

    img.save(output_path)
    print(f"[+] Message hidden in '{output_path}' successfully.")

# Extract message from image
def extract_message(image_path):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    binary_message = ''

    for row in range(height):
        for col in range(width):
            pixel = pixels[col, row]
            for i in range(3):
                binary_message += str(pixel[i] & 1)

    binary_message = binary_message.split('1111111111111110', 1)[0]
    return binary_to_bytes(binary_message)

# Argument parser setup
def parse_args():
    parser = argparse.ArgumentParser(description="AES + LSB Steganography Tool")
    parser.add_argument('--mode', choices=['hide', 'extract'], required=True, help="Mode: hide or extract a message")
    parser.add_argument('--image', required=True, help="Path to the input image")
    parser.add_argument('--message', help="Message to hide (required in hide mode)")
    parser.add_argument('--output', help="Path to save the output image (required in hide mode)")
    return parser.parse_args()

def main():
    args = parse_args()
    key = os.urandom(32)

    if args.mode == 'hide':
        if not args.message:
            print("[-] Error: --message is required in hide mode.")
            return
        if not args.output:
            print("[-] Error: --output is required in hide mode.")
            return
        encrypted = aes_encrypt(args.message, key)
        hide_message(args.image, encrypted, args.output)
        print(f"[+] AES Key (save this to decrypt): {binascii.hexlify(key).decode()}")

    elif args.mode == 'extract':
        encrypted_bytes = extract_message(args.image)
        hex_key = input("[?] Enter the AES key used for encryption (hex format): ")
        try:
            key = binascii.unhexlify(hex_key.strip())
            message = aes_decrypt(encrypted_bytes, key)
            print(f"[+] Decrypted message: {message}")
        except Exception as e:
            print(f"[-] Failed to decrypt message: {e}")

if __name__ == '__main__':
    main()
