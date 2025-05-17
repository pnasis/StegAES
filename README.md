# StegAES: AES-Encrypted LSB Image Steganography Tool

**StegAES** is a Python-based steganography tool that hides encrypted text messages inside image files using the Least Significant Bit (LSB) technique. It combines **AES-256 encryption** with **image-based steganography**, providing confidentiality and covertness in a single solution.

---

## How It Works

### 1. **AES Encryption**
Before hiding the message in an image, the tool encrypts it using the **AES algorithm in CBC mode** with a randomly generated 256-bit key. This ensures that even if the message is extracted, it remains unreadable without the correct key.

- Uses `PKCS7` padding.
- The AES key and IV are randomly generated.
- Encrypted output = `IV + Ciphertext`.

### 2. **LSB Steganography**
The encrypted message (in bytes) is converted to a binary string and embedded in the **least significant bits of each pixel's RGB values**.

- 1 bit per color channel → 3 bits per pixel.
- A **binary delimiter** `1111111111111110` is used to mark the end of the hidden message.

### 3. **Message Extraction**
To extract the message:
- Traverse all pixels to collect LSBs.
- Stop at the binary delimiter.
- Reconstruct encrypted bytes.
- Decrypt using the AES key to retrieve the original message.

---

## Features

- ✅ AES-256 encryption
- ✅ LSB image steganography
- ✅ Embed or extract message via command-line options
- ✅ Works with PNG and other uncompressed image formats
- ✅ Does **not** visibly distort the image

---

## Installation

### 1. Clone the repository:
```bash
git clone https://github.com/pnasis/StegAES.git
cd StegAES
```

### 2. Install dependencies:

Make sure you have Python 3 installed, then install the required libraries:
```bash
pip install -r requirements.txt
```
```requirements.txt```
```
cryptography
Pillow
```

---

## 🚀 Usage

The tool can be used in **two modes:** `hide` and `extract`.

### 🔐 Hide a Message
```bash
python steg_aes.py --mode hide --image input.png --message "Your secret message" --output stego_image.png
```

**Arguments:**

- `--mode hide` — Use hide mode
- `--image input.png` — Path to the input image
- `--message "..."` — Message to encrypt and hide
- `--output stego_image.png` — Path to save the modified image

You’ll get an output like:
```bash
[+] Message hidden in 'stego_image.png' successfully.
[+] AES Key (save this to decrypt): 6c9f4a7b13e5... (hex)
```
Save the key printed to decrypt the message later.

---

### 🔓 Extract a Message
```bash
python steg_aes.py --mode extract --image stego_image.png
```

You’ll be prompted to input the AES key in hex format:
```bash
[?] Enter the AES key used for encryption (hex format): 6c9f4a7b13e5...
```

If successful:
```bash
[+] Decrypted message: Your secret message
```

---

## 📌 Notes

- Use **uncompressed formats like PNG** for best results. JPEG may cause data loss.
- The tool prints the AES key to standard output — it is **your responsibility to securely store or share it**.

---

## 🛡️ Security Considerations

- This tool combines confidentiality (AES) with steganographic secrecy (LSB).
- Extraction alone does not compromise the message — AES encryption provides a second layer of defense.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.
