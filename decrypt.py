import argparse
import hashlib
import binascii
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad


def decrypt(encrypted_password, password_key):

    sha1_key = hashlib.sha1(password_key.encode()).digest() # sha1 hash of the passwordKey
    encrypted_password_bytes = binascii.unhexlify(encrypted_password) # hex to bytes

    iv_size = Blowfish.block_size
    iv = encrypted_password_bytes[:iv_size] # the first 8 bytes of the encrypted password is the initialization vector
    ciphertext = encrypted_password_bytes[iv_size:] # the actual encrypted password

    cipher = Blowfish.new(sha1_key, Blowfish.MODE_CBC, iv)
    decrypted_password_bytes = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    decrypted_password = decrypted_password_bytes.decode('utf-8')

    return decrypted_password


def main():
    parser = argparse.ArgumentParser(description="Decrypt Openfire Passwords")
    parser.add_argument('-p', '--password', help='The encryptedPassword in OFUSER',required=True)
    parser.add_argument("-k", "--key", help="The passwordKey in OFPROPERTY", required=True)
    args = parser.parse_args()

    encrypted_password = args.password
    password_key = args.key
    print("[+] encrypted password:", encrypted_password)
    print("[+] password key", password_key)

    try:
        decrypted_password = decrypt(encrypted_password, password_key)
        print("[+] decrypted password:", decrypted_password)

    except Exception as e:
        print("[-] an error occurred during decryption:", str(e))


if __name__ == "__main__":
    main()