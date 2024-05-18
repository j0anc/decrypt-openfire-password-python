# Decrypt Openfire Password
This Python script decrypts Openfire passwords.

To use this script, you need to provide both the encrypted password and the password key. The password key can be found in the OFPROPERTY table. The SHA1-hashed password key is used as the Blowfish CBC key for encrypting the password, so it is essential for decryption.

**Example**
```
python3 decrypt.py -p encrypted_password -k password_key
```
This scirpt was created for a CTF challenge, so it might not work in every situation. Use it at your own risk!
