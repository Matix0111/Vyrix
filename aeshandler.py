from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import binascii
import base64
import secrets
# import os

class AESHandler:
    def __init__(self, key, mode, use_encoding=False, padding=False):
        self.use_encoding = use_encoding
        self.padding = padding
        if self.use_encoding:
            try:
                self.key = base64.b64decode(key)
            except binascii.Error:
                self.key = key
        else:
            self.key = key
        self.mode = mode
    
    @staticmethod
    def encode_data(data):
        return base64.b64encode(data).decode()
    
    @staticmethod
    def decode_data(data):
        return base64.b64decode(data).decode()

    @property
    def aes_key(self):
        if self.use_encoding:
            return base64.b64encode(self.key).decode()
        return self.key
    
    def return_cipher(self):
        return Cipher(algorithms.AES(self.key), self.mode)
    
    def return_objects(self, new_iv):
        try:
            cipher = Cipher(algorithms.AES(self.key), self.mode(new_iv))
        except TypeError:
            raise ValueError("Key is not bytes.")
        return cipher.encryptor(), cipher.decryptor()

    def pad(self, message):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        return padded_data

    def unpad(self, data):
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    
    def encrypt(self, message):
        iv = secrets.token_bytes(16)
        enc, _ = self.return_objects(iv)
        if self.padding:
            padded_data = self.pad(message)
            ciphertext = iv + enc.update(padded_data) + enc.finalize()
        else:
            error = False
            try:
                ciphertext = iv + enc.update(message.encode()) + enc.finalize()
            except ValueError as e:
                error_message = e
                error = True
            if error:
                raise ValueError(f'{error_message} Enable padding to fix this.')

        if self.use_encoding:
            return self.encode_data(ciphertext)
        return ciphertext
    
    def decrypt(self, ciphertext):
        if self.use_encoding:
            ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:16]
        real_ciphertext = ciphertext[16:]
        _, dec = self.return_objects(iv)
        
        original = dec.update(real_ciphertext) + dec.finalize()

        if self.padding:
            original = self.unpad(original)

        return original
    
    @staticmethod
    def generate_key(bit_length=256, encode = False):
        bit_convert = {
            128: 16,
            192: 24,
            256: 32
        }

        if bit_length not in bit_convert.keys():
            raise ValueError('bit length must be 128, 196, or 256')
        else:
            if encode:
                return base64.b64encode(secrets.token_bytes(bit_convert[bit_length])).decode()
            return secrets.token_bytes(bit_convert[bit_length])
    
    @staticmethod
    def generate_iv():
        return secrets.token_bytes(16)

def main():
    key = AESHandler.generate_key(encode=True)
    iv = AESHandler.generate_iv()
    print(key)
    a = AESHandler(key, modes.CBC(iv), use_encoding=True)
    enc = a.encrypt('Hello!')
    print(enc)
    dec = a.decrypt(enc)
    print(dec)
    print(a.aes_key)
    print(a.iv)

if __name__ == '__main__':
    main()