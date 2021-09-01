import configparser
import bcrypt
import aeshandler
import base64
import hashlib
from cryptography.fernet import *

conf = configparser.ConfigParser()

def encryptValues(fKey, decrypted_values):
    encVals = []
    for value in decrypted_values:
        encVals.append(fKey.encrypt(value.encode()).decode())
    
    return encVals

def get_new_aes_key(passwd):
    def create_salt(password: bytes):
        if type(password) != bytes:
            raise ValueError('Password must be in byte form.')
        password_hash = hashlib.sha3_256(password).hexdigest()
        return f'${password_hash[:6]}$${password_hash[6:12]}$'.encode()

    kdf = bcrypt.kdf(
        password=passwd,
        salt=create_salt(passwd),
        desired_key_bytes=32,
        rounds=50
    )

    return kdf

def get_new_f_key(passwd, newsalt):
    kdf = bcrypt.kdf(
        password=passwd,
        salt=newsalt,
        desired_key_bytes=32,
        rounds=50
    )

    return kdf

def update_ini(newValues, newSalt, aes_key):
    a = aeshandler.AESHandler(aes_key, aeshandler.modes.CBC, use_encoding=True, padding=True)
    conf['UNLOCK']['salt'] = a.encrypt(newSalt.decode())
    for key, value in zip(conf['AUTH'], newValues):
        conf['AUTH'][key] = value
    
    with open('auth.ini', 'w') as f:
        conf.write(f)

def decryptVals(f):
    vals = []
    for _, value in conf['AUTH'].items():
        vals.append(f.decrypt(value.encode()).decode())
    
    return vals

def generate_salt():
    salt = ""
    for _ in range(3):
        salt += bcrypt.gensalt(16).decode()[7:]
    return salt.encode()

def clean(f, passwd, path):
    conf.read(path)
    new_salt = generate_salt()
    vals = decryptVals(f)
    kdf_key = get_new_f_key(passwd, new_salt)
    aes_key = get_new_aes_key(passwd)
    f = Fernet(base64.urlsafe_b64encode(kdf_key))
    encrypted = encryptValues(f, vals)
    update_ini(encrypted, new_salt, aes_key)