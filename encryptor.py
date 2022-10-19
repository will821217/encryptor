from cryptography.fernet import Fernet
import json
import ast


class Encryptor():

    def key_create(self):
        key = Fernet.generate_key()
        return key

    def key_write(self, key, key_name):
        with open(key_name, 'wb') as mykey:
            mykey.write(key)

    def key_load(self, key_name):
        with open(key_name, 'rb') as mykey:
            key = mykey.read()
        return key

    def file_encrypt_bk(self, key, original_file, encrypted_file):

        f = Fernet(key)

        with open(original_file, 'rb') as file:
            original = file.read()

        encrypted = f.encrypt(original)

        with open(encrypted_file, 'ab') as file:
            file.write(encrypted)

    def file_decrypt_bk(self, key, encrypted_file, decrypted_file):
        with open(encrypted_file, 'rb') as file:
            encrypted = file.read()

        decrypted = file.decrypt(encrypted)
        with open(decrypted_file, 'ab') as file:
            file.write(decrypted)

    ###################################################

    def file_encrypt(self, key, dict_for_test):
        encode_dict = json.dumps(dict_for_test, sort_keys=True, indent=2).encode('utf-8')
        f = Fernet(key)
        encrypted = f.encrypt(encode_dict)
        return encrypted

    def file_decrypt(self, key, encrypted_string):
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_string)
        return decrypted
