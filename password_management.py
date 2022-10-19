import os
import ast
import getpass
import hashlib
import encryptor
from cryptography.fernet import Fernet

def encrypt_for_dict(dict_user):
    encryptor_ = encryptor.Encryptor()
    mykey = encryptor_.key_create()
    encryptor_.key_write(mykey, 'mykey.key')
    loaded_key = encryptor_.key_load('mykey.key')
    enc_dict_byte = encryptor_.file_encrypt(loaded_key, dict_user)
    return enc_dict_byte

def decrypt_for_dict(enc_dict_str):
    encryptor_ = encryptor.Encryptor()
    loaded_key = encryptor_.key_load('mykey.key')
    dec_dict_byte = encryptor_.file_decrypt(loaded_key, enc_dict_str)
    dec_dict_str = dec_dict_byte.decode('utf-8')
    dict_ori = ast.literal_eval(dec_dict_str)
    return dict_ori

def signup():
    with open(user_info_txt, 'a+') as file:
        file.seek(0)
        lines = file.readlines()
        username_check = True
        while username_check:
            username = input("Enter username: ")
            if lines:
                for index, line in enumerate(lines):
                    line_split = line.split(' ')
                    if username == line_split[1]:
                        print('This username has already used!!!')
                        break
                    elif index == len(lines)-1:
                        username_check = False
                        break
            else:
                break
        user_pwd = getpass.getpass("Enter password: ")
        while True:
            conf_pwd = getpass.getpass("Confirm password: ")
            if conf_pwd != user_pwd:
                print('Password is not the same as previous! \n')
            else:
                break
        enc_user_pwd = user_pwd.encode()
        md5_enc_user_pwd = hashlib.md5(enc_user_pwd).hexdigest()
        file.write('Username: '+username+' '+md5_enc_user_pwd+' no_encryptor \n')
        print('You have registered successfully!')

def login():
    username = input('Enter username: ')
    with open(user_info_txt, 'a+') as file:
        file.seek(0)
        lines = file.readlines()
        check_user = False
        for line in lines:
            line_split = line.split(' ')
            enc_dict_str = line_split[3]
            if username == line_split[1]:
                md5_enc_user_pwd = line_split[2]
                check_user = True
                break
        if check_user:
            count = 3
            while True:
                login_pwd = getpass.getpass("Enter password: ")
                enc_login_pwd = login_pwd.encode()
                md5_enc_login_pwd = hashlib.md5(enc_login_pwd).hexdigest()
                if md5_enc_login_pwd == md5_enc_user_pwd:
                    print('Logged in successfully!')
                    print('===============================')
                    break
                elif count == 0:
                    check_user = False
                    print('Logged in failed!')
                    print('===============================')
                    break
                else:
                    print('Wrong password')
                    print('Remain chances: ', count)
                    count -= 1
        else:
            print('User doesn\'t register!')
            print('===============================')
    return username, enc_dict_str, check_user


def add_password(username, enc_dict_str):
    print('========== Account ', username, '===========')
    if enc_dict_str != 'no_encryptor':
        dict_user = decrypt_for_dict(enc_dict_str.encode())
    else:
        dict_user = {}
    account = input('Enter account name which you want to store in: ')
    add_new_pwd = True
    if account in dict_user:
        while True:
            overwrite = input('Account is already exsist, if overwrite? [y/n]: ')
            if overwrite == 'y':
                break
            elif overwrite == 'n':
                add_new_pwd = False
                break
            else:
                print('wrong input! please input [y/n]')
                continue
    if add_new_pwd:
        account_pwd = getpass.getpass("Enter account password: ")
        while True:
            confirm_pwd = getpass.getpass("Confirm account password: ")
            if confirm_pwd != account_pwd:
                print('Password is not the same as previous!')
            else:
                dict_user[account] = account_pwd
                break
        enc_dict_byte = encrypt_for_dict(dict_user)
        enc_dict_str_new = str(enc_dict_byte.decode())
        print('Add password of account: '+account+' in '+username+' successfully!')
        with open(user_info_txt, 'r+') as file:
            lines = file.readlines()
            file.seek(0)
            for line in lines:
                line_split = line.split(' ')
                if username == line_split[1]:
                    line_split[3] = enc_dict_str_new
                    line_new = ' '.join(line_split)
                    file.write(line_new)
                else:
                    file.write(line)
            file.truncate()
    else:
        print('No new account and password are added!')
    return username, enc_dict_str_new

def view_password(username, enc_dict_str):
    if enc_dict_str != 'no_encryptor':
        print(enc_dict_str)
        print(enc_dict_str.encode())
        dict_user = decrypt_for_dict(enc_dict_str.encode())
        print('##########')
        print(username)
        count = 0
        for key in dict_user:
            count += 1
            print('*** '+str(count)+' ***')
            print('Account: ' + key)
            print('Password: ' + dict_user[key])
            print('*********')
        print('##########')
    else:
        print('User', username, 'doesn\'t store any account!')

if __name__ == '__main__':
    user_info_txt = 'user_encryption.txt'
    while True:
        print("********** Password managment system **********")
        print("1.Signup")
        print("2.Login")
        print("3.Exit")
        choice = input("Enter your choice: ")
        if choice == str(1):
            signup()
        elif choice == str(2):
            if os.path.exists(user_info_txt) and os.path.getsize (user_info_txt) > 0 :
                username, enc_dict_str, check_user = login()
                if check_user:
                    while True:
                        print('Welcome, '+username+'. How may I help you?')
                        print("1.Store account password")
                        print("2.View account password")
                        print("3.Exit")
                        choice = input("Enter your choice: ")
                        if choice == str(1):
                            username, enc_dict_str  = add_password(username, enc_dict_str)
                            continue
                        elif choice == str(2):
                            view_password(username, enc_dict_str)
                            continue
                        elif choice == str(3):
                            break
                        else:
                            print("Wrong choice! Please enter correct one!")
            else:
                print('No existing user!')
        elif choice == str(3):
            break
        else:
            print("Invalid choice number! Please enter 1 or 2 or 3 !")

