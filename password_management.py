import hashlib
from cryptography.fernet import Fernet
import encryptor
import os
import os.path
import ast
import json
from os import path

def encrypt_for_dict(dict_for_test):
    encryptor_ = encryptor.Encryptor()
    mykey = encryptor_.key_create()
    encryptor_.key_write(mykey, 'mykey.key')
    loaded_key = encryptor_.key_load('mykey.key')
    enc_string = encryptor_.file_encrypt(loaded_key, dict_for_test)
    return enc_string

def decrypt_for_dict(encryptor_string):
    encryptor_ = encryptor.Encryptor()
    loaded_key = encryptor_.key_load('mykey.key')
    dict_byte = encryptor_.file_decrypt(loaded_key, encryptor_string)
    dict_str = dict_byte.decode('utf-8')
    #dict_str_repr = repr(dict_str)
    dict_ori = ast.literal_eval(dict_str)
    return dict_ori

def signup():
    username = input("Enter username: ")
    pwd = input('Enter password: ')
    conf_pwd = input('Confirm password: ')
    while conf_pwd != pwd:
        print('Password is not same as above! \n')
        conf_pwd = input('Confirm password: ')
    if conf_pwd == pwd:
        enc = conf_pwd.encode()
        hash1 = hashlib.md5(enc).hexdigest()
        with open('credentials.txt', 'a') as f:
            f.write(
                'Username: ' + username + ' ' + hash1 + ' no_encryptor \n')
            #f.write(dict_user['Password_enc'] + '\n')
        f.close()
        print('You have registered successfully!')
        # return dict_user

def login():
    username = input('Enter username: ')
    with open('credentials.txt', 'r') as f:
        lines = f.readlines()
        check_user = False
        for line in lines:
            line_split = line.split(' ')
            stored_username = line_split[1]
            if username == stored_username:
                stored_pwd = line_split[2]
                enc_pwd = line_split[3]
                check_user = True
                break

        if check_user:
            count = 3
            for i in range(3):
                pwd = input('Enter password: ')
                auth = pwd.encode()
                auth_hash = hashlib.md5(auth).hexdigest()
                # print(auth_hash)
                if auth_hash == stored_pwd.strip():
                    print('Logged in Successfully!')
                    print('===============================')
                    break
                else:
                    print('Logged in failed!')
                    count = count - 1
                    print('remain chances: ', count)
        else:
            print('User doesn\'t register! \n')
            print('===============================')
    f.close()
    return username, enc_pwd, check_user


def add_password(username, enc_pwd):
    print('========== Account ', username, '===========')
    if enc_pwd != 'no_encryptor':
        dict_user = decrypt_for_dict(enc_pwd)
    else:
        dict_user = {}

    account = input('Enter Account name which you want to store: ')
    do_overwrite = True
    if account in dict_user:
        while True:
            overwrite = input('Account is already exsist, if overwrite? [y/n]: ')
            if overwrite == 'y':
                do_overwrite = True
                break
            elif overwrite == 'n':
                do_overwrite = False
                break
            else:
                print('wrong input! please input [y/n]')
                continue
    if do_overwrite:
        passwd = input('Enter Account Password: ')
        confirm_passwd = input('Enter Account Password again: ')
        while confirm_passwd != passwd:
            print('Password is not same as above! \n')
            confirm_passwd = input('Enter Account Password again: ')
        dict_user[account] = passwd

    enc_pwd_new = encrypt_for_dict(dict_user)
    print('Add password of account: '+account+' in '+username+' successfully!')

    print('########## Before add ##############')
    print(enc_pwd)
    print(type(enc_pwd))
    print('########## Before add ##############')
    print('########## After add ##############')
    print(dict_user)
    print(enc_pwd_new)
    print('########## After add ##############')
    return enc_pwd_new

def renew_enc_pwd(username, enc_pwd_new):
    print('########## Before renew ##############')
    with open('credentials.txt', 'r+') as f:   
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            line_split = line.split(' ')
            if username == line_split[1]:
                print('########## Old line ##############')
                print(line)
                print('########## Old line ##############')
                if len(line_split) == 4:
                    line_split.insert(3, str(enc_pwd_new.decode()))
                else:
                    line_split[3] = str(enc_pwd_new.decode())
                line_new = ' '.join(line_split)
                print('########## New line ##############')
                print(line_new)
                print('########## New line ##############')
                f.write(line_new)
                print('!!!!! check !!!!!')
            else:
                f.write(line)
                print('@@@@@ check @@@@')
        f.truncate()
    f.close()
    print('########## After renew ##############')
    return 


def view_password(username, enc_pwd):
    if enc_pwd != 'no_encryptor':
        dict_user = decrypt_for_dict(enc_pwd)
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

############### need change for switching account
while True:
    print("********** Password manage System **********")
    print("1.Signup")
    print("2.Login")
    print("3.Exit")
    ch = input("Enter your choice: ")
    if ch == str(1):
        signup()
    elif ch == str(2):
        if path.exists('credentials.txt') and os.path.getsize ('credentials.txt') > 0 :
            username, enc_pwd, check_user = login()
            if check_user:
                while True:
                    print("1.Store account password")
                    print("2.View account password")
                    print("3.Exit")
                    ch = input("Enter your choice: ")
                    if ch == str(1):
                        enc_pwd = add_password(username, enc_pwd)
                        renew_enc_pwd(username, enc_pwd)
                        continue
                    elif ch == str(2):
                        view_password(username, enc_pwd)
                        continue
                    elif ch == str(3):
                        break
                    else:
                        print("Wrong Choice! Please Enter correct one!")
        else:
            print('No existing user!')
    elif ch == str(3):
        break
    else:
        print("Wrong Choice! Please Enter correct one!")
