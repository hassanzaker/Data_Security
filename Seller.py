import json
import socket
import ssl
import time
import Constants
import rsa
from AesEverywhere import aes256
from aes_cipher import DataDecrypter

import CA

hostname = 'localhost'
# (publicKey, privateKey) = rsa.newkeys(512)
# with open('private_seller.json', 'w') as fp:
#      json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys(Constants.TITLE_SELLER, publicKey)

with open('private_seller.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def step2_connect_to_user(accountID, amount):
    session_key = rsa.randnum.read_random_bits(256)
    signed = rsa.sign(accountID.encode('latin') + b'&&&' + amount.encode('latin'), privateKey, 'SHA-1')
    message = accountID.encode('latin') + b'&&&' + amount.encode('latin') + b'&&&' + signed
    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(Constants.TITLE_USER))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, Constants.PORT_SELLER_USER))
    s.sendall(enc_data + b'&&&' + encrypted_key)
    s.close()


def step5_connect_to_user():
    session_key = rsa.randnum.read_random_bits(256)
    ack = 'transaction has been successfully done'
    signed = rsa.sign(ack.encode('latin'), privateKey, 'SHA-1')
    message = ack.encode('latin') + b'&&&' + signed
    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(Constants.TITLE_USER))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, Constants.PORT_SELLER_USER))
    s.sendall(enc_data + b'&&&' + encrypted_key)
    s.close()


def step5_connect_to_bank():
    s = socket.socket()
    s.bind((hostname, Constants.PORT_BANK_SELLER))
    s.listen(5)

    c, addr = s.accept()
    print('Connected by', addr)
    data = c.recv(1024)
    enc_data, enc_key = data.decode('latin').split('---')

    key = rsa.decrypt(enc_key.encode('latin'), privateKey)

    plain = aes256.decrypt(enc_data, key.decode('latin')).decode()
    ack, timestamp, signature = plain.split('---')
    message = ack + '---' + timestamp


    try:
        isVerified = rsa.verify(message.encode('latin'), signature.encode('latin'), CA.get_pub_key(Constants.TITLE_BANK))
        print(ack)
    except:
        print('unauthenticated person')


step2_connect_to_user('123', '1000')
