import json
import socket
import ssl
import time

import rsa
from AesEverywhere import aes256
from aes_cipher import DataDecrypter

import CA

hostname = 'localhost'
# (publicKey, privateKey) = rsa.newkeys(512)
# with open('private_seller.json', 'w') as fp:
#      json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys('seller', publicKey)

with open('private_seller.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def step5_connect_to_bank():
    s = socket.socket()
    s.bind((hostname, 2222))
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
        isVerified = rsa.verify(message.encode('latin'), signature.encode('latin'), CA.get_pub_key('bank'))
        print(ack)
    except:
        print('unauthenticated person')

step5_connect_to_bank()
