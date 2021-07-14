import json
import socket
import ssl
import time
import rsa.randnum
from AesEverywhere import aes256


import CA
import Constants
import rsa

hostname = 'localhost'
ackForSeller = 'hiiii'
# (publicKey, privateKey) = rsa.newkeys(512)
# with open('private_bank.json', 'w') as fp:
#     json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys('bank', publicKey)

with open('private_bank.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def connect_to_seller():
    timeStamp = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    message = ackForSeller + '---' + str(time.time())
    message = message.encode('latin')
    message += '---'.encode('latin') + rsa.sign(message, privateKey, 'SHA-1')
    session_key = rsa.randnum.read_random_bits(256)

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))

    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key('seller'))
    s.connect((hostname, Constants.PORT_BANK_SELLER))
    s.sendall(enc_data + b'---' + encrypted_key)
    s.close()

connect_to_seller()