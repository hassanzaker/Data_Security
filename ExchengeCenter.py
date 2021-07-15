import random
import socket
import ssl
import rsa
import rsa.randnum
import json
from Constants import PORT_BANK_USER

from AesEverywhere import aes256

import CA
import Constants

hostname = 'localhost'

# publicKey, privateKey = rsa.newkeys(512)
# with open('private_exchange_center.json', 'w') as fp:
#      json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys(Constants.TITLE_EXCHANGE_CENTER, publicKey)

with open('private_exchange_center.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def price(amount):
    return amount * random.random()


def step4_connect_to_bank():
    s = socket.socket()
    s.bind((hostname, Constants.PORT_EXCHANGE_BANK))
    s.listen(5)

    c, addr = s.accept()
    print('Connected by', addr)
    data = c.recv(1024)

    enc_data, enc_key = data.decode('latin').split('---')

    session_key = rsa.decrypt(enc_key.encode('latin'), privateKey)

    plain = aes256.decrypt(enc_data, session_key.decode('latin')).decode()

    amount, nonce, signature = plain.split('&&&')
    amount = int(amount)
    nonce = int(nonce)
    message = str(amount) + "&&&" + str(nonce)
    try:
        rsa.verify(message.encode('latin'), signature.encode('latin'), CA.get_pub_key(Constants.TITLE_BANK))
    except:
        print('unauthenticated')
        return
    crypto_amount = price(amount)
    message = str(crypto_amount) + '&&&' + str(nonce + 1)
    message = message.encode('latin')
    signature = rsa.sign(message, privateKey, 'SHA-1')
    message = message + b'&&&' + signature
    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))

    c.sendall(enc_data)
    enc_data = c.recv(1024)

    plain = aes256.decrypt(enc_data, session_key.decode('latin')).decode()

    sender_account_id, receiver_account_id, crypto_amount, new_nonce, sign1, signature = plain.split('&&&')
    new_nonce = int(new_nonce)
    message = sender_account_id + '&&&' + receiver_account_id + '&&&' + crypto_amount + '&&&' + str(new_nonce)
    if nonce + 2 == new_nonce:
        try:
            rsa.verify(message.encode('latin'), sign1.encode('latin'),
                       CA.get_pub_key(Constants.TITLE_BANK))
        except:
            print('unauthenticated')
            return
    else:
        print('unauthenticated')
        return

    message = sender_account_id + '&&&' + receiver_account_id + '&&&' + crypto_amount + '&&&' + signature + '&&&' + str(nonce + 3)
    signed = rsa.sign(message.encode('latin'), privateKey, 'SHA-1')
    message = message.encode('latin') + b'&&&' + signed

    session_key2 = rsa.randnum.read_random_bits(256)

    enc_data = aes256.encrypt(message.decode('latin'), session_key2.decode('latin'))

    encrypted_key = rsa.encrypt(session_key2, CA.get_pub_key(Constants.TITLE_BLOCKCHAIN))

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((hostname, Constants.PORT_EXCHANGE_BLOCKCHAIN))
    s2.sendall(enc_data + b'---' + encrypted_key)
    data = s2.recv(1024)

    plain = aes256.decrypt(data, session_key2.decode('latin')).decode()
    sign1, new_nonce, sign2 = plain.split('&&&')
    message = sign1 + '&&&' + new_nonce
    new_nonce = int(new_nonce)
    if new_nonce == nonce + 4:
        try:
            rsa.verify(message.encode('latin'), sign2.encode('latin'), CA.get_pub_key(Constants.TITLE_BLOCKCHAIN))
        except:
            print('unauthenticated')
            return
    else:
        print('unauthenticated')
        return

    message = sign1 + '&&&' + receiver_account_id + '&&&' + str(amount)
    signed = rsa.sign(message.encode('latin'), privateKey, 'SHA-1')
    message = message.encode('latin') + b'&&&' + signed

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    c.sendall(enc_data)

    c.close()
    s.close()




step4_connect_to_bank()
