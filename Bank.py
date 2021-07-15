import json
import random
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
# CA.add_keys(Constants.TITLE_BANK, publicKey)

with open('private_bank.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def step5_send_ack(port, receiver):
    timeStamp = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    message = ackForSeller + '---' + str(timeStamp)
    message = message.encode('latin')
    message += '---'.encode('latin') + rsa.sign(message, privateKey, 'SHA-1')
    session_key = rsa.randnum.read_random_bits(256)

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(receiver))
    s.connect((hostname, port))
    s.sendall(enc_data + b'---' + encrypted_key)
    s.close()


def step3_connect_to_user():
    s = socket.socket()
    s.bind((hostname, Constants.PORT_BANK_USER))
    s.listen(5)

    c, addr = s.accept()
    print('Connected by', addr)
    data = c.recv(1024)

    enc_data, enc_key = data.decode('latin').split('---')

    session_key = rsa.decrypt(enc_key.encode('latin'), privateKey)

    plain = aes256.decrypt(enc_data, session_key.decode('latin')).decode()
    user_account_id, seller_account_id, amount, signed = plain.split('&&&')
    message = user_account_id + '&&&' + seller_account_id + '&&&' + amount
    try:
        rsa.verify(message.encode('latin'), signed.encode('latin'), CA.get_pub_key('user'))
    except:
        print('unauthenticated')
        return
    nance = random.randint(1, 10000000)
    message = str(nance) + '&&&' + message

    enc_data = aes256.encrypt(message, session_key.decode('latin'))
    c.sendall(enc_data)
    enc_data = c.recv(1024)
    new_nance = int(aes256.decrypt(enc_data.decode('latin'), session_key.decode('latin')))
    if new_nance == nance + 1:
        print('OK')
        ## do what is needed
    c.close()
    s.close()


def step4_connect_to_exchange(sender_account_id, receiver_account_id, amount):
    nonce = random.randint(1, 10000000)
    message = str(amount) + "&&&" + str(nonce)
    signed = rsa.sign(message.encode('latin'), privateKey, 'SHA-1')
    message = message.encode('latin') + b'&&&' + signed

    session_key = rsa.randnum.read_random_bits(256)

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))

    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(Constants.TITLE_EXCHANGE_CENTER))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, Constants.PORT_EXCHANGE_BANK))
    s.sendall(enc_data + b'---' + encrypted_key)

    enc_data = s.recv(1024)
    plain = aes256.decrypt(enc_data, session_key.decode('latin')).decode()

    crypto_amount, new_nonce, signature = plain.split('&&&')
    new_nonce = int(new_nonce)
    message = crypto_amount + '&&&' + str(new_nonce)
    if nonce + 1 == new_nonce:
        try:
            rsa.verify(message.encode('latin'), signature.encode('latin'),
                       CA.get_pub_key(Constants.TITLE_EXCHANGE_CENTER))
        except:
            print('unauthenticated')
            return
    else:
        print('unauthenticated')
        return

    message1 = sender_account_id + '&&&' + receiver_account_id + '&&&' + crypto_amount

    signed1 = rsa.sign(message1.encode('latin'), privateKey, 'SHA-1')
    message2 = message1 + '&&&' + str(nonce + 2)
    signed2 = rsa.sign(message2.encode('latin'), privateKey, 'SHA-1')
    message = message2.encode('latin') + b'&&&' + signed2 + b'&&&' + signed1

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))

    s.sendall(enc_data)

    data = s.recv(1024)
    data = aes256.decrypt(data, session_key.decode('latin')).decode()
    enc_ack, receiver_account_id, amount, sign = data.split('&&&')
    ack = rsa.decrypt(enc_ack.encode('latin'), privateKey).decode()
    message = enc_ack + '&&&' + receiver_account_id + '&&&' + amount
    try:
        rsa.verify(message.encode('latin'), sign.encode('latin'), CA.get_pub_key(Constants.TITLE_EXCHANGE_CENTER))
    except:
        print('unauthenticated')
        return
    print(ack)

    s.close()

# step5_send_ack(Constants.PORT_BANK_SELLER, 'seller')
# step5_send_ack(Constants.PORT_BANK_USER, 'user')
# step3_connect_to_user(
step4_connect_to_exchange('87654321', '12345678', 1000)
