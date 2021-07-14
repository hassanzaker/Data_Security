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
# with open('private_user.json', 'w') as fp:
#      json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys(Constants.TITLE_USER, publicKey)

with open('private_user.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def step5_connect_to_bank():
    s = socket.socket()
    s.bind((hostname, PORT_BANK_USER))
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


def step1_connect_to_blockchain(range, count, start_time, finish_time, receiver):
    session_key = rsa.randnum.read_random_bits(256)
    bank_pubkey = CA.get_pub_key(Constants.TITLE_BANK)
    user_pubkey = CA.get_pub_key(Constants.TITLE_USER)
    policy = range + '==' + count + '==' + start_time + '==' + finish_time + '==' + receiver
    signed = rsa.sign(bank_pubkey.save_pkcs1() + b'&&&' + policy.encode('latin'), privateKey, 'SHA-1')
    message = bank_pubkey.save_pkcs1() + b'&&&' + user_pubkey.save_pkcs1() + b'&&&' + policy.encode('latin') + b'&&&' + signed

    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(Constants.TITLE_BLOCKCHAIN))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, Constants.PORT_BLOCKCHAIN_USER))
    s.sendall(enc_data + b'&&&' + encrypted_key)

    data = s.recv(1024)
    plain = aes256.decrypt(data, session_key.decode('latin')).decode()
    ack, timeStamp, signed = plain.split('&&&')
    try:
        rsa.verify(ack.encode('latin') + b'&&&' + timeStamp.encode('latin'), signed.encode('latin'), CA.get_pub_key(Constants.TITLE_BLOCKCHAIN))
        print('OK')
    except:
        print('unauthenticated')
    s.close()


def step2or5_connect_to_seller(step):
    s = socket.socket()
    s.bind(('localhost', Constants.PORT_SELLER_USER))
    s.listen(5)
    c, addr = s.accept()
    print('Got connection from', addr)
    data = c.recv(1024)
    encrypted_record, encrypted_key = data.decode('latin').split('&&&')
    session_key = rsa.decrypt(encrypted_key.encode('latin'), privateKey)
    plain = aes256.decrypt(encrypted_record, session_key.decode('latin')).decode()
    try:
        if step == "two":
            accountID, amount, signature = plain.split('&&&')
            rsa.verify(accountID.encode('latin') + b'&&&' + amount.encode('latin'), signature.encode('latin'),
                       CA.get_pub_key(Constants.TITLE_SELLER))
            print("Success")
        elif step == "five":
            ack, signature = plain.split('&&&')
            rsa.verify(ack.encode('latin'), signature.encode('latin'), CA.get_pub_key(Constants.TITLE_SELLER))
            print("Success")
    except:
        print("Alert")
    c.close()
    s.close()


# step1_connect_to_blockchain('(1, 10)', '10', '2021/6/15', '2021/7/7', '12345678')
step2or5_connect_to_seller('two')

def step3_connect_to_bank(user_account_id, seller_account_id, amount):
    session_key = rsa.randnum.read_random_bits(256)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    temp = user_account_id + "&&&" + seller_account_id + "&&&" + str(amount)
    signed = rsa.sign(temp.encode('latin'), privateKey, 'SHA-1')
    message = temp.encode('latin') + b'&&&' + signed
    # print(temp)
    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))

    encrypted_key = rsa.encrypt(session_key, CA.get_pub_key(Constants.TITLE_BANK))

    s.connect((hostname, Constants.PORT_BANK_USER))
    s.sendall(enc_data + b'---' + encrypted_key)
    enc_data = s.recv(1024)
    data = aes256.decrypt(enc_data.decode('latin'), session_key.decode('latin')).decode('latin')
    a, b, c, d = data.split('&&&')
    if b == user_account_id and c == seller_account_id and d == str(amount):
        nance = int(a) + 1
        enc_data = aes256.encrypt(str(nance), session_key.decode('latin'))
        s.sendall(enc_data)
        print('ok')

    s.close()

step3_connect_to_bank('87654321', '12345678', 100000)
# step1_connect_to_blockchain('(1, 10)', '10', '2021/6/15', '2021/7/7', '12345678')