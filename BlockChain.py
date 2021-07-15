import json
import socket
import time
import datetime
from AesEverywhere import aes256

import Constants
import rsa
import CA

hostname = 'localhost'

# (publicKey, privateKey) = rsa.newkeys(512)
# with open('private_blockChain.json', 'w') as fp:
#      json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
# CA.add_keys(Constants.TITLE_BLOCKCHAIN, publicKey)

with open('private_blockChain.json', 'r') as fp2:
    table2 = json.load(fp2)
privateKey = rsa.pkcs1.key.PrivateKey(table2['list'][0], table2['list'][1], table2['list'][2], table2['list'][3],
                                      table2['list'][4])

with open('blocks.json', 'r') as fp:
    table = json.load(fp)


def add_block(block):
    id = int.from_bytes(str(block['PKd'] + block['PKm'] + block['receiver']).encode('latin'), 'big') % 1000000

    table[id] = block
    with open('blocks.json', 'w') as fp:
        json.dump(table, fp)


def do_exchange(receiver, crypto_amount):
    bank_pubkey = CA.get_pub_key(Constants.TITLE_BANK).save_pkcs1()
    user_pubkey = CA.get_pub_key(Constants.TITLE_USER).save_pkcs1()
    id = int.from_bytes(bank_pubkey + user_pubkey + receiver.encode(), 'big') % 1000000
    id = str(id)
    block = table[id]
    rang_floor, rang_ceil = map(int, block['range'].split(','))
    rang_ceil = int(rang_ceil)
    rang_floor = int(rang_floor)
    sTime = datetime.datetime(year=int(block['sTime'].split('-')[0]),
                              month=int(block['sTime'].split('-')[1]),
                              day=int(block['sTime'].split('-')[2]))
    fTime = datetime.datetime(year=int(block['fTime'].split('-')[0]),
                              month=int(block['fTime'].split('-')[1]),
                              day=int(block['fTime'].split('-')[2]))
    current = datetime.datetime.now()
    count = int(block['count'])
    if count > 0 and sTime < current < fTime and rang_floor < crypto_amount < rang_ceil:
        #  do trade
        table[id]['count'] = str(int(table[id]['count']) - 1)
        with open('blocks.json', 'w') as fp:
            json.dump(table, fp)
        return True
    else:
        return False


def step1_connect_to_user():
    s = socket.socket()
    s.bind(('localhost', Constants.PORT_BLOCKCHAIN_USER))
    s.listen(5)
    c, addr = s.accept()
    print('Got connection from', addr)
    data = c.recv(1024)
    encrypted_record, encrypted_key = data.decode('latin').split('&&&')
    session_key = rsa.decrypt(encrypted_key.encode('latin'), privateKey)

    plain = aes256.decrypt(encrypted_record, session_key.decode('latin')).decode()
    PKd, PKm, policy, signature = plain.split('&&&')
    signature = signature.encode('latin')

    if validation_of_delegation(PKd, policy, signature):
        rng, count, sTime, fTime, receiver = policy.split('==')
        block = {
            'PKd': PKd,
            'PKm': PKm,
            'range': rng,
            'count': count,
            'sTime': sTime,
            'fTime': fTime,
            'receiver': receiver
        }
        add_block(block)
        ack = 'delegation has been added to block chain'
        timeStamp = str(time.time())
        signed = rsa.sign(ack.encode('latin') + b'&&&' + timeStamp.encode('latin'), privateKey, 'SHA-1')

        message = ack + "&&&" + timeStamp + "&&&" + signed.decode('latin')

        enc_data = aes256.encrypt(message, session_key.decode('latin'))
        c.sendall(enc_data)
        c.close()


def validation_of_delegation(PKd, policy, signature):
    try:
        rsa.verify(PKd.encode('latin') + b'&&&' + policy.encode('latin'), signature,
                   CA.get_pub_key(Constants.TITLE_USER))
    except:
        print("Alert")
        return False
    return True


def step4_conncet_to_exchange():
    s = socket.socket()
    s.bind((hostname, Constants.PORT_EXCHANGE_BLOCKCHAIN))
    s.listen(5)

    c, addr = s.accept()
    print('Connected by', addr)
    data = c.recv(1024)

    enc_data, enc_key = data.decode('latin').split('---')

    session_key = rsa.decrypt(enc_key.encode('latin'), privateKey)

    plain = aes256.decrypt(enc_data, session_key.decode('latin')).decode()

    sender_account, receiver_account, crypto_amount, signature, nonce, sign = plain.split('&&&')
    message = sender_account + '&&&' + receiver_account + '&&&' + crypto_amount + '&&&' + signature + '&&&' + nonce
    nonce = int(nonce)
    try:
        rsa.verify(message.encode('latin'), sign.encode('latin'), CA.get_pub_key(Constants.TITLE_EXCHANGE_CENTER))
    except:
        print('unauthenticated')
        return

    if do_exchange(receiver_account, float(crypto_amount)):
        ack = 'exchange done'
    else:
        ack = 'invalid input'

    enc_ack = rsa.encrypt(ack.encode('latin'), CA.get_pub_key(Constants.TITLE_BANK))
    message = enc_ack.decode('latin') + '&&&' + str(nonce + 1)
    signed = rsa.sign(message.encode('latin'), privateKey, 'SHA-1')
    message = message.encode('latin') + b'&&&' + signed


    enc_data = aes256.encrypt(message.decode('latin'), session_key.decode('latin'))
    c.sendall(enc_data)

    # c.close()
    # s.close()


# step1_connect_to_user()
step4_conncet_to_exchange()
