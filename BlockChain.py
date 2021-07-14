import json
import socket
import time

from AesEverywhere import aes256

import Constants
import rsa
import CA


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
    id = hash(block['PKd'] + block['PKm'] + block['receiver'])
    table[id] = block
    with open('blocks.json', 'w') as fp:
        json.dump(table, fp)

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
        rsa.verify(PKd.encode('latin') + b'&&&' + policy.encode('latin'), signature, CA.get_pub_key(Constants.TITLE_USER))
    except:
        print("Alert")
        return False
    return True


step1_connect_to_user()