import json
import socket
import Constants
import rsa
import CA


(publicKey, privateKey) = rsa.newkeys(512)
with open('private_blockChain.json', 'w') as fp:
     json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
CA.add_keys(Constants.TITLE_BLOCKCHAIN, publicKey)

with open('private_blockChain.json', 'r') as fp2:
    table2 = json.load(fp2)
privateKey = rsa.pkcs1.key.PrivateKey(table2['list'][0], table2['list'][1], table2['list'][2], table2['list'][3],
                                      table2['list'][4])

with open('blocks.json', 'r') as fp:
    table = json.load(fp)


def add_block(block):
    table[len(table)] = block
    with open('blocks.json', 'w') as fp:
        json.dump(table, fp)


def connect_to_user():
    s = socket.socket()
    s.bind(('localhost', Constants.PORT_BLOCKCHAIN_USER))
    s.listen(5)
    c, addr = s.accept()
    print('Got connection from', addr)
    data = c.recv(1024)
    encrypted_record = data.decode('latin')
    decrypted_record = rsa.decrypt(encrypted_record.encode('latin'), privateKey)
    print(decrypted_record)
    PKd, PKm, policy, signature = decrypted_record.split()
    if validation_of_delegation(PKd, policy, signature):
        rng, count, sTime, fTime, receiver = policy.split('-')
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


def validation_of_delegation(PKd, policy, signature):
    rsa.sign(PKd + policy, privateKey, 'SHA-1')
    try:
        rsa.verify(PKd + policy, signature, publicKey)
    except:
        print("Alert")
    return True

