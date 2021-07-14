import socket
import ssl
import rsa
import json
import CA
import Constants

publicKey, privateKey = rsa.newkeys(512)
with open('private_user.json', 'w') as fp:
     json.dump({'list': [privateKey.n, privateKey.e, privateKey.d, privateKey.p, privateKey.q]}, fp)
CA.add_keys(Constants.TITLE_USER, publicKey)

with open('private_user.json', 'r') as fp:
    table = json.load(fp)

privateKey = rsa.pkcs1.key.PrivateKey(table['list'][0], table['list'][1], table['list'][2], table['list'][3],
                                      table['list'][4])


def connect_to_blockchain():
    pass
