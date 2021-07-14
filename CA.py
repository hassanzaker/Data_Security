import json
import rsa

with open('certificates.json', 'r') as fp:
    table = json.load(fp)

def add_keys(id, publicKey):
    table[id] = [publicKey.n, publicKey.e]
    with open('certificates.json', 'w') as fp:
        json.dump(table, fp)


def get_pub_key(id):
    return rsa.pkcs1.key.PublicKey(table[id][0], table[id][1])