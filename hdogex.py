#!/usr/bin/env python

import argparse
import base64
import hashlib
import hmac
from hashlib import md5
from typing import List, Tuple

import base58
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

from wallet_pb2 import Wallet


def derive_key_and_iv(password: str, salt: bytes, key_len: int, iv_len: int) -> Tuple[bytes, bytes]:
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = md5(d_i + password.encode() + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def get_wallet(filename: str, password: str) -> Wallet:
    with open(filename, 'rb') as f:
        data = base64.b64decode(f.read())
        assert data[:8] == b'Salted__'
        salt = data[8:16]
        key, iv = derive_key_and_iv(password, salt, 32, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plain = cipher.decrypt(data[AES.block_size:])
        pad_len = padded_plain[-1]

        if isinstance(pad_len, str):
            pad_len = ord(pad_len)

        w = Wallet()
        w.ParseFromString(padded_plain[:-pad_len])
        return w


def ripemd160(payload: bytes) -> bytes:
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(payload).digest())
    return h1.digest()


def sha256x2(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()


def base58_encode(payload: bytes) -> str:
    return base58.b58encode(payload).decode('utf-8')


def base58_check_encode(payload: bytes, version: str = '1e') -> str:
    vs = bytes.fromhex(version) + payload
    check = sha256x2(vs)[:4]
    return base58_encode(vs + check)


def public_key_to_address(public_key: bytes) -> str:
    address = base58_check_encode(ripemd160(public_key))
    return address


def wif_key_to_private_key(wif_key: str) -> bytes:
    decoded = base58.b58decode(wif_key).hex()
    version = decoded[:2]
    assert version == '9e'
    checksum = decoded[-8:]
    ext_private_key = bytes.fromhex(decoded[:-8])
    assert checksum == sha256x2(ext_private_key)[:4].hex()
    return bytes.fromhex(decoded[2:-8])


def private_key_to_wif_key(private_key: bytes) -> str:
    ext_private_key = bytes.fromhex('9e') + private_key + bytes.fromhex('01')
    checksum = sha256x2(ext_private_key)[:4]
    return base58_encode(ext_private_key + checksum)


def padded_hex(x: int, padding: int) -> str:
    return '{0:#0{1}x}'.format(x, padding + 2)[2:]


def path_to_string(path_list: List[int]) -> str:
    return 'm/' + '/'.join(map(lambda x: '0\'' if x == 2147483648 else str(x), path_list))


def point(x: int) -> Point:
    """EC Point multiplication"""
    return x * Point(secp256k1.gx, secp256k1.gy, curve=secp256k1)


def serp(point: Point) -> bytes:
    prefix = '02' if point.y % 2 == 0 else '03'
    return bytes.fromhex(prefix + padded_hex(point.x, 64))


def ser32(i: int) -> bytes:
    return bytes.fromhex(padded_hex(i, 8))


def get_public_key(private_key: bytes) -> bytes:
    p = point(int.from_bytes(private_key, byteorder='big'))
    return serp(p)


def derive_private_key(path: List[int]):
    i = path.pop()
    parent_private_key, parent_chain_code = private_key_dict[path_to_string(path)]

    if i >= 2147483648:
        raise NotImplementedError
    else:
        point_k_p = point(int.from_bytes(parent_private_key, byteorder='big'))
        n = secp256k1.q
        msg = serp(point_k_p) + ser32(i)
        hash = hmac.new(key=parent_chain_code, msg=msg, digestmod=hashlib.sha512).hexdigest()
        lefthand_hash = hash[:64]
        secret_bytes = bytes.fromhex(padded_hex((int(lefthand_hash, 16) + int.from_bytes(parent_private_key, byteorder='big')) % n, 64))
        return secret_bytes


private_key_dict = {}


def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('filename')
    parser.add_argument('password')

    args = parser.parse_args()

    w = get_wallet(args.filename, args.password)

    with open('private_keys.csv', 'w') as f:
        for k in w.key:
            if len(k.secret_bytes) > 0 and k.type == 3:
                print('Mnemonic:', k.secret_bytes.decode())
            if len(k.public_key) > 0 and k.type == 4:
                address = public_key_to_address(k.public_key)
                path = k.deterministic_key.path
                path_str = path_to_string(path)
                chain_code = k.deterministic_key.chain_code

                if len(k.secret_bytes) > 0:
                    private_key_dict[path_str] = (k.secret_bytes, chain_code)
                    wif_key = private_key_to_wif_key(k.secret_bytes)
                elif len(path) > 1:
                    private_key = derive_private_key(path)
                    wif_key = private_key_to_wif_key(private_key)
                else:
                    wif_key = ''

                f.write(address + ',' + wif_key + '\n')


if __name__ == '__main__':
    main()
