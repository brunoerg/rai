from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from py_essentials import hashing as hs
import ed25519_blake2b
from .utils import decoder, encodWalletMensg
import hashlib


def generate_shared_secret(priv_key_bytes, address):
    priv_key = load_private_key_from_bytes(priv_key_bytes)
    return priv_key.exchange(load_public_key_from_bytes_x25519
                             (address_to_publickey_bytes(address)))


def derivate_shared_key(shared_key, message):
    return HKDF(
        algorithm=hashes.BLAKE2b,
        length=32,
        salt=None,
        info=bytes(message),
        backend=default_backend()
    ).derive(shared_key)


def save_message_in_address(message):
    message_len = len(message.encode('utf-8'))
    message_split = [message[i:i+32] for i in range(0, message_len, 32)]
    message_encoded = []
    for m in message_split:
        if len(m) < 32:
            mess = []
            for i in range(len(m)):
                mess.append(m[i])
            for i in range(32 - len(m)):
                mess.append(" ")
            mes_str = ''.join(mess)
            message_encoded.append(encodWalletMensg(mes_str))
        else:
            message_encoded.append(encodWalletMensg(m))
    return message_encoded


def get_message_from_address(address):
    mens_cod = 'dxho' + address[4:-8]
    return decoder(mens_cod)[3:]


def address_to_publickey_bytes(address):
    if address.startswith('xrb_'):
        address = address[4:]
    elif address.startswith('nano_'):
        address = address[5:]
    else:
        return False
    prefix = '1111'
    address = prefix + address[8:]
    address = decoder(address)
    address = bytearray(address)
    for i in range(3):
        del address[i]
    return bytes(address)


def file_to_address(file_path, algorithm):
    hsh = hs.fileChecksum(file_path, algorithm)
    return save_message_in_address(hsh)


def load_private_key_from_bytes(priv_bytes):
    return x25519.X25519PrivateKey.from_private_bytes(priv_bytes)


def generate_x25519_private_public_key():
    priv_key = X25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return priv_key, pub_key


def get_bytes_from_privkey_object(priv_key):
    if isinstance(priv_key, X25519PrivateKey):
        return priv_key.priv_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif isinstance(priv_key, ed25519_blake2b.SigningKey):
        return priv_key.to_bytes()
    else:
        return False


def load_public_key_from_bytes_x25519(pub_bytes):
    return x25519.X25519PublicKey.from_public_bytes(pub_bytes)


def load_public_key_bytes_from_addr_x25519(address):
    return x25519.X25519PublicKey.from_public_bytes(
                    address_to_publickey_bytes(address))


def get_pair_ed_key_from_seed(seed):
    sk = ed25519_blake2b.SigningKey(seed.encode('utf-8'))
    return sk, sk.get_verifying_key()


def sign_message_from_seed(seed, message):
    sk = get_pair_ed_key_from_seed(seed)
    return sign_message(sk[0], message)


def sign_message(signing_key, message):
    return signing_key.sign(message.encode('utf-8'), encoding="base64")


def address_to_pubkey_blake_hash(address):
    pub_key = address_to_publickey_bytes(address)
    return hashlib.blake2b(pub_key).hexdigest()
