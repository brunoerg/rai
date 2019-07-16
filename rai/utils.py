import base64
from hashlib import blake2b

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
CUSTOM_ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'
ENCODE_TRANS = str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = str.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def encoder(input):
  return base64.b32encode(bytearray(input, 'utf-8')).decode('utf-8').translate(ENCODE_TRANS)

def encodecheck(input):
    w=bytearray.fromhex(input)
    return base64.b32encode(w).decode('utf-8').translate(ENCODE_TRANS)

def decoder(input):
  return base64.b32decode(input.translate(DECODE_TRANS))

def encodWalletMensg(mens):
    mensExp = '   ' + str(mens)
    mensExpCod = encoder(mensExp)[4:]
    mensByte = str(mens).encode('utf-8')
    p = blake2b(digest_size=5)
    p.update(mensByte)
    checksum = p.hexdigest()
    invchek = "".join(reversed([checksum[i:i+2] for i in range(0, len(checksum), 2)]))
    chekInvCod = encodecheck(invchek)
    return 'xrb_' + mensExpCod + chekInvCod

def decodWalletMensg(wallet):
    mensCod = 'dxho' + wallet[4:-8]
    return decoder(mensCod)[3:]
