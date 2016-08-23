from Crypto.Cipher import AES
import base64

def str_to_bytes(data):
    u_type = type(b''.decode('utf8'))
    if isinstance(data, u_type):
        return data.encode('utf8')
    return data

def _pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * str_to_bytes(chr(AES.block_size - len(s) % AES.block_size))

def _cipher():
    key = 'aaaaaaaaaaaaaaaa'
    iv = '0000000000000000'
    return AES.new(key=key, mode=AES.MODE_CBC, IV=iv)

def encrypt_token(data):
    return _cipher().encrypt(_pad(data))

def decrypt_token(data):
    return _cipher().decrypt(data)

if __name__ == '__main__':
    str_start = "胡汉三"
    encrpy_str = encrypt_token(str_to_bytes(str_start))
    decrpy_str = decrypt_token(encrpy_str)
    print('Python encrypt: ', base64.b64encode(encrpy_str).decode('ascii'))
    print('Python decrypt: ', decrpy_str.decode('utf8')) 
