from sympy import Mod, Integer
from sympy.core.numbers import mod_inverse
from Crypto.Util.number import *

# 模数
N_HEX = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
MODULUS = Integer(int(N_HEX, 16))
MSG_PREFIX = "CryptoCup message:"

# 解密函数
def decrypt_message(encrypted_message, key=-1):
    num_blocks = len(encrypted_message) // 32
    blocks = [encrypted_message[i * 32:(i + 1) * 32] for i in range(num_blocks)]

    decrypted_blocks = []

    k = key

    # 解密每个分组
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        if k == -1:
            # get key
            decrypted_block_int = bytes_to_long(MSG_PREFIX[:16].encode())
            k = block_int * mod_inverse(decrypted_block_int, MODULUS) % MODULUS
            
        key_inv = mod_inverse(k, MODULUS)
        decrypted_block_int = Mod(block_int * key_inv, MODULUS)
        decrypted_blocks.append(decrypted_block_int)
        k += 1  # 密钥自增1

    # 将解密后的分组连接成最终的明文
    decrypted_message = b''.join(
        int(block_int).to_bytes(16, byteorder='big') for block_int in decrypted_blocks
    )

    # 去除前缀
    if decrypted_message.startswith(MSG_PREFIX.encode('utf-8')):
        decrypted_message = decrypted_message[len(MSG_PREFIX):]

    return decrypted_message.rstrip(b'\x00').decode('utf-8')


encrypted_message = bytes.fromhex('534ed400954f43256f50e9224595608726b3f016f8cece29ad868085526be54b1449d8eb3400703f429ae51b9675ce74aa8548240f176fe65b4ae4632f00eb157d852e4662abbb84a8a8914519beca68dbd6c138283a67d2b677c148ad396006')
decrypted_message = decrypt_message(encrypted_message)
print("Decrypted Message:", decrypted_message)