from sympy import Mod, Integer
from sympy.core.numbers import mod_inverse

# 模数
N_HEX = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
MODULUS = Integer(int(N_HEX, 16))
MSG_PREFIX = "CryptoCup message:"

# 解密函数
def decrypt_message(encrypted_message, key):
    num_blocks = len(encrypted_message) // 32
    blocks = [encrypted_message[i * 32:(i + 1) * 32] for i in range(num_blocks)]
    decrypted_blocks = []
    k = key

    # 解密每个分组
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
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
        decrypted_message = decrypted_message[len(MSG_PREFIX.encode('utf-8')):]
    
    return decrypted_message.rstrip(b'\x00').decode('utf-8')

# 给定的密文（16进制字符串）
ciphertext_hex = "9780b05ea8decefb932468a5e95202c055003062d7ced47b2bc83396bf535c9679ffe947e9eea132752f057f2c3efa9b5ddc364907ecd5d5a1c6c92c8e33927612b58f9fbd1a1039fd35c51b65961f551862c2ce7aa5096fb67185cc5a19260948f190a5379f57181883a615fabae29bf4cfa26e0614062a4e5c64501540fc38"
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# 提取第一个密文分组（32字节）
first_block = ciphertext_bytes[:32]
c1_int = int.from_bytes(first_block, 'big')

# 计算第一个明文分组（前缀的前16字节）
m1_bytes = MSG_PREFIX.encode('utf-8')[:16]
m1_int = int.from_bytes(m1_bytes, 'big')

# 恢复初始密钥：k = c1 * m1^{-1} mod MODULUS
m1_inv = mod_inverse(m1_int, MODULUS)
initial_key = Mod(c1_int * m1_inv, MODULUS)

# 使用恢复的密钥解密整个密文
decrypted_msg = decrypt_message(ciphertext_bytes, initial_key)
print("Decrypted Message:", decrypted_msg)