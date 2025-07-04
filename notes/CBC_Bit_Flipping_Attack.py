from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 1. 准备“cookie”JSON 明文
plaintext_json = '{"username":"guest","admin":1}'
print("原始 JSON 明文：", plaintext_json)

# 2. 转成字节，并打印二进制表示
plain_bytes = plaintext_json.encode('utf-8')
bits = ''.join(f'{b:08b}' for b in plain_bytes)
print("\n=== 明文字节（二进制） ===")
for i in range(0, len(bits), 8):
    print(bits[i:i+8], end=' ')
print("\n\n共计", len(plain_bytes), "字节，", len(bits), "位")

# 3. 按 AES 块大小（16 字节）分块，并展示每块的二进制
BLOCK_SIZE = AES.block_size  # 16
print("\n=== 分块（16 字节一块） ===")
for idx in range(0, len(plain_bytes), BLOCK_SIZE):
    block = plain_bytes[idx:idx+BLOCK_SIZE]
    block_bits = ''.join(f'{b:08b}' for b in block)
    print(f"P{idx//BLOCK_SIZE+1}:", block, "\n    二进制:", block_bits)

# 4. 在 CBC 模式下加密
key = b'0123456789ABCDEF'
iv  = b'FEDCBA9876543210'
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plain_bytes, BLOCK_SIZE))

# 拆出第 1、2 块密文
C1 = ciphertext[:16]
C2 = ciphertext[16:32]
print("\n=== 密文块（十六进制） ===")
print("C1:", C1.hex())
print("C2:", C2.hex())

# 5. 对 C1 做比特翻转（翻转第 13 个字节的最低位，使 P2 中 '1'→'0'）
tampered_C1 = bytearray(C1)
print('\n下一步：数出 1 在 P2 的第 13 个字节，所以翻转 C1[12] ，在解密时 P2 中的 1 即会对应变化为 0 。')
tampered_C1[12] ^= 0x01
print("篡改后的 C1':", bytes(tampered_C1).hex())

tampered_C1_bin = ''.join(f'{b:08b}' for b in tampered_C1)
print("\nC1' 的二进制表示：",end='')
for i in range(0, len(tampered_C1_bin), 8):
    print(tampered_C1_bin[i:i+8], end=' ')

C1_bin = ''.join(f'{b:08b}' for b in C1)
print("\n C1 的二进制表示：",end='')
for i in range(0, len(C1_bin), 8):
    print(C1_bin[i:i+8], end=' ')

print("\n发现：密文块中的 11001011 变为了 11001010")

print("\n下一步：计算对 C1 进行解密算法之后生成的 D1, 对 C1' 进行解密算法的 D1',进而计算出可以用 D1' 异或回 原始 P1 的 修补用 IV'。\n依据：D1′ ⊕ IV′  ==  D1 ⊕ IV\n")
ecb = AES.new(key, AES.MODE_ECB)
D1       = ecb.decrypt(C1)
D1_prime = ecb.decrypt(bytes(tampered_C1))
print("AES-ECB-Dec(C1) D1:       ", D1.hex())
print("AES-ECB-Dec(C1') D1':      ", D1_prime.hex())

# 原始 P1 = D1 ⊕ IV
orig_P1 = bytes(d ^ v for d, v in zip(D1, iv))
print("原始 P1 (D1 ⊕ IV):         ", orig_P1)

# 计算 IV'：使得 D1' ⊕ IV' = 原始 P1  →  IV' = D1' ⊕ 原始 P1
tampered_iv = bytes(d ^ p for d, p in zip(D1_prime, orig_P1))
print("修补后 IV':               ", tampered_iv.hex())

# 6. 用修补后的 IV' 和篡改的 C1' 合并解密，观察完整明文恢复
decipher = AES.new(key, AES.MODE_CBC, tampered_iv)
forged_cipher = bytes(tampered_C1) + C2 + ciphertext[32:]
decrypted = decipher.decrypt(forged_cipher)
recovered = unpad(decrypted, BLOCK_SIZE)

print("\n恢复后的明文：", recovered.decode('utf-8'))