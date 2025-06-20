import sympy as sp
import random

# 设置参数
n = 16  # 向量长度
q = 251  # 模数

# 生成随机噪声向量e
e = sp.Matrix(sp.randMatrix(n, 1, min=0, max=1))  # 噪声向量
# 生成随机n维私钥向量s和n*n矩阵A
s = sp.Matrix(sp.randMatrix(n, 1, min=0, max=q - 1))  # 私钥向量
Temp = sp.Matrix(sp.randMatrix(n, n, min=0, max=q - 1))  # 中间变量矩阵Temp
A = Temp.inv_mod(q)  # 计算矩阵Temp在模 q 下的逆矩阵作为A

# 计算n维公钥向量b
b = (A * s + e) % q  # 公钥向量b = A * s + e

# 加密函数
def encrypt(message, A, b):
    m_bin = bin(message)[2:].zfill(n)  # 将消息转换为16比特的二进制字符串
    m = sp.Matrix([int(bit) for bit in m_bin])  # 转换为SymPy矩阵
    x = sp.Matrix(sp.randMatrix(n, n, min=0, max=q // (n * 4)))  # 随机产生一个n*n的矩阵x
    e1 = sp.Matrix(sp.randMatrix(n, 1, min=0, max=1))  # 随机产生一个n维噪声向量e
    c1 = (x * A) % q  # 密文部分c1 = x * A
    c2 = (x * b + e1 + m * (q // 2)) % q  # 密文部分c2 = x * b + e1 + m * q/2
    return c1, c2


# 这是用穷举法的解密函数
def decrypt_without_private_key(A, b, c1, c2, q=251, threshold=50):
    n = A.rows
    
    # 提前计算A的模逆矩阵
    try:
        A_inv = A.inv_mod(q)
    except ValueError:
        # 如果A不可逆，尝试使用伪逆（虽然题目中A可逆）
        A_inv = A.pinv()
    
    # 遍历所有可能的噪声向量e (2^16种可能)
    for num in range(2**n):
        # 生成候选噪声向量 (0/1向量)
        e_vec = sp.Matrix([(num >> i) & 1 for i in range(n)])
        
        # 计算候选私钥 s = A⁻¹(b - e) mod q
        c = (b - e_vec) % q
        s_candidate = (A_inv * c) % q
        
        # 使用候选私钥尝试解密
        t = (c2 - c1 * s_candidate) % q
        
        # 还原消息比特
        m_rec_vec = t.applyfunc(lambda x: round(2 * x / q) % 2)
        
        # 计算噪声向量
        noise_vec = (t - m_rec_vec.applyfunc(lambda bit: bit * (q // 2))) % q
        
        # 调整噪声到[-q/2, q/2]范围
        for i in range(noise_vec.rows):
            if noise_vec[i] > q // 2:
                noise_vec[i] -= q
        
        # 检查噪声是否在可接受范围内
        if all(abs(x) < threshold for x in noise_vec):
            # 将消息向量转换为整数
            m_bin = ''.join(str(int(bit)) for bit in m_rec_vec)
            return int(m_bin, 2)
    
    # 如果未找到有效解密
    raise ValueError("Failed to decrypt: no valid private key found")

message = random.randint(0, 2 ** n - 1)  # 要加密的消息，随机生成一个16比特整数
c1, c2 = encrypt(message, A, b)  # 加密
print("原始消息: ", message)
decrypted_msg = decrypt_without_private_key(A, b, c1, c2)
print("解密后的消息:", decrypted_msg)