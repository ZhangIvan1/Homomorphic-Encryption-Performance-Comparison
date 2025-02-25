import time
import random
import numpy as np
from phe import paillier
import tenseal as ts
from Pyfhel import Pyfhel
import traceback
import sys

def get_object_size(obj):
    """计算对象的字节大小"""
    return sys.getsizeof(obj)

def test_paillier(n):
    """测试Paillier加密方案"""
    pk, sk = paillier.generate_paillier_keypair()
    data = [random.randint(0, 100) for _ in range(n)]

    # 明文体积
    plaintext_size = get_object_size(data)

    # 加密
    start = time.time()
    encrypted = []
    for i, x in enumerate(data):
        encrypted.append(pk.encrypt(x))
        if (i + 1) % (n // 10) == 0:  # 每10%的进度输出一次
            print(f"Paillier 加密进度: {((i + 1) / n) * 100:.2f}%")
    encrypt_time = (time.time() - start) * 1000  # 毫秒

    # 密文体积
    ciphertext_size = get_object_size(encrypted)

    # 解密
    start = time.time()
    decrypted = []
    for i, x in enumerate(encrypted):
        decrypted.append(sk.decrypt(x))
        if (i + 1) % (n // 10) == 0:  # 每10%的进度输出一次
            print(f"Paillier 解密进度: {((i + 1) / n) * 100:.2f}%")
    decrypt_time = (time.time() - start) * 1000  # 毫秒

    return encrypt_time, decrypt_time, plaintext_size, ciphertext_size

def test_ckks(n):
    """测试CKKS加密方案"""
    try:
        # 参数设置
        context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=8192,
            coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        context.generate_galois_keys()
        context.global_scale = 2**40

        # 生成数据
        data = [random.random() for _ in range(n)]
        print(f"Generated data: {data[:5]}...")  # Show first 5 elements for quick review

        # 明文体积
        plaintext_size = get_object_size(data)

        # 将所有数据封装到一个密文中
        start = time.time()
        encrypted = ts.ckks_vector(context, data)
        encrypt_time = (time.time() - start) * 1000  # 毫秒
        print(f"CKKS 加密进度: 100.00%")

        # 密文体积
        ciphertext_size = get_object_size(encrypted)

        # 解密
        start = time.time()
        decrypted = encrypted.decrypt()  # 解密整个向量
        decrypt_time = (time.time() - start) * 1000  # 毫秒
        print(f"CKKS 解密进度: 100.00%")

        # 显示前5个解密后的结果进行检查
        print(f"Decrypted values: {decrypted[:5]}...")  # Show first 5 decrypted values

        return encrypt_time, decrypt_time, plaintext_size, ciphertext_size
    except Exception as e:
        print(f"CKKS Error: {str(e)}")
        return None, None, None, None


def test_bgv(n):
    """测试BGV加密方案"""
    try:
        HE = Pyfhel()
        bgv_params = {
            'scheme': 'BGV',
            'n': 2**13,
            't': 65537,
            't_bits': 20,
            'sec': 128,
        }
        HE.contextGen(**bgv_params)
        HE.keyGen()

        # 生成并编码数据
        data = [random.randint(0, 100) for _ in range(n)]

        # 明文体积
        plaintext_size = get_object_size(data)

        # 对每个数据点单独编码
        ptxt = [HE.encode(d) for d in data]

        # 加密
        start = time.time()
        ctxt = [HE.encrypt(ptxt[i]) for i in range(n)]  # 加密每个PyPtxt对象
        encrypt_time = (time.time() - start) * 1000  # 毫秒

        # 密文体积
        ciphertext_size = get_object_size(ctxt)

        # 解密
        start = time.time()
        ptxt_dec = []
        for i, ctxt_item in enumerate(ctxt):
            ptxt_dec.append(HE.decrypt(ctxt_item))
            if (i + 1) % (n // 10) == 0:  # 每10%的进度输出一次
                print(f"BGV 解密进度: {((i + 1) / n) * 100:.2f}%")
        decrypt_time = (time.time() - start) * 1000  # 毫秒

        # 解密后的结果已经是解密的数值数组，可以直接使用
        decrypted = [ptxt_dec[i][0] for i in range(n)]  # 解密结果已经是数值，直接取出第一个元素

        return encrypt_time, decrypt_time, plaintext_size, ciphertext_size
    except Exception as e:
        print(f"BGV Error: {str(e)}")
        print("Error occurred at:")
        traceback.print_exc()  # 打印详细的错误信息和出错位置
        return None, None, None, None


def test_bfv(n):
    """测试BFV加密方案"""
    try:
        HE = Pyfhel()
        HE.contextGen(scheme='bfv', n=2**14, t_bits=20)
        HE.keyGen()

        # 生成并编码数据
        data = [random.randint(0, 100) for _ in range(n)]

        # 明文体积
        plaintext_size = get_object_size(data)

        # 对每个数据点单独编码
        ptxt = [HE.encode(d) for d in data]

        # 加密
        start = time.time()
        ctxt = [HE.encrypt(ptxt[i]) for i in range(n)]  # 加密每个PyPtxt对象
        encrypt_time = (time.time() - start) * 1000  # 毫秒

        # 密文体积
        ciphertext_size = get_object_size(ctxt)

        # 解密
        start = time.time()
        ptxt_dec = [HE.decrypt(ctxt[i]) for i in range(n)]  # 解密每个PyPtxt对象
        decrypt_time = (time.time() - start) * 1000  # 毫秒

        # 解密后的结果已经是解密的数值数组，可以直接使用
        decrypted = [ptxt_dec[i][0] for i in range(n)]  # 解密结果已经是数值，直接取出第一个元素

        return encrypt_time, decrypt_time, plaintext_size, ciphertext_size
    except Exception as e:
        print(f"BFV Error: {str(e)}")
        print("Error occurred at:")
        traceback.print_exc()  # 打印详细的错误信息和出错位置
        return None, None, None, None


if __name__ == "__main__":
    # 测试参数设置
    n_values = range(100, 1001, 100)
   #n_values = range(10, 21, 10)
    results = []

    # 运行测试
    for n in n_values:
        print(f"Testing n = {n}...")

        # Paillier测试
        p_enc, p_dec, p_plain_size, p_cipher_size = test_paillier(n)

        # CKKS测试
        c_enc, c_dec, c_plain_size, c_cipher_size = test_ckks(n)

        # BGV测试
        b_enc, b_dec, b_plain_size, b_cipher_size = test_bgv(n)

        # BFV测试
        f_enc, f_dec, f_plain_size, f_cipher_size = test_bfv(n)

        results.append((
            n,
            p_enc, p_dec, p_plain_size, p_cipher_size,
            c_enc, c_dec, c_plain_size, c_cipher_size,
            b_enc, b_dec, b_plain_size, b_cipher_size,
            f_enc, f_dec, f_plain_size, f_cipher_size
        ))

    # 格式化输出结果
    print("\n测试结果对比表：")
    print(f"{'明文长度':<10} | {'Paillier加密(ms)':<15} | {'Paillier解密(ms)':<15} | "
          f"{'Paillier明文体积(bytes)':<25} | {'Paillier密文体积(bytes)':<25} | "
          f"{'CKKS加密(ms)':<15} | {'CKKS解密(ms)':<15} | "
          f"{'CKKS明文体积(bytes)':<25} | {'CKKS密文体积(bytes)':<25} | "
          f"{'BGV加密(ms)':<15} | {'BGV解密(ms)':<15} | "
          f"{'BGV明文体积(bytes)':<25} | {'BGV密文体积(bytes)':<25} | "
          f"{'BFV加密(ms)':<15} | {'BFV解密(ms)':<15} | "
          f"{'BFV明文体积(bytes)':<25} | {'BFV密文体积(bytes)':<25}")
    print("-"*200)

    for res in results:
        print(
            f"{res[0]:<10} | "
            f"{res[1]:<15.6f} | {res[2]:<15.6f} | {res[3]:<25} | {res[4]:<25} | "
            f"{res[5] if res[5] is not None else 'N/A':<15} | "
            f"{res[6] if res[6] is not None else 'N/A':<15} | "
            f"{res[7]:<25} | {res[8]:<25} | "
            f"{res[9] if res[9] is not None else 'N/A':<15} | "
            f"{res[10] if res[10] is not None else 'N/A':<15} | "
            f"{res[11]:<25} | {res[12]:<25} | "
            f"{res[13] if res[13] is not None else 'N/A':<15} | "
            f"{res[14] if res[14] is not None else 'N/A':<15} | "
            f"{res[15]:<25} | {res[16]:<25}"
        )

