import math
import random
from AKS import *

#Hàm đổi chữ sang số để tính toán và ngược lại
def text_to_number(text):
    # Đảm bảo text là chữ hoa
    text = text.upper()
    # Thêm padding để tránh mất chữ A ở đầu
    padded_text = 'X' + text  # Thêm một ký tự prefix
    return sum((ord(char) - 65) * (26 ** i) for i, char in enumerate(padded_text[::-1]))

def number_to_text(number):
    if number == 0:
        return 'A'  # Trường hợp đặc biệt cho số 0
        
    result = []
    while number:
        number, remainder = divmod(number, 26)
        result.append(chr(remainder + 65))
    
    text = ''.join(result[::-1])
    # Bỏ ký tự padding X ở đầu nếu có
    if text.startswith('X'):
        text = text[1:]
    return text

def find_primitive_root(p):
    if p == 2:
        return 1
    p1, p2 = 2, (p - 1) // 2
    while True:
        alpha = random.randint(2, p - 1)
        if pow(alpha, (p - 1) // p1, p) != 1 and pow(alpha, (p - 1) // p2, p) != 1:
            return alpha

def elgamal_encrypt(p, alpha, beta, k, m):
    c1 = pow(alpha, k, p)
    c2 = (m * pow(beta, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(p, a, c1, c2):
    s = pow(c1, p-a-1, p)
    m = (c2 * s) % p
    return m

def sign(x, p, a, alpha, k):
    gamma = pow(alpha, k, p)
    delta = ((x - a*gamma)*pow(k, -1, p-1))%(p-1)
    return (gamma, delta)

def verify(x, p, alpha, beta, gamma, delta):
    return (pow(beta, gamma, p)*pow(gamma, delta, p)) % p == pow(alpha, x, p) 

def generate_random_number(p):
    while True:
        k = random.randint(1, p - 1)
        if math.gcd(k,p) == 1 and math.gcd(k,p-1) == 1:
            return k

def generate_prime_candidate(n):
    """Sinh số ngẫu nhiên n-bit"""
    return random.randrange(2**(n-1) + 1, 2**n - 1) | 1

def generate_n_bit_prime(n):
    """Sinh số nguyên tố n-bit sử dụng AKS để xác minh"""
    while True:
        candidate = generate_prime_candidate(n)
        if aks_primality_test(candidate):
            return candidate

def main():
    n = int(input("Nhập số bit:"))
    p = generate_n_bit_prime(n)
    alpha = find_primitive_root(p)
    a = generate_random_number(p)
    k1 = generate_random_number(p)
    k2 = generate_random_number(p)
    beta = pow(alpha, a, p)
    message = input("Nhập thông điệp:")
    x = text_to_number(message)
    
    print("---Tham số hệ mật:---")
    print(f"Số bit: {n}")
    print(f"p = {p}")
    print(f"alpha = {alpha}")
    print(f"a = {a}")
    print(f"k mã hóa = {k1}")
    print(f"k ký = {k1}")
    print(f"beta = {beta}")
    print(f"Tin nhắn gốc: {message}")
    print("-------------------------")
    print("-------------------------")

    c1, c2 = elgamal_encrypt(p, alpha, beta, k1, x)
    print(f"Cặp mã hóa tin nhắn: (c1: {c1}, c2: {c2})")
    decrypted_ciphertext = elgamal_decrypt(p, a, c1, c2)
    print(f"Tin nhắn giải mã: {number_to_text(decrypted_ciphertext)}")
    gamma, delta= sign(x, p, a, alpha, k2)
    print(f"Chữ ký: {gamma, delta}")
    print(f"Xác nhận chữ ký: {verify(decrypted_ciphertext, p, alpha, beta, gamma, delta)}")

if __name__ == "__main__":
    main()