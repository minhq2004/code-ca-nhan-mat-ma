import random
import sys
from math import gcd
from AKS import *

#Tăng chữ số tối đa
sys.set_int_max_str_digits(10000)

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

def generate_prime_candidate(n):
    """Sinh số ngẫu nhiên n-bit"""
    return random.randrange(2**(n-1) + 1, 2**n - 1) | 1

def generate_n_bit_prime(n):
    """Sinh số nguyên tố n-bit sử dụng AKS để xác minh"""
    while True:
        candidate = generate_prime_candidate(n)
        if aks_primality_test(candidate):
            return candidate

def generate_different_primes(n):
    """Sinh hai số nguyên tố khác nhau"""
    p = generate_n_bit_prime(n)
    q = generate_n_bit_prime(n)
    return p, q

#Thuật toán mã hóa
def rsa_encrypt(message, e, n):
    return pow(message, e, n)

#Thuật toán giải mã
def rsa_decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)

#Thuật toán ký
def sign(message, d, n):
    return pow(message, d, n)

#Thuật toán kiểm thử
def verify(x, signature, e, n):
    return x % n == pow(signature, e, n)


# Nhập số bit từ bàn phím
bit_length = int(input("Nhập số bit:"))

p, q = generate_different_primes(bit_length)

n = p * q
phi = (p - 1) * (q - 1)

# Chọn e ngẫu nhiên sao cho nguyên tố phi
e = random.randint(2, phi - 1)
while gcd(e, phi) != 1:
    e = random.randint(2, phi - 1)

d = pow(e, -1, phi)

# Thực hiện hệ mật RSA
message_text = input("Nhập thông điệp:")
message_number = text_to_number(message_text)

encrypted_message = rsa_encrypt(message_number, e, n)
decrypted_message_number = rsa_decrypt(encrypted_message, d, n)
decrypted_message_text = number_to_text(decrypted_message_number)

print("---Tham số hệ mật:---")
print(f"Số bit: {bit_length}")
print("Tin nhắn gốc:", message_text)
print(f"p: {p}")
print(f"q: {q}")
print(f"n: {n}")
print(f"e: {e}")
print(f"d: {d}")
print("Tin nhắn được mã hóa: ", number_to_text(encrypted_message))
print("Tin nhắn được giải mã: ", decrypted_message_text) 

print("Sơ đồ ký: ")
signature = sign(message_number, d, n)
print(f"Chữ ký: {signature}")
print(f"Xác nhận chữ ký: {verify(decrypted_message_number, signature, e, n)}")