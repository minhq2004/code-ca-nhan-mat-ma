import hashlib, random, math
from EllipticCurve import *
import re
from AKS import *

class MyEllipticCurve:
    def __init__(self, a, b, p, G, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n

    def point_addition(self, P, Q):
        if P == (None, None):
            return Q
        if Q == (None, None):
            return P

        (x1, y1) = P
        (x2, y2) = Q

        if x1 == x2 and y1 != y2:
            return (None, None)

        if P == Q:
            m = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)

        m = m % self.p
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_multiplication(self, k, P):
        N = P
        Q = (None, None)
        while k:
            if k & 1:
                Q = self.point_addition(Q, N)
            N = self.point_addition(N, N)
            k >>= 1
        return Q

def generate_keypair(curve):
    private_key = random.randint(1, curve.n - 1)
    public_key = curve.scalar_multiplication(private_key, curve.G)
    return private_key, public_key

def ec_elgamal_encrypt(curve, public_key, plaintext_point):
    k = random.randint(1, curve.n - 1)
    C1 = curve.scalar_multiplication(k, curve.G)
    C2 = curve.point_addition(plaintext_point, curve.scalar_multiplication(k, public_key))
    return C1, C2

def ec_elgamal_decrypt(curve, private_key, ciphertext):
    C1, C2 = ciphertext
    S = curve.scalar_multiplication(private_key, C1)
    S_inv = (S[0], -S[1] % curve.p)
    plaintext_point = curve.point_addition(C2, S_inv)
    return plaintext_point

def sign_message(curve, private_key, message):
    z = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    r = 0
    s = 0
    while r == 0 or s == 0 or math.gcd(s, curve.n) != 1:
        k = random.randint(1, curve.n - 1)
        while math.gcd(k, curve.n) != 1:
            k = random.randint(1, curve.n - 1)
        x, y = curve.scalar_multiplication(k, curve.G)
        r = x % curve.n
        s = ((z + r * private_key) * pow(k, -1, curve.n)) % curve.n
        if s == 0:
            continue
        
    return (r, s)

def verify_signature(curve, public_key, message, signature):
    r, s = signature
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    z = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    w = pow(s, -1, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n
    x, y = curve.point_addition(
        curve.scalar_multiplication(u1, curve.G),
        curve.scalar_multiplication(u2, public_key)
    )
    return r == x % curve.n


def hash_message_to_point(curve, message):
    hash_int = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    x = hash_int % curve.p
    while True:
        y2 = (x**3 + curve.a * x + curve.b) % curve.p
        if pow(y2, (curve.p - 1) // 2, curve.p) == 1:  
            y = pow(y2, (curve.p + 1) // 4, curve.p)
            return (x, y)
        x = (x + 1) % curve.p
    
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

def generate_valid_curve_params(bits):
    p = generate_n_bit_prime(bits)
    while True:
        while True:
            a = random.randint(1 , p - 1)
            b = random.randint(1 , p - 1)

            if (4 * a**3 + 27 * b**2) % p != 0:
                break

        while True:
            x = random.randint(0, p - 1)
            y2 = (x**3 + a * x + b) % p
            if pow(y2, (p - 1) // 2, p) == 1:  
                y = pow(y2, (p + 1) // 4, p)
                G = (x, y)
                break

        E = EllipticCurve(p, a, b) 
        order = E.sea()
        n = int(re.search(r'\d+', order).group())
        if (aks_primality_test(n)):
            return a, b, p, G, n
        else:
            continue

if __name__ == "__main__":
    bits = int(input("Nhập số bit:"))
    a, b, p, G, n = generate_valid_curve_params(bits)
    print(f"Tham số đường cong Elliptic:")
    print(f"Số bit: {bits}")
    print(f"a: {a}")
    print(f"b: {b}")
    print(f"p: {p}")
    print(f"G: {G}")
    print(f"n: {n}")

    curve = MyEllipticCurve(a, b, p, G, n)
    message = input("Nhập thông điệp:")

    # Generate key pair
    private_key, public_key = generate_keypair(curve)
    print(f"Khóa bí mật: {private_key}")
    print(f"Khóa công khai: {public_key}")

    plaintext_point = hash_message_to_point(curve, message)
    print(f"Điểm bản rõ M: {plaintext_point}")
    M1, M2 = ec_elgamal_encrypt(curve, public_key, plaintext_point)
    print(f"Bản mã: M1: {M1}, M2: {M2}")

    # Decrypt the message
    decrypted_point = ec_elgamal_decrypt(curve, private_key, (M1, M2))
    print(f"Điểm giải mã: {decrypted_point}")

    # Sign a message
    signature = sign_message(curve, private_key, message)
    print(f"Chữ ký: {signature}")

    # Verify the signature
    is_valid = verify_signature(curve, public_key, message, signature)
    print(f"Xác nhận chữ ký: {is_valid}")