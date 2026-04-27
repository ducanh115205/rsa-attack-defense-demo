# rsa_core.py
# Các hàm RSA cơ bản dùng chung cho Attack, Defense và App Tkinter

import math


def is_prime(n):
    """
    Kiểm tra n có phải số nguyên tố không.
    Dùng cho demo nên thuật toán đơn giản, dễ hiểu.
    """
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    limit = int(math.sqrt(n)) + 1

    for i in range(3, limit, 2):
        if n % i == 0:
            return False

    return True


def gcd(a, b):
    """
    Tính ước chung lớn nhất bằng thuật toán Euclid.
    """
    while b != 0:
        a, b = b, a % b

    return a


def extended_gcd(a, b):
    """
    Thuật toán Euclid mở rộng.
    Trả về gcd, x, y sao cho:
        a*x + b*y = gcd(a, b)
    """
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


def mod_inverse(e, phi):
    """
    Tìm d là nghịch đảo modulo của e theo phi.
    Tức là:
        e*d mod phi = 1
    """
    g, x, y = extended_gcd(e, phi)

    if g != 1:
        raise ValueError("Không tồn tại nghịch đảo modulo vì gcd(e, phi) != 1.")

    return x % phi


def generate_keys(p, q, e):
    """
    Sinh khóa RSA từ p, q, e.

    Công thức:
        n = p * q
        phi = (p - 1) * (q - 1)
        d = e^-1 mod phi

    Trả về dictionary để app.py dễ dùng.
    """

    if not is_prime(p):
        raise ValueError("p không phải số nguyên tố.")

    if not is_prime(q):
        raise ValueError("q không phải số nguyên tố.")

    if p == q:
        raise ValueError("p và q không được bằng nhau.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if e <= 1 or e >= phi:
        raise ValueError("e không hợp lệ. Cần 1 < e < phi.")

    if gcd(e, phi) != 1:
        raise ValueError("e không hợp lệ vì gcd(e, phi) != 1.")

    d = mod_inverse(e, phi)

    return {
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "d": d,
        "public_key": (e, n),
        "private_key": (d, n)
    }


def encrypt(m, e, n):
    """
    Mã hóa RSA:
        C = M^e mod n
    """
    if m < 0:
        raise ValueError("Plaintext M phải là số nguyên không âm.")

    if m >= n:
        raise ValueError("Plaintext M phải nhỏ hơn n.")

    return pow(m, e, n)


def decrypt(c, d, n):
    """
    Giải mã RSA:
        M = C^d mod n
    """
    if c < 0:
        raise ValueError("Ciphertext C phải là số nguyên không âm.")

    return pow(c, d, n)


if __name__ == "__main__":
    print("=== TEST RSA CORE ===")

    p = 61
    q = 53
    e = 17
    m = 65

    keys = generate_keys(p, q, e)

    print("n =", keys["n"])
    print("phi =", keys["phi"])
    print("d =", keys["d"])
    print("public key =", keys["public_key"])
    print("private key =", keys["private_key"])

    c = encrypt(m, e, keys["n"])
    print("Ciphertext =", c)

    plain = decrypt(c, keys["d"], keys["n"])
    print("Plaintext sau giải mã =", plain)