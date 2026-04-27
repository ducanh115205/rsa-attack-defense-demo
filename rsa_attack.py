# rsa_attack.py
# Mô phỏng 3 kiểu tấn công RSA yếu:
# 1. Factorization Attack
# 2. Fermat Attack
# 3. Textbook RSA / Guessing Attack

import math
import time

from rsa_core import mod_inverse, decrypt, encrypt


def factorization_attack(n, e, c):
    """
    Attack 1: Factorization Attack

    Input:
        n: modulus công khai
        e: public exponent
        c: ciphertext

    Ý tưởng:
        Nếu n nhỏ, attacker thử chia n để tìm p, q.
        Sau đó tính phi, tính d, giải mã c.

    Output:
        dictionary chứa p, q, phi, d, plaintext m.
    """

    start_time = time.time()

    p = None
    q = None

    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            p = i
            q = n // i
            break

    end_time = time.time()
    elapsed_time = end_time - start_time

    if p is None or q is None:
        return {
            "success": False,
            "message": "Không phân tích được n. Có thể n là số nguyên tố hoặc quá khó trong phạm vi demo.",
            "time": elapsed_time
        }

    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    m = decrypt(c, d, n)

    return {
        "success": True,
        "attack_name": "Factorization Attack",
        "n": n,
        "e": e,
        "c": c,
        "p": p,
        "q": q,
        "phi": phi,
        "d": d,
        "plaintext": m,
        "time": elapsed_time,
        "explanation": "Do n quá nhỏ nên attacker phân tích được n = p * q, từ đó tính lại private key d."
    }


def fermat_attack(n):
    """
    Attack 2: Fermat Attack

    Input:
        n

    Ý tưởng:
        Dùng khi p và q quá gần nhau.

        n = p * q
        n = a^2 - b^2
        n = (a - b)(a + b)

        p = a - b
        q = a + b

    Output:
        dictionary chứa p, q, số vòng lặp, thời gian chạy.
    """

    start_time = time.time()

    a = math.isqrt(n)

    if a * a < n:
        a += 1

    loop_count = 0

    while True:
        b_square = a * a - n
        b = math.isqrt(b_square)

        if b * b == b_square:
            p = a - b
            q = a + b

            if p * q == n:
                end_time = time.time()

                return {
                    "success": True,
                    "attack_name": "Fermat Attack",
                    "n": n,
                    "p": p,
                    "q": q,
                    "a": a,
                    "b": b,
                    "loops": loop_count,
                    "time": end_time - start_time,
                    "explanation": "Do p và q quá gần nhau nên có thể biểu diễn n = a^2 - b^2 và tìm lại p, q."
                }

        a += 1
        loop_count += 1

        # Giới hạn vòng lặp để app không bị treo khi demo
        if loop_count > 1_000_000:
            end_time = time.time()

            return {
                "success": False,
                "message": "Fermat Attack thất bại trong giới hạn demo. Có thể p và q không đủ gần nhau.",
                "loops": loop_count,
                "time": end_time - start_time
            }


def guess_plaintext_attack(possible_messages, e, n, target_c):
    """
    Attack 3: Textbook RSA / Guessing Attack

    Input:
        possible_messages: danh sách plaintext nghi ngờ
        e, n: public key
        target_c: ciphertext mục tiêu

    Ý tưởng:
        RSA thô không padding có tính quyết định.
        Cùng plaintext M với cùng public key luôn tạo ra cùng ciphertext C.

        Attacker thử mã hóa các plaintext nghi ngờ.
        Nếu ciphertext tạo ra trùng target_c thì đoán được plaintext.
    """

    attempts = []

    for m in possible_messages:
        try:
            generated_c = encrypt(m, e, n)

            attempts.append({
                "plaintext_try": m,
                "ciphertext_generated": generated_c,
                "matched": generated_c == target_c
            })

            if generated_c == target_c:
                return {
                    "success": True,
                    "attack_name": "Textbook RSA / Guessing Attack",
                    "found_plaintext": m,
                    "target_ciphertext": target_c,
                    "attempts": attempts,
                    "explanation": "Do RSA thô không có padding nên cùng một plaintext luôn tạo ra cùng ciphertext."
                }

        except Exception as error:
            attempts.append({
                "plaintext_try": m,
                "error": str(error),
                "matched": False
            })

    return {
        "success": False,
        "message": "Không tìm thấy plaintext phù hợp trong danh sách nghi ngờ.",
        "target_ciphertext": target_c,
        "attempts": attempts
    }


if __name__ == "__main__":
    print("=== TEST RSA ATTACK ===")

    print("\n--- Attack 1: Factorization Attack ---")
    result1 = factorization_attack(n=3233, e=17, c=2790)
    print(result1)

    print("\n--- Attack 2: Fermat Attack ---")
    result2 = fermat_attack(n=1022117)
    print(result2)

    print("\n--- Attack 3: Guessing Attack ---")
    possible_messages = [10, 20, 30, 65, 100]
    result3 = guess_plaintext_attack(
        possible_messages=possible_messages,
        e=17,
        n=3233,
        target_c=2790
    )
    print(result3)