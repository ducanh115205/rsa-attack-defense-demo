# rsa_defense.py
# Phòng thủ/phòng chống các lỗi triển khai RSA yếu

import random

from rsa_core import is_prime, gcd, encrypt


def check_rsa_security(p, q, e):
    """
    Kiểm tra an toàn tham số RSA.

    Kiểm tra:
        - p có phải số nguyên tố không
        - q có phải số nguyên tố không
        - p và q có bằng nhau không
        - n có quá nhỏ không
        - p và q có quá gần nhau không
        - e có hợp lệ không
        - e có quá nhỏ không

    Trả về dictionary để app.py dễ hiển thị.
    """

    checks = []
    recommendations = []
    serious_errors = 0
    warnings = 0

    # Giá trị mặc định nếu p, q không hợp lệ
    n = None
    phi = None
    bit_length = None

    # 1. Kiểm tra p là số nguyên tố
    if not is_prime(p):
        checks.append("[X] p không phải số nguyên tố.")
        recommendations.append("Chọn p là số nguyên tố lớn.")
        serious_errors += 1
    else:
        checks.append("[OK] p là số nguyên tố.")

    # 2. Kiểm tra q là số nguyên tố
    if not is_prime(q):
        checks.append("[X] q không phải số nguyên tố.")
        recommendations.append("Chọn q là số nguyên tố lớn.")
        serious_errors += 1
    else:
        checks.append("[OK] q là số nguyên tố.")

    # Nếu p hoặc q không nguyên tố, vẫn cố tính n để hiển thị, nhưng e/phi có thể không chuẩn
    n = p * q
    bit_length = n.bit_length()

    # 3. Kiểm tra p và q có bằng nhau không
    if p == q:
        checks.append("[X] p và q không được bằng nhau.")
        recommendations.append("Chọn p và q là hai số nguyên tố khác nhau.")
        serious_errors += 1
    else:
        checks.append("[OK] p và q khác nhau.")

    # 4. Tính phi nếu p, q hợp lệ
    if is_prime(p) and is_prime(q) and p != q:
        phi = (p - 1) * (q - 1)
    else:
        phi = None

    # 5. Defense 1: Chống Factorization Attack
    if bit_length < 2048:
        checks.append(f"[!] n chỉ có {bit_length} bit, quá nhỏ so với RSA thực tế.")
        checks.append("[!] Nguy cơ: dễ bị Factorization Attack.")
        recommendations.append("Dùng RSA tối thiểu 2048 bit hoặc 3072 bit trong thực tế.")
        warnings += 1
    else:
        checks.append(f"[OK] n có {bit_length} bit, đạt mức tối thiểu 2048 bit.")

    # 6. Defense 2: Chống Fermat Attack
    distance = abs(p - q)

    if distance < 100:
        checks.append(f"[!] |p - q| = {distance}, p và q quá gần nhau trong phạm vi demo.")
        checks.append("[!] Nguy cơ: dễ bị Fermat Attack.")
        recommendations.append("Chọn p và q ngẫu nhiên, đủ lớn và không quá gần nhau.")
        warnings += 1
    else:
        checks.append(f"[OK] |p - q| = {distance}, không quá gần nhau trong phạm vi demo.")

    # 7. Kiểm tra e
    if phi is not None:
        if e <= 1:
            checks.append("[X] e phải lớn hơn 1.")
            recommendations.append("Chọn e sao cho 1 < e < phi(n).")
            serious_errors += 1
        elif e >= phi:
            checks.append("[X] e phải nhỏ hơn phi(n).")
            recommendations.append("Chọn e sao cho 1 < e < phi(n).")
            serious_errors += 1
        elif gcd(e, phi) != 1:
            checks.append("[X] gcd(e, phi(n)) != 1, e không hợp lệ.")
            recommendations.append("Chọn e sao cho gcd(e, phi(n)) = 1.")
            serious_errors += 1
        else:
            checks.append("[OK] e hợp lệ vì 1 < e < phi(n) và gcd(e, phi(n)) = 1.")
    else:
        checks.append("[X] Không kiểm tra được e vì p, q không hợp lệ.")
        recommendations.append("Sửa p, q trước rồi kiểm tra lại e.")
        serious_errors += 1

    # 8. Cảnh báo e nhỏ
    if e in [3, 5, 17]:
        checks.append(f"[!] e = {e} là public exponent nhỏ.")
        checks.append("[!] Trong thực tế thường dùng e = 65537.")
        recommendations.append("Nên dùng e = 65537 trong triển khai thực tế.")
        warnings += 1
    elif e == 65537:
        checks.append("[OK] e = 65537, đây là giá trị phổ biến trong thực tế.")
    else:
        checks.append("[OK] e không nằm trong nhóm e nhỏ thường cảnh báo trong demo.")

    # 9. Defense 3: Cảnh báo RSA thô không padding
    checks.append("[!] RSA thô không padding có tính quyết định.")
    checks.append("[!] Cùng một plaintext với cùng public key sẽ luôn cho cùng ciphertext.")
    recommendations.append("Không dùng RSA thô. Thực tế cần dùng RSA-OAEP từ thư viện mật mã uy tín.")

    # 10. Kết luận risk level
    if serious_errors >= 1 or warnings >= 3:
        risk_level = "RỦI RO CAO"
    elif warnings >= 1:
        risk_level = "RỦI RO TRUNG BÌNH"
    else:
        risk_level = "TẠM ỔN TRONG PHẠM VI DEMO"

    # Xóa khuyến nghị trùng
    unique_recommendations = []

    for item in recommendations:
        if item not in unique_recommendations:
            unique_recommendations.append(item)

    return {
        "p": p,
        "q": q,
        "e": e,
        "n": n,
        "phi": phi,
        "bit_length": bit_length,
        "distance": distance,
        "risk_level": risk_level,
        "checks": checks,
        "recommendations": unique_recommendations
    }


def raw_rsa_encrypt_three_times(m, e, n):
    """
    Defense 3 - phần chứng minh RSA thô không an toàn.

    Mã hóa cùng một m ba lần bằng RSA thô:
        C = M^e mod n

    Vì RSA thô có tính quyết định nên 3 ciphertext sẽ giống nhau.
    """

    results = []

    for i in range(3):
        c = pow(m, e, n)

        results.append({
            "time": i + 1,
            "plaintext": m,
            "ciphertext": c
        })

    return {
        "method": "Raw RSA - không padding",
        "results": results,
        "explanation": "RSA thô không padding có tính quyết định, nên cùng plaintext luôn tạo ra cùng ciphertext."
    }


def padding_rsa_encrypt_three_times(m, e, n):
    """
    Defense 3 - mô phỏng padding ngẫu nhiên.

    Lưu ý quan trọng:
        Đây chỉ là mô phỏng ý tưởng padding.
        Đây KHÔNG PHẢI OAEP chuẩn.
        Trong thực tế phải dùng RSA-OAEP từ thư viện mật mã uy tín.

    Cách mô phỏng:
        Mỗi lần tạo random pad nhỏ.
        Ghép pad vào plaintext để tạo padded_m.
        Sau đó mã hóa padded_m.

    Để tránh padded_m >= n trong demo nhỏ:
        padded_m = (m * 100 + random_pad) % n

    Với n quá nhỏ, mô phỏng này chỉ dùng để minh họa ý tưởng.
    """

    results = []

    for i in range(3):
        random_pad = random.randint(10, 99)

        padded_m = (m * 100 + random_pad) % n

        c = pow(padded_m, e, n)

        results.append({
            "time": i + 1,
            "original_plaintext": m,
            "random_pad": random_pad,
            "padded_plaintext": padded_m,
            "ciphertext": c
        })

    return {
        "method": "RSA có padding mô phỏng",
        "results": results,
        "warning": "Đây chỉ là mô phỏng ý tưởng padding, không phải OAEP chuẩn.",
        "recommendation": "Thực tế phải dùng RSA-OAEP từ thư viện mật mã uy tín.",
        "explanation": "Do mỗi lần thêm padding ngẫu nhiên khác nhau nên ciphertext thường khác nhau dù plaintext ban đầu giống nhau."
    }


if __name__ == "__main__":
    print("=== TEST RSA DEFENSE ===")

    print("\n--- Defense: kiểm tra RSA yếu n nhỏ ---")
    result = check_rsa_security(p=61, q=53, e=17)

    print("n =", result["n"])
    print("phi =", result["phi"])
    print("bit length =", result["bit_length"])
    print("risk level =", result["risk_level"])

    print("\nCác kiểm tra:")
    for check in result["checks"]:
        print(check)

    print("\nKhuyến nghị:")
    for rec in result["recommendations"]:
        print("-", rec)

    print("\n--- Defense: raw RSA encrypt 3 lần ---")
    raw_result = raw_rsa_encrypt_three_times(m=65, e=17, n=3233)
    print(raw_result)

    print("\n--- Defense: padding mô phỏng encrypt 3 lần ---")
    padding_result = padding_rsa_encrypt_three_times(m=65, e=17, n=3233)
    print(padding_result)