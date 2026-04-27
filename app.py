# app.py
# Ứng dụng desktop Tkinter demo RSA Attack & Defense

import tkinter as tk
from tkinter import ttk, messagebox

from rsa_core import generate_keys, encrypt, decrypt
from rsa_attack import factorization_attack, fermat_attack, guess_plaintext_attack
from rsa_defense import (
    check_rsa_security,
    raw_rsa_encrypt_three_times,
    padding_rsa_encrypt_three_times
)


class RSADemoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Attack & Defense Demo")
        self.root.geometry("1000x700")

        self.generated_keys = None
        self.last_ciphertext = None

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.create_basic_tab()
        self.create_attack_tab()
        self.create_defense_tab()

    # =========================
    # HÀM HỖ TRỢ
    # =========================

    def get_int(self, entry, field_name):
        """
        Lấy số nguyên từ ô nhập.
        Nếu nhập sai thì báo lỗi.
        """
        value = entry.get().strip()

        if value == "":
            raise ValueError(f"Bạn chưa nhập {field_name}.")

        try:
            return int(value)
        except ValueError:
            raise ValueError(f"{field_name} phải là số nguyên.")

    def clear_text(self, text_widget):
        text_widget.delete("1.0", tk.END)

    def write_text(self, text_widget, content):
        text_widget.insert(tk.END, content + "\n")
        text_widget.see(tk.END)

    def write_flow(self, text_widget, steps, final_callback=None, delay=500):
        """
        Hiển thị từng bước xử lý lên màn hình.
        Sau khi hiện xong các bước thì chạy final_callback để hiện kết quả.
        """

        self.clear_text(text_widget)

        def show_step(index):
            if index < len(steps):
                text_widget.insert(tk.END, steps[index] + "\n")
                text_widget.see(tk.END)

                self.root.after(delay, lambda: show_step(index + 1))
            else:
                if final_callback is not None:
                    final_callback()

        show_step(0)

    def append_result_title(self, text_widget, title):
        """
        Thêm tiêu đề kết quả sau khi đã chạy xong luồng.
        """
        text_widget.insert(tk.END, "\n" + title + "\n")
        text_widget.see(tk.END)

    # =========================
    # TAB 1: RSA CƠ BẢN
    # =========================

    def create_basic_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="RSA cơ bản")

        input_frame = ttk.LabelFrame(tab, text="Nhập tham số RSA")
        input_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(input_frame, text="p:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.basic_p_entry = ttk.Entry(input_frame, width=20)
        self.basic_p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="q:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.basic_q_entry = ttk.Entry(input_frame, width=20)
        self.basic_q_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(input_frame, text="e:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.basic_e_entry = ttk.Entry(input_frame, width=20)
        self.basic_e_entry.grid(row=0, column=5, padx=5, pady=5)

        ttk.Button(input_frame, text="Sinh khóa", command=self.handle_generate_keys).grid(
            row=0, column=6, padx=10, pady=5
        )

        message_frame = ttk.LabelFrame(tab, text="Mã hóa / Giải mã")
        message_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(message_frame, text="Plaintext M:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.basic_m_entry = ttk.Entry(message_frame, width=30)
        self.basic_m_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(message_frame, text="Mã hóa", command=self.handle_encrypt).grid(
            row=0, column=2, padx=10, pady=5
        )

        ttk.Label(message_frame, text="Ciphertext C:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.basic_c_entry = ttk.Entry(message_frame, width=30)
        self.basic_c_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(message_frame, text="Giải mã", command=self.handle_decrypt).grid(
            row=1, column=2, padx=10, pady=5
        )

        output_frame = ttk.LabelFrame(tab, text="Kết quả")
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.basic_output = tk.Text(output_frame, height=20)
        self.basic_output.pack(fill="both", expand=True, padx=5, pady=5)

    def handle_generate_keys(self):
        try:
            p = self.get_int(self.basic_p_entry, "p")
            q = self.get_int(self.basic_q_entry, "q")
            e = self.get_int(self.basic_e_entry, "e")

            steps = [
                "[1] Nhận p, q, e từ người dùng.",
                f"[2] Kiểm tra p = {p} có phải số nguyên tố không.",
                f"[3] Kiểm tra q = {q} có phải số nguyên tố không.",
                "[4] Tính n = p * q.",
                "[5] Tính phi(n) = (p - 1) * (q - 1).",
                "[6] Kiểm tra gcd(e, phi(n)) = 1.",
                "[7] Tính d là nghịch đảo modulo của e theo phi(n).",
                "[8] Tạo public key = (e, n) và private key = (d, n)."
            ]

            def show_result():
                try:
                    keys = generate_keys(p, q, e)
                    self.generated_keys = keys

                    self.append_result_title(self.basic_output, "=== KẾT QUẢ SINH KHÓA RSA ===")
                    self.write_text(self.basic_output, f"p = {keys['p']}")
                    self.write_text(self.basic_output, f"q = {keys['q']}")
                    self.write_text(self.basic_output, f"n = p * q = {keys['n']}")
                    self.write_text(self.basic_output, f"phi(n) = (p - 1)(q - 1) = {keys['phi']}")
                    self.write_text(self.basic_output, f"e = {keys['e']}")
                    self.write_text(self.basic_output, f"d = {keys['d']}")
                    self.write_text(self.basic_output, f"Public key = {keys['public_key']}")
                    self.write_text(self.basic_output, f"Private key = {keys['private_key']}")

                except Exception as error:
                    messagebox.showerror("Lỗi sinh khóa", str(error))

            self.write_flow(self.basic_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi sinh khóa", str(error))

    def handle_encrypt(self):
        try:
            if self.generated_keys is None:
                raise ValueError("Bạn cần sinh khóa trước khi mã hóa.")

            m = self.get_int(self.basic_m_entry, "Plaintext M")

            e = self.generated_keys["e"]
            n = self.generated_keys["n"]

            steps = [
                "[1] Nhận plaintext M từ người dùng.",
                f"[2] Lấy public key = (e, n) = ({e}, {n}).",
                "[3] Áp dụng công thức RSA: C = M^e mod n.",
                f"[4] Thay số: C = {m}^{e} mod {n}.",
                "[5] Tính ciphertext C."
            ]

            def show_result():
                try:
                    c = encrypt(m, e, n)
                    self.last_ciphertext = c

                    self.basic_c_entry.delete(0, tk.END)
                    self.basic_c_entry.insert(0, str(c))

                    self.append_result_title(self.basic_output, "=== KẾT QUẢ MÃ HÓA ===")
                    self.write_text(self.basic_output, f"M = {m}")
                    self.write_text(self.basic_output, "C = M^e mod n")
                    self.write_text(self.basic_output, f"C = {m}^{e} mod {n}")
                    self.write_text(self.basic_output, f"C = {c}")

                except Exception as error:
                    messagebox.showerror("Lỗi mã hóa", str(error))

            self.write_flow(self.basic_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi mã hóa", str(error))

    def handle_decrypt(self):
        try:
            if self.generated_keys is None:
                raise ValueError("Bạn cần sinh khóa trước khi giải mã.")

            c = self.get_int(self.basic_c_entry, "Ciphertext C")

            d = self.generated_keys["d"]
            n = self.generated_keys["n"]

            steps = [
                "[1] Nhận ciphertext C từ người dùng.",
                f"[2] Lấy private key = (d, n) = ({d}, {n}).",
                "[3] Áp dụng công thức RSA: M = C^d mod n.",
                f"[4] Thay số: M = {c}^{d} mod {n}.",
                "[5] Tính lại plaintext M."
            ]

            def show_result():
                try:
                    m = decrypt(c, d, n)

                    self.append_result_title(self.basic_output, "=== KẾT QUẢ GIẢI MÃ ===")
                    self.write_text(self.basic_output, f"C = {c}")
                    self.write_text(self.basic_output, "M = C^d mod n")
                    self.write_text(self.basic_output, f"M = {c}^{d} mod {n}")
                    self.write_text(self.basic_output, f"M = {m}")

                except Exception as error:
                    messagebox.showerror("Lỗi giải mã", str(error))

            self.write_flow(self.basic_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi giải mã", str(error))

    # =========================
    # TAB 2: ATTACK
    # =========================

    def create_attack_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Attack")

        factor_frame = ttk.LabelFrame(tab, text="Attack 1: Factorization Attack")
        factor_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(factor_frame, text="n:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.factor_n_entry = ttk.Entry(factor_frame, width=20)
        self.factor_n_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(factor_frame, text="e:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.factor_e_entry = ttk.Entry(factor_frame, width=20)
        self.factor_e_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(factor_frame, text="ciphertext c:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.factor_c_entry = ttk.Entry(factor_frame, width=20)
        self.factor_c_entry.grid(row=0, column=5, padx=5, pady=5)

        ttk.Button(factor_frame, text="Tấn công", command=self.handle_factorization_attack).grid(
            row=0, column=6, padx=10, pady=5
        )

        fermat_frame = ttk.LabelFrame(tab, text="Attack 2: Fermat Attack")
        fermat_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(fermat_frame, text="n:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.fermat_n_entry = ttk.Entry(fermat_frame, width=20)
        self.fermat_n_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(fermat_frame, text="Tấn công", command=self.handle_fermat_attack).grid(
            row=0, column=2, padx=10, pady=5
        )

        guess_frame = ttk.LabelFrame(tab, text="Attack 3: Textbook RSA / Guessing Attack")
        guess_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(guess_frame, text="Plaintext nghi ngờ, cách nhau bằng dấu phẩy:").grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.guess_messages_entry = ttk.Entry(guess_frame, width=40)
        self.guess_messages_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=5, sticky="w")

        ttk.Label(guess_frame, text="e:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.guess_e_entry = ttk.Entry(guess_frame, width=20)
        self.guess_e_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(guess_frame, text="n:").grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.guess_n_entry = ttk.Entry(guess_frame, width=20)
        self.guess_n_entry.grid(row=1, column=3, padx=5, pady=5)

        ttk.Label(guess_frame, text="target ciphertext:").grid(row=1, column=4, padx=5, pady=5, sticky="w")
        self.guess_target_c_entry = ttk.Entry(guess_frame, width=20)
        self.guess_target_c_entry.grid(row=1, column=5, padx=5, pady=5)

        ttk.Button(guess_frame, text="Tấn công", command=self.handle_guessing_attack).grid(
            row=1, column=6, padx=10, pady=5
        )

        output_frame = ttk.LabelFrame(tab, text="Kết quả Attack")
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.attack_output = tk.Text(output_frame, height=20)
        self.attack_output.pack(fill="both", expand=True, padx=5, pady=5)

    def handle_factorization_attack(self):
        try:
            n = self.get_int(self.factor_n_entry, "n")
            e = self.get_int(self.factor_e_entry, "e")
            c = self.get_int(self.factor_c_entry, "ciphertext c")

            steps = [
                "[1] Attacker chỉ biết public key gồm e và n.",
                f"[2] Public key nhận được: e = {e}, n = {n}.",
                f"[3] Attacker có ciphertext c = {c}.",
                "[4] Vì n nhỏ, attacker thử chia n cho các số từ 2 đến căn bậc hai của n.",
                "[5] Nếu tìm được ước của n, attacker suy ra p và q.",
                "[6] Tính phi(n) = (p - 1)(q - 1).",
                "[7] Tính d = e^-1 mod phi(n).",
                "[8] Dùng d để giải mã ciphertext."
            ]

            def show_result():
                try:
                    result = factorization_attack(n, e, c)

                    self.append_result_title(self.attack_output, "=== KẾT QUẢ FACTORIZATION ATTACK ===")

                    if not result["success"]:
                        self.write_text(self.attack_output, result["message"])
                        return

                    self.write_text(self.attack_output, f"n = {result['n']}")
                    self.write_text(self.attack_output, f"e = {result['e']}")
                    self.write_text(self.attack_output, f"c = {result['c']}")
                    self.write_text(self.attack_output, "")
                    self.write_text(self.attack_output, f"Tìm được p = {result['p']}")
                    self.write_text(self.attack_output, f"Tìm được q = {result['q']}")
                    self.write_text(self.attack_output, f"phi = {result['phi']}")
                    self.write_text(self.attack_output, f"d = {result['d']}")
                    self.write_text(self.attack_output, f"Plaintext m = {result['plaintext']}")
                    self.write_text(self.attack_output, "")
                    self.write_text(self.attack_output, result["explanation"])

                except Exception as error:
                    messagebox.showerror("Lỗi Factorization Attack", str(error))

            self.write_flow(self.attack_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi Factorization Attack", str(error))

    def handle_fermat_attack(self):
        try:
            n = self.get_int(self.fermat_n_entry, "n")

            steps = [
                "[1] Nhận n từ người dùng.",
                "[2] Fermat Attack dùng khi p và q quá gần nhau.",
                "[3] Biểu diễn n dưới dạng n = a^2 - b^2.",
                "[4] Khi đó n = (a - b)(a + b).",
                "[5] Suy ra p = a - b và q = a + b.",
                "[6] Bắt đầu thử các giá trị a từ ceil(sqrt(n))."
            ]

            def show_result():
                try:
                    result = fermat_attack(n)

                    self.append_result_title(self.attack_output, "=== KẾT QUẢ FERMAT ATTACK ===")

                    if not result["success"]:
                        self.write_text(self.attack_output, result["message"])
                        self.write_text(self.attack_output, f"Số vòng lặp = {result['loops']}")
                        return

                    self.write_text(self.attack_output, f"n = {result['n']}")
                    self.write_text(self.attack_output, f"p = {result['p']}")
                    self.write_text(self.attack_output, f"q = {result['q']}")
                    self.write_text(self.attack_output, f"a = {result['a']}")
                    self.write_text(self.attack_output, f"b = {result['b']}")
                    self.write_text(self.attack_output, f"Số vòng lặp = {result['loops']}")
                    self.write_text(self.attack_output, "")
                    self.write_text(self.attack_output, result["explanation"])

                except Exception as error:
                    messagebox.showerror("Lỗi Fermat Attack", str(error))

            self.write_flow(self.attack_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi Fermat Attack", str(error))

    def handle_guessing_attack(self):
        try:
            raw_messages = self.guess_messages_entry.get().strip()

            if raw_messages == "":
                raise ValueError("Bạn chưa nhập danh sách plaintext nghi ngờ.")

            possible_messages = []

            for item in raw_messages.split(","):
                item = item.strip()

                if item == "":
                    continue

                possible_messages.append(int(item))

            if len(possible_messages) == 0:
                raise ValueError("Danh sách plaintext nghi ngờ không hợp lệ.")

            e = self.get_int(self.guess_e_entry, "e")
            n = self.get_int(self.guess_n_entry, "n")
            target_c = self.get_int(self.guess_target_c_entry, "target ciphertext")

            steps = [
                "[1] Attacker biết public key e, n và target ciphertext.",
                f"[2] Public key: e = {e}, n = {n}.",
                f"[3] Target ciphertext = {target_c}.",
                "[4] Vì RSA thô không padding có tính quyết định.",
                "[5] Cùng một plaintext luôn tạo ra cùng ciphertext.",
                "[6] Attacker mã hóa thử từng plaintext nghi ngờ.",
                "[7] So sánh ciphertext tạo ra với target ciphertext."
            ]

            def show_result():
                try:
                    result = guess_plaintext_attack(possible_messages, e, n, target_c)

                    self.append_result_title(self.attack_output, "=== KẾT QUẢ GUESSING ATTACK ===")

                    if result["success"]:
                        self.write_text(self.attack_output, f"Tìm thấy plaintext m = {result['found_plaintext']}")
                        self.write_text(self.attack_output, f"Target ciphertext = {result['target_ciphertext']}")
                        self.write_text(self.attack_output, "")
                        self.write_text(self.attack_output, result["explanation"])
                    else:
                        self.write_text(self.attack_output, result["message"])
                        self.write_text(self.attack_output, f"Target ciphertext = {result['target_ciphertext']}")

                    self.write_text(self.attack_output, "")
                    self.write_text(self.attack_output, "Các lần thử:")

                    for attempt in result["attempts"]:
                        if "error" in attempt:
                            self.write_text(
                                self.attack_output,
                                f"- Thử m = {attempt['plaintext_try']} -> lỗi: {attempt['error']}"
                            )
                        else:
                            self.write_text(
                                self.attack_output,
                                f"- Thử m = {attempt['plaintext_try']} -> "
                                f"c = {attempt['ciphertext_generated']} -> "
                                f"matched = {attempt['matched']}"
                            )

                except Exception as error:
                    messagebox.showerror("Lỗi Guessing Attack", str(error))

            self.write_flow(self.attack_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi Guessing Attack", str(error))

    # =========================
    # TAB 3: DEFENSE
    # =========================

    def create_defense_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Defense")

        security_frame = ttk.LabelFrame(tab, text="Kiểm tra an toàn RSA")
        security_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(security_frame, text="p:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.defense_p_entry = ttk.Entry(security_frame, width=20)
        self.defense_p_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(security_frame, text="q:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.defense_q_entry = ttk.Entry(security_frame, width=20)
        self.defense_q_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(security_frame, text="e:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.defense_e_entry = ttk.Entry(security_frame, width=20)
        self.defense_e_entry.grid(row=0, column=5, padx=5, pady=5)

        ttk.Button(security_frame, text="Kiểm tra an toàn", command=self.handle_check_security).grid(
            row=0, column=6, padx=10, pady=5
        )

        padding_frame = ttk.LabelFrame(tab, text="Demo padding")
        padding_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(padding_frame, text="m:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.padding_m_entry = ttk.Entry(padding_frame, width=20)
        self.padding_m_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(padding_frame, text="e:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.padding_e_entry = ttk.Entry(padding_frame, width=20)
        self.padding_e_entry.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(padding_frame, text="n:").grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.padding_n_entry = ttk.Entry(padding_frame, width=20)
        self.padding_n_entry.grid(row=0, column=5, padx=5, pady=5)

        ttk.Button(
            padding_frame,
            text="Mã hóa RSA thô 3 lần",
            command=self.handle_raw_rsa_three_times
        ).grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(
            padding_frame,
            text="Mã hóa có padding mô phỏng 3 lần",
            command=self.handle_padding_rsa_three_times
        ).grid(row=1, column=2, columnspan=2, padx=5, pady=5)

        output_frame = ttk.LabelFrame(tab, text="Kết quả Defense")
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.defense_output = tk.Text(output_frame, height=20)
        self.defense_output.pack(fill="both", expand=True, padx=5, pady=5)

    def handle_check_security(self):
        try:
            p = self.get_int(self.defense_p_entry, "p")
            q = self.get_int(self.defense_q_entry, "q")
            e = self.get_int(self.defense_e_entry, "e")

            steps = [
                "[1] Nhận p, q, e từ người dùng.",
                "[2] Kiểm tra p có phải số nguyên tố không.",
                "[3] Kiểm tra q có phải số nguyên tố không.",
                "[4] Kiểm tra p và q có bằng nhau không.",
                "[5] Tính n = p * q.",
                "[6] Kiểm tra số bit của n bằng n.bit_length().",
                "[7] Nếu n quá nhỏ thì cảnh báo nguy cơ Factorization Attack.",
                "[8] Tính |p - q| để kiểm tra nguy cơ Fermat Attack.",
                "[9] Kiểm tra e có hợp lệ không.",
                "[10] Cảnh báo RSA thô không padding."
            ]

            def show_result():
                try:
                    result = check_rsa_security(p, q, e)

                    self.append_result_title(self.defense_output, "=== KẾT QUẢ KIỂM TRA AN TOÀN RSA ===")
                    self.write_text(self.defense_output, f"p = {result['p']}")
                    self.write_text(self.defense_output, f"q = {result['q']}")
                    self.write_text(self.defense_output, f"e = {result['e']}")
                    self.write_text(self.defense_output, f"n = {result['n']}")
                    self.write_text(self.defense_output, f"phi = {result['phi']}")
                    self.write_text(self.defense_output, f"bit length của n = {result['bit_length']}")
                    self.write_text(self.defense_output, f"|p - q| = {result['distance']}")
                    self.write_text(self.defense_output, f"Kết luận rủi ro: {result['risk_level']}")

                    self.write_text(self.defense_output, "")
                    self.write_text(self.defense_output, "Các kiểm tra:")
                    for check in result["checks"]:
                        self.write_text(self.defense_output, check)

                    self.write_text(self.defense_output, "")
                    self.write_text(self.defense_output, "Khuyến nghị:")
                    for rec in result["recommendations"]:
                        self.write_text(self.defense_output, "- " + rec)

                except Exception as error:
                    messagebox.showerror("Lỗi kiểm tra an toàn", str(error))

            self.write_flow(self.defense_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi kiểm tra an toàn", str(error))

    def handle_raw_rsa_three_times(self):
        try:
            m = self.get_int(self.padding_m_entry, "m")
            e = self.get_int(self.padding_e_entry, "e")
            n = self.get_int(self.padding_n_entry, "n")

            steps = [
                "[1] Nhận plaintext m, e, n từ người dùng.",
                "[2] Mã hóa cùng một plaintext 3 lần bằng RSA thô.",
                "[3] Công thức mỗi lần đều là C = M^e mod n.",
                "[4] Vì không có padding nên đầu vào không thay đổi.",
                "[5] Dự đoán: 3 ciphertext sẽ giống nhau."
            ]

            def show_result():
                try:
                    result = raw_rsa_encrypt_three_times(m, e, n)

                    self.append_result_title(self.defense_output, "=== KẾT QUẢ RSA THÔ 3 LẦN ===")
                    self.write_text(self.defense_output, result["explanation"])
                    self.write_text(self.defense_output, "")

                    for item in result["results"]:
                        self.write_text(
                            self.defense_output,
                            f"Lần {item['time']}: m = {item['plaintext']} -> c = {item['ciphertext']}"
                        )

                    self.write_text(self.defense_output, "")
                    self.write_text(
                        self.defense_output,
                        "Nhận xét: 3 ciphertext giống nhau, chứng minh RSA thô có tính quyết định."
                    )

                except Exception as error:
                    messagebox.showerror("Lỗi RSA thô", str(error))

            self.write_flow(self.defense_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi RSA thô", str(error))

    def handle_padding_rsa_three_times(self):
        try:
            m = self.get_int(self.padding_m_entry, "m")
            e = self.get_int(self.padding_e_entry, "e")
            n = self.get_int(self.padding_n_entry, "n")

            steps = [
                "[1] Nhận plaintext m, e, n từ người dùng.",
                "[2] Mỗi lần mã hóa sẽ tạo một padding ngẫu nhiên.",
                "[3] Ghép padding vào plaintext để tạo padded_m.",
                "[4] Mã hóa padded_m bằng RSA.",
                "[5] Vì padding mỗi lần khác nhau nên ciphertext thường khác nhau.",
                "[6] Lưu ý: đây chỉ là mô phỏng ý tưởng, không phải OAEP chuẩn."
            ]

            def show_result():
                try:
                    result = padding_rsa_encrypt_three_times(m, e, n)

                    self.append_result_title(self.defense_output, "=== KẾT QUẢ PADDING MÔ PHỎNG 3 LẦN ===")
                    self.write_text(self.defense_output, result["explanation"])
                    self.write_text(self.defense_output, "")
                    self.write_text(self.defense_output, result["warning"])
                    self.write_text(self.defense_output, result["recommendation"])
                    self.write_text(self.defense_output, "")

                    for item in result["results"]:
                        self.write_text(
                            self.defense_output,
                            f"Lần {item['time']}: m = {item['original_plaintext']}, "
                            f"pad = {item['random_pad']}, "
                            f"padded_m = {item['padded_plaintext']} -> c = {item['ciphertext']}"
                        )

                    self.write_text(self.defense_output, "")
                    self.write_text(
                        self.defense_output,
                        "Nhận xét: ciphertext thường khác nhau, giúp chống kiểu đoán plaintext trong RSA thô."
                    )

                except Exception as error:
                    messagebox.showerror("Lỗi padding mô phỏng", str(error))

            self.write_flow(self.defense_output, steps, show_result)

        except Exception as error:
            messagebox.showerror("Lỗi padding mô phỏng", str(error))


if __name__ == "__main__":
    root = tk.Tk()
    app = RSADemoApp(root)
    root.mainloop()