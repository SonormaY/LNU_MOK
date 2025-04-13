import random
import math
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk


class KnapsackCrypto:
    def __init__(self):
        self.private_key = []
        self.public_key = []
        self.modulus = 0
        self.multiplier = 0
        self.inverse_multiplier = 0

    def gcd(self, a, b):
        """Знаходження найбільшого спільного дільника"""
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(self, a, m):
        """Знаходження мультиплікативно оберненого за модулем"""
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    def generate_superincreasing_sequence(self, length):
        """Генерація надзростаючої послідовності"""
        sequence = []
        total = 0

        for i in range(length):
            # Новий елемент більший за суму попередніх
            next_value = total + random.randint(1, 10)
            sequence.append(next_value)
            total += next_value

        return sequence

    def generate_keys(self, length=8):
        """Генерація пари ключів"""
        # Генерація надзростаючої послідовності (закритий ключ)
        self.private_key = self.generate_superincreasing_sequence(length)

        # Вибір модуля (більший за суму всіх елементів закритого ключа)
        total_sum = sum(self.private_key)
        self.modulus = total_sum + random.randint(1, 100)

        # Вибір множника (взаємно простий з модулем)
        while True:
            self.multiplier = random.randint(2, self.modulus - 1)
            if self.gcd(self.multiplier, self.modulus) == 1:
                break

        # Обчислення мультиплікативно оберненого
        self.inverse_multiplier = self.mod_inverse(self.multiplier, self.modulus)

        # Створення відкритого ключа
        self.public_key = [
            (self.multiplier * x) % self.modulus for x in self.private_key
        ]

        return {
            "public_key": self.public_key,
            "private_key": self.private_key,
            "modulus": self.modulus,
            "multiplier": self.multiplier,
            "inverse_multiplier": self.inverse_multiplier,
        }

    def set_keys(
        self, public_key, private_key, modulus, multiplier, inverse_multiplier
    ):
        """Встановити власні ключі"""
        self.public_key = public_key
        self.private_key = private_key
        self.modulus = modulus
        self.multiplier = multiplier
        self.inverse_multiplier = inverse_multiplier

    def encrypt(self, message, public_key=None):
        """Шифрування повідомлення"""
        if public_key is None:
            public_key = self.public_key

        # Перетворення повідомлення в бінарний формат
        binary = "".join(format(ord(char), "08b") for char in message)

        # Перевіряємо, чи довжина бінарного повідомлення не перевищує довжину відкритого ключа
        if len(binary) > len(public_key):
            # Розбиваємо на блоки
            encrypted_blocks = []
            for i in range(0, len(binary), len(public_key)):
                block = binary[i : i + len(public_key)]
                if len(block) < len(public_key):
                    block = block.ljust(len(public_key), "0")
                encrypted_blocks.append(self.encrypt_block(block, public_key))
            return encrypted_blocks
        else:
            # Доповнюємо нулями, якщо потрібно
            if len(binary) < len(public_key):
                binary = binary.ljust(len(public_key), "0")
            return [self.encrypt_block(binary, public_key)]

    def encrypt_block(self, binary_block, public_key):
        """Шифрування одного блоку даних"""
        encrypted_sum = 0

        for i in range(len(binary_block)):
            if i < len(public_key) and binary_block[i] == "1":
                encrypted_sum += public_key[i]

        return encrypted_sum

    def decrypt(
        self, encrypted_blocks, private_key=None, modulus=None, inverse_multiplier=None
    ):
        """Розшифрування повідомлення"""
        if private_key is None:
            private_key = self.private_key
        if modulus is None:
            modulus = self.modulus
        if inverse_multiplier is None:
            inverse_multiplier = self.inverse_multiplier

        binary_message = ""

        for encrypted_sum in encrypted_blocks:
            # Застосовуємо обернений множник
            s_prime = (encrypted_sum * inverse_multiplier) % modulus

            # Розшифровуємо за допомогою закритого ключа
            binary_block = self.decrypt_block(s_prime, private_key)
            binary_message += binary_block

        # Перетворюємо двійковий рядок назад у текст
        text = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i : i + 8]
            if (
                byte and all(b in "01" for b in byte) and len(byte) == 8
            ):  # Перевірка на коректний байт
                text += chr(int(byte, 2))

        return text

    def decrypt_block(self, s_prime, private_key):
        """Розшифрування одного блоку даних"""
        binary_result = ["0"] * len(private_key)

        # Проходимо по закритому ключу з кінця
        for i in range(len(private_key) - 1, -1, -1):
            if s_prime >= private_key[i]:
                binary_result[i] = "1"
                s_prime -= private_key[i]

        return "".join(binary_result)


class KnapsackApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Криптографічна система на основі задачі рюкзака")
        self.root.geometry("900x700")

        self.crypto = KnapsackCrypto()
        self.setup_ui()

    def setup_ui(self):
        # Головний контейнер з вкладками
        self.tab_control = ttk.Notebook(self.root)

        # Вкладка для автоматичної генерації ключів
        self.tab_auto = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_auto, text="Автоматична генерація")

        # Вкладка для ручного введення ключів
        self.tab_manual = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_manual, text="Ручне введення ключів")

        self.tab_control.pack(expand=1, fill="both")

        # Налаштування першої вкладки (автогенерація)
        self.setup_auto_tab()

        # Налаштування другої вкладки (ручне введення)
        self.setup_manual_tab()

    def setup_auto_tab(self):
        # Фрейм для генерації ключів
        key_frame = tk.LabelFrame(
            self.tab_auto, text="Генерація ключів", padx=10, pady=10
        )
        key_frame.pack(fill="x", padx=10, pady=10)

        tk.Button(
            key_frame, text="Згенерувати ключі", command=self.generate_keys_dialog
        ).pack(pady=5)

        # Фрейм для відображення ключів
        display_frame = tk.LabelFrame(
            self.tab_auto, text="Інформація про ключі", padx=10, pady=10
        )
        display_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.key_display = scrolledtext.ScrolledText(display_frame, height=10)
        self.key_display.pack(fill="both", expand=True, pady=5)

        # Фрейм для шифрування/розшифрування
        self.create_crypto_frame(self.tab_auto)

    def setup_manual_tab(self):
        # Фрейм для введення ключів
        manual_key_frame = tk.LabelFrame(
            self.tab_manual, text="Введення ключів", padx=10, pady=10
        )
        manual_key_frame.pack(fill="x", padx=10, pady=10)

        # Публічний ключ
        public_frame = tk.Frame(manual_key_frame)
        public_frame.pack(fill="x", pady=5)

        tk.Label(public_frame, text="Відкритий ключ (через кому):").pack(
            side="top", anchor="w", padx=5
        )
        self.public_key_entry = scrolledtext.ScrolledText(public_frame, height=3)
        self.public_key_entry.pack(fill="x", pady=5)

        # Приватний ключ
        private_frame = tk.Frame(manual_key_frame)
        private_frame.pack(fill="x", pady=5)

        tk.Label(private_frame, text="Закритий ключ (через кому):").pack(
            side="top", anchor="w", padx=5
        )
        self.private_key_entry = scrolledtext.ScrolledText(private_frame, height=3)
        self.private_key_entry.pack(fill="x", pady=5)

        # Модуль і множники
        params_frame = tk.Frame(manual_key_frame)
        params_frame.pack(fill="x", pady=5)

        tk.Label(params_frame, text="Модуль (m):").grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.modulus_entry = tk.Entry(params_frame, width=15)
        self.modulus_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(params_frame, text="Множник (t):").grid(
            row=1, column=0, padx=5, pady=5, sticky="w"
        )
        self.multiplier_entry = tk.Entry(params_frame, width=15)
        self.multiplier_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(params_frame, text="Обернений множник (t^-1):").grid(
            row=2, column=0, padx=5, pady=5, sticky="w"
        )
        self.inverse_entry = tk.Entry(params_frame, width=15)
        self.inverse_entry.grid(row=2, column=1, padx=5, pady=5)

        # Кнопка застосування ключів
        tk.Button(
            manual_key_frame, text="Застосувати ключі", command=self.apply_manual_keys
        ).pack(pady=10)

        # Фрейм для шифрування/розшифрування
        self.create_crypto_frame(self.tab_manual)

    def create_crypto_frame(self, parent):
        # Фрейм для шифрування/розшифрування
        crypto_frame = tk.LabelFrame(
            parent, text="Шифрування та розшифрування", padx=10, pady=10
        )
        crypto_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Поле для введення повідомлення (велике)
        input_frame = tk.Frame(crypto_frame)
        input_frame.pack(fill="x", pady=5)

        tk.Label(input_frame, text="Повідомлення:").pack(side="top", anchor="w", padx=5)

        self.message_text = scrolledtext.ScrolledText(input_frame, height=5)
        self.message_text.pack(fill="both", expand=True, pady=5)

        # Кнопки для шифрування/розшифрування
        button_frame = tk.Frame(crypto_frame)
        button_frame.pack(fill="x", pady=5)

        tk.Button(
            button_frame,
            text="Зашифрувати текст",
            command=lambda: self.encrypt_message(parent),
        ).pack(side="left", padx=5)
        tk.Button(
            button_frame,
            text="Розшифрувати шифртекст",
            command=lambda: self.decrypt_message(parent),
        ).pack(side="left", padx=5)
        tk.Button(button_frame, text="Очистити", command=self.clear_message).pack(
            side="right", padx=5
        )

        # Фрейм для результатів
        result_frame = tk.LabelFrame(parent, text="Результати", padx=10, pady=10)
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)

        if parent == self.tab_auto:
            self.result_display_auto = scrolledtext.ScrolledText(result_frame, height=8)
            self.result_display_auto.pack(fill="both", expand=True, pady=5)
        else:
            self.result_display_manual = scrolledtext.ScrolledText(
                result_frame, height=8
            )
            self.result_display_manual.pack(fill="both", expand=True, pady=5)

    def generate_keys_dialog(self):
        length = simpledialog.askinteger(
            "Довжина ключа",
            "Введіть довжину ключа (кількість бітів):",
            minvalue=4,
            maxvalue=32,
            initialvalue=8,
        )

        if length:
            self.generate_keys(length)

    def generate_keys(self, length):
        keys = self.crypto.generate_keys(length)

        self.key_display.delete(1.0, tk.END)
        self.key_display.insert(tk.END, "ВІДКРИТИЙ КЛЮЧ:\n")
        self.key_display.insert(tk.END, str(keys["public_key"]) + "\n\n")

        self.key_display.insert(tk.END, "ЗАКРИТИЙ КЛЮЧ:\n")
        self.key_display.insert(tk.END, str(keys["private_key"]) + "\n\n")

        self.key_display.insert(tk.END, f"Модуль (m): {keys['modulus']}\n")
        self.key_display.insert(tk.END, f"Множник (t): {keys['multiplier']}\n")
        self.key_display.insert(
            tk.END, f"Обернений множник (t^-1): {keys['inverse_multiplier']}\n"
        )

        messagebox.showinfo("Успіх", "Ключі успішно згенеровано!")

    def apply_manual_keys(self):
        try:
            # Отримуємо дані з полів
            public_key_str = self.public_key_entry.get(1.0, tk.END).strip()
            private_key_str = self.private_key_entry.get(1.0, tk.END).strip()
            modulus = int(self.modulus_entry.get())
            multiplier = int(self.multiplier_entry.get())
            inverse_multiplier = int(self.inverse_entry.get())

            # Перетворюємо рядки ключів у списки чисел
            try:
                public_key = [int(x.strip()) for x in public_key_str.split(",")]
                private_key = [int(x.strip()) for x in private_key_str.split(",")]
            except:
                messagebox.showerror(
                    "Помилка", "Ключі повинні бути числами, розділеними комами!"
                )
                return

            # Перевірка надзростаючої послідовності
            is_superincreasing = True
            sum_so_far = 0
            for num in private_key:
                if num <= sum_so_far:
                    is_superincreasing = False
                    break
                sum_so_far += num

            if not is_superincreasing:
                if not messagebox.askyesno(
                    "Увага",
                    "Закритий ключ не є надзростаючою послідовністю. Продовжити?",
                ):
                    return

            # Перевірка коректності ключів
            if len(public_key) != len(private_key):
                messagebox.showerror(
                    "Помилка",
                    "Відкритий і закритий ключі повинні мати однакову довжину!",
                )
                return

            # Перевірка оберненого множника
            if (multiplier * inverse_multiplier) % modulus != 1:
                if not messagebox.askyesno(
                    "Увага",
                    f"{multiplier} * {inverse_multiplier} ≠ 1 (mod {modulus}). Продовжити?",
                ):
                    return

            # Встановлюємо ключі
            self.crypto.set_keys(
                public_key, private_key, modulus, multiplier, inverse_multiplier
            )

            messagebox.showinfo("Успіх", "Ключі успішно застосовано!")

        except ValueError as e:
            messagebox.showerror("Помилка", f"Помилка введення: {str(e)}")
        except Exception as e:
            messagebox.showerror("Помилка", f"Невідома помилка: {str(e)}")

    def clear_message(self):
        self.message_text.delete(1.0, tk.END)

    def encrypt_message(self, parent):
        message = self.message_text.get(1.0, tk.END).strip()

        if not message:
            messagebox.showerror("Помилка", "Введіть повідомлення для шифрування!")
            return

        if not self.crypto.public_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте або введіть ключі!")
            return

        encrypted = self.crypto.encrypt(message)

        result_display = (
            self.result_display_auto
            if parent == self.tab_auto
            else self.result_display_manual
        )
        result_display.delete(1.0, tk.END)
        result_display.insert(tk.END, "ЗАШИФРОВАНЕ ПОВІДОМЛЕННЯ:\n")
        result_display.insert(tk.END, str(encrypted) + "\n\n")

    def decrypt_message(self, parent):
        try:
            # Спробуємо спочатку інтерпретувати повідомлення як зашифрований текст
            message = self.message_text.get(1.0, tk.END).strip()

            if not message:
                messagebox.showerror(
                    "Помилка", "Введіть зашифроване повідомлення для розшифрування!"
                )
                return

            if not self.crypto.private_key:
                messagebox.showerror(
                    "Помилка", "Спочатку згенеруйте або введіть ключі!"
                )
                return

            # Перевіряємо, чи це зашифроване повідомлення (список чисел)
            try:
                encrypted_blocks = eval(message)
                if not isinstance(encrypted_blocks, list) or not all(
                    isinstance(x, int) for x in encrypted_blocks
                ):
                    raise ValueError("Невірний формат зашифрованого повідомлення")
            except:
                messagebox.showerror(
                    "Помилка",
                    "Зашифроване повідомлення повинно бути у форматі списку чисел!",
                )
                return

            decrypted = self.crypto.decrypt(encrypted_blocks)

            result_display = (
                self.result_display_auto
                if parent == self.tab_auto
                else self.result_display_manual
            )
            result_display.delete(1.0, tk.END)
            result_display.insert(tk.END, "РОЗШИФРОВАНЕ ПОВІДОМЛЕННЯ:\n")
            result_display.insert(tk.END, decrypted + "\n")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка при розшифруванні: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = KnapsackApp(root)
    root.mainloop()
