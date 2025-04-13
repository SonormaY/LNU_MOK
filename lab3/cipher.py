import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import string
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import pickle
import random
import secrets

class GammaCipher:
    # шифрування/розшифрування методом гамування
    
    def __init__(self):
        self.ua_alphabet = ' абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        self.ua_alphabet_upper = ' АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ'
        self.en_alphabet = ' abcdefghijklmnopqrstuvwxyz'
        self.en_alphabet_upper = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.punctuation = string.punctuation + '№«»—'
        
    def generate_gamma(self, length, alphabet_type, seed=None):
        # робить випадкову гаму
        if seed is not None:
            random.seed(seed)
        
        gamma = ""
        if alphabet_type == "ukrainian":
            alphabet = self.ua_alphabet
            for _ in range(length):
                gamma += random.choice(alphabet)
        else:  # латинський
            alphabet = self.en_alphabet
            for _ in range(length):
                gamma += random.choice(alphabet)
        
        return gamma
    
    def generate_vernam_key(self, length, alphabet_type):
        # для шифру вернама - одноразовий блокнот
        return self.generate_gamma(length, alphabet_type, seed=None)
    
    def encrypt_gamma(self, text, gamma, alphabet_type):
        # шифруємо текст гамою
        result = ""
        
        # якщо гама коротша за текст
        if len(gamma) < len(text):
            repetitions = len(text) // len(gamma) + 1
            gamma = gamma * repetitions
        
        gamma_idx = 0  # поточний індекс в гамі
        
        for char in text:
            if alphabet_type == "ukrainian":
                if char in self.ua_alphabet:
                    char_index = self.ua_alphabet.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.ua_alphabet.find(gamma_char.lower())
                    new_index = (char_index + gamma_index) % len(self.ua_alphabet)
                    result += self.ua_alphabet[new_index]
                    gamma_idx += 1
                elif char in self.ua_alphabet_upper:
                    char_index = self.ua_alphabet_upper.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.ua_alphabet.find(gamma_char.lower())
                    new_index = (char_index + gamma_index) % len(self.ua_alphabet_upper)
                    result += self.ua_alphabet_upper[new_index]
                    gamma_idx += 1
                elif char in self.punctuation:
                    result += char  # пунктуацію не шифруємо
                else:
                    result += char  # інші символи теж
            else:  # якщо латинський алфавіт
                if char in self.en_alphabet:
                    char_index = self.en_alphabet.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.en_alphabet.find(gamma_char.lower())
                    new_index = (char_index + gamma_index) % len(self.en_alphabet)
                    result += self.en_alphabet[new_index]
                    gamma_idx += 1
                elif char in self.en_alphabet_upper:
                    char_index = self.en_alphabet_upper.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.en_alphabet.find(gamma_char.lower())
                    new_index = (char_index + gamma_index) % len(self.en_alphabet_upper)
                    result += self.en_alphabet_upper[new_index]
                    gamma_idx += 1
                elif char in self.punctuation:
                    result += char  # пунктуацію не шифруємо
                else:
                    result += char  # інші символи теж
        
        return result
    
    def decrypt_gamma(self, encrypted_text, gamma, alphabet_type):
        # розшифровуємо - все як при шифруванні, але віднімаємо індекси
        result = ""
        
        if len(gamma) < len(encrypted_text):
            repetitions = len(encrypted_text) // len(gamma) + 1
            gamma = gamma * repetitions
        
        gamma_idx = 0
        
        for char in encrypted_text:
            if alphabet_type == "ukrainian":
                if char in self.ua_alphabet:
                    char_index = self.ua_alphabet.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.ua_alphabet.find(gamma_char.lower())
                    new_index = (char_index - gamma_index) % len(self.ua_alphabet)
                    result += self.ua_alphabet[new_index]
                    gamma_idx += 1
                elif char in self.ua_alphabet_upper:
                    char_index = self.ua_alphabet_upper.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.ua_alphabet.find(gamma_char.lower())
                    new_index = (char_index - gamma_index) % len(self.ua_alphabet_upper)
                    result += self.ua_alphabet_upper[new_index]
                    gamma_idx += 1
                elif char in self.punctuation:
                    result += char
                else:
                    result += char
            else:  # латинський алфавіт
                if char in self.en_alphabet:
                    char_index = self.en_alphabet.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.en_alphabet.find(gamma_char.lower())
                    new_index = (char_index - gamma_index) % len(self.en_alphabet)
                    result += self.en_alphabet[new_index]
                    gamma_idx += 1
                elif char in self.en_alphabet_upper:
                    char_index = self.en_alphabet_upper.find(char)
                    gamma_char = gamma[gamma_idx % len(gamma)]
                    gamma_index = self.en_alphabet.find(gamma_char.lower())
                    new_index = (char_index - gamma_index) % len(self.en_alphabet_upper)
                    result += self.en_alphabet_upper[new_index]
                    gamma_idx += 1
                elif char in self.punctuation:
                    result += char
                else:
                    result += char
        
        return result

    def encrypt_vernam(self, text, key, alphabet_type):
        # шифр вернама - по суті те саме гамування, але ключ = довжині тексту
        if len(key) < len(text):
            raise ValueError("Ключ має бути не коротшим за текст")
            
        return self.encrypt_gamma(text, key, alphabet_type)
    
    def decrypt_vernam(self, encrypted_text, key, alphabet_type):
        # розшифрування вернама
        if len(key) < len(encrypted_text):
            raise ValueError("Ключ має бути не коротшим за текст")
            
        return self.decrypt_gamma(encrypted_text, key, alphabet_type)
    
    def save_key_to_file(self, key, file_path):
        # зберігаємо ключ
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(key)
    
    def load_key_from_file(self, file_path):
        # завантажуємо ключ
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()

class CipherGUI:    
    def __init__(self, root):
        self.root = root
        self.root.title("Криптосистема")
        self.root.geometry("800x800")
        
        self.gamma_cipher = GammaCipher()
        self.validator = CipherValidator()
        self.binary_encryption = BinaryEncryption()
        
        self.current_file = None
        self.current_gamma = None
        self.current_vernam_key = None

        self.create_menu()
        self.create_main_interface()
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Створити", command=self.new_file)
        file_menu.add_command(label="Відкрити", command=self.open_file)
        file_menu.add_command(label="Зберегти", command=self.save_file)
        file_menu.add_command(label="Зберегти як", command=self.save_file_as)
        file_menu.add_separator()
        file_menu.add_command(label="Друкувати", command=self.print_file)
        file_menu.add_separator()
        file_menu.add_command(label="Вихід", command=self.exit_app)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        encryption_menu = tk.Menu(menubar, tearoff=0)
        encryption_menu.add_command(label="Шифрувати файл", command=self.encrypt_file)
        encryption_menu.add_command(label="Розшифрувати файл", command=self.decrypt_file)
        menubar.add_cascade(label="Шифрування", menu=encryption_menu)
        
        gamma_menu = tk.Menu(menubar, tearoff=0)
        gamma_menu.add_command(label="Генерувати гаму", command=self.generate_gamma)
        gamma_menu.add_command(label="Завантажити гаму з файлу", command=self.load_gamma_from_file)
        gamma_menu.add_command(label="Зберегти гаму у файл", command=self.save_gamma_to_file)
        gamma_menu.add_separator()
        gamma_menu.add_command(label="Шифрувати методом гамування", command=self.encrypt_with_gamma)
        gamma_menu.add_command(label="Розшифрувати методом гамування", command=self.decrypt_with_gamma)
        menubar.add_cascade(label="Гамування", menu=gamma_menu)
        
        vernam_menu = tk.Menu(menubar, tearoff=0)
        vernam_menu.add_command(label="Генерувати ключ Вернама", command=self.generate_vernam_key)
        vernam_menu.add_command(label="Завантажити ключ Вернама", command=self.load_vernam_key)
        vernam_menu.add_command(label="Зберегти ключ Вернама", command=self.save_vernam_key)
        vernam_menu.add_separator()
        vernam_menu.add_command(label="Шифрувати методом Вернама", command=self.encrypt_with_vernam)
        vernam_menu.add_command(label="Розшифрувати методом Вернама", command=self.decrypt_with_vernam)
        menubar.add_cascade(label="Шифр Вернама", menu=vernam_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Про програму", command=self.show_about)
        menubar.add_cascade(label="Допомога", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def create_main_interface(self):
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        # вибір алфавіту
        ttk.Label(control_frame, text="Алфавіт:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.alphabet_var = tk.StringVar(value="ukrainian")
        ttk.Radiobutton(control_frame, text="Український", variable=self.alphabet_var, value="ukrainian").grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(control_frame, text="Латинський", variable=self.alphabet_var, value="latin").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # вибір методу
        ttk.Label(control_frame, text="Метод шифрування:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.encryption_method_var = tk.StringVar(value="gamma")
        ttk.Radiobutton(control_frame, text="Гамування", variable=self.encryption_method_var, value="gamma").grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(control_frame, text="Вернам", variable=self.encryption_method_var, value="vernam").grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        # інфа про гаму
        ttk.Label(control_frame, text="Гама:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.gamma_info_var = tk.StringVar(value="Гама не згенерована")
        ttk.Label(control_frame, textvariable=self.gamma_info_var).grid(row=3, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # інфа про ключ вернама
        ttk.Label(control_frame, text="Ключ Вернама:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.vernam_key_info_var = tk.StringVar(value="Ключ не згенерований")
        ttk.Label(control_frame, textvariable=self.vernam_key_info_var).grid(row=4, column=1, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # кнопки шифрування
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=5, column=0, columnspan=4, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Шифрувати", command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Розшифрувати", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        
        # текстові поля
        text_frame = ttk.Frame(self.root, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(text_frame, text="Вхідний текст:").pack(anchor=tk.W)
        
        self.input_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(text_frame, text="Результат:").pack(anchor=tk.W)
        
        self.output_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # статус
        self.status_var = tk.StringVar()
        self.status_var.set("Готово")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def new_file(self):
        self.input_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.current_file = None
        self.status_var.set("Створено новий файл")
    
    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Відкрити файл",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.input_text.delete(1.0, tk.END)
                    self.input_text.insert(tk.END, content)
                self.current_file = file_path
                self.status_var.set(f"Відкрито файл: {file_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося відкрити файл: {e}")
    
    def save_file(self):
        if self.current_file:
            self._save_to_file(self.current_file)
        else:
            self.save_file_as()
    
    def save_file_as(self):
        file_path = filedialog.asksaveasfilename(
            title="Зберегти файл як",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
            defaultextension=".txt"
        )
        
        if file_path:
            self._save_to_file(file_path)
    
    def _save_to_file(self, file_path):
        try:
            content = self.output_text.get(1.0, tk.END)
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(content)
            self.current_file = file_path
            self.status_var.set(f"Файл збережено: {file_path}")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося зберегти файл: {e}")
    
    def generate_gamma(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть текст перед генерацією гами")
            return
        
        # гама в 1.5 рази більша за вхідний текст
        gamma_length = int(len(text) * 1.5)
        self.current_gamma = self.gamma_cipher.generate_gamma(gamma_length, alphabet_type)
        
        self.gamma_info_var.set(f"Згенеровано гаму довжиною {len(self.current_gamma)} символів")
        self.status_var.set("Гаму згенеровано")
        
        messagebox.showinfo("Генерація гами", f"Гаму успішно згенеровано з довжиною {len(self.current_gamma)} символів")
    
    def load_gamma_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Завантажити гаму з файлу",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")]
        )
        
        if file_path:
            try:
                self.current_gamma = self.gamma_cipher.load_key_from_file(file_path)
                self.gamma_info_var.set(f"Завантажено гаму з файлу довжиною {len(self.current_gamma)} символів")
                self.status_var.set(f"Гаму завантажено з {file_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося завантажити гаму: {e}")
    
    def save_gamma_to_file(self):
        if not self.current_gamma:
            messagebox.showerror("Помилка", "Спочатку згенеруйте гаму")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Зберегти гаму у файл",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
            defaultextension=".txt"
        )
        
        if file_path:
            try:
                self.gamma_cipher.save_key_to_file(self.current_gamma, file_path)
                self.status_var.set(f"Гаму збережено у {file_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося зберегти гаму: {e}")
    
    def encrypt_with_gamma(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть текст для шифрування")
            return
            
        if not self.current_gamma:
            messagebox.showerror("Помилка", "Спочатку згенеруйте гаму")
            return
            
        encrypted_text = self.gamma_cipher.encrypt_gamma(text, self.current_gamma, alphabet_type)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, encrypted_text)
        self.status_var.set("Текст зашифровано методом гамування")
    
    def decrypt_with_gamma(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть зашифрований текст")
            return
            
        if not self.current_gamma:
            messagebox.showerror("Помилка", "Спочатку завантажте гаму")
            return
            
        decrypted_text = self.gamma_cipher.decrypt_gamma(text, self.current_gamma, alphabet_type)
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, decrypted_text)
        self.status_var.set("Текст розшифровано методом гамування")
    
    def generate_vernam_key(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть текст перед генерацією ключа")
            return
        
        # довжина ключа = довжині тексту
        self.current_vernam_key = self.gamma_cipher.generate_vernam_key(len(text), alphabet_type)
        
        self.vernam_key_info_var.set(f"Згенеровано ключ довжиною {len(self.current_vernam_key)} символів")
        self.status_var.set("Ключ Вернама згенеровано")
        
        messagebox.showinfo("Генерація ключа", f"Ключ Вернама успішно згенеровано з довжиною {len(self.current_vernam_key)} символів")
    
    def load_vernam_key(self):
        file_path = filedialog.askopenfilename(
            title="Завантажити ключ Вернама",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")]
        )
        
        if file_path:
            try:
                self.current_vernam_key = self.gamma_cipher.load_key_from_file(file_path)
                self.vernam_key_info_var.set(f"Завантажено ключ довжиною {len(self.current_vernam_key)} символів")
                self.status_var.set(f"Ключ завантажено з {file_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося завантажити ключ: {e}")
    
    def save_vernam_key(self):
        if not self.current_vernam_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Зберегти ключ Вернама",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
            defaultextension=".txt"
        )
        
        if file_path:
            try:
                self.gamma_cipher.save_key_to_file(self.current_vernam_key, file_path)
                self.status_var.set(f"Ключ збережено у {file_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося зберегти ключ: {e}")
    
    def encrypt_with_vernam(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть текст для шифрування")
            return
            
        if not self.current_vernam_key:
            messagebox.showerror("Помилка", "Спочатку згенеруйте ключ Вернама")
            return
            
        try:
            encrypted_text = self.gamma_cipher.encrypt_vernam(text, self.current_vernam_key, alphabet_type)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, encrypted_text)
            self.status_var.set("Текст зашифровано методом Вернама")
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
    
    def decrypt_with_vernam(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Введіть зашифрований текст")
            return
            
        if not self.current_vernam_key:
            messagebox.showerror("Помилка", "Спочатку завантажте ключ Вернама")
            return
            
        try:
            decrypted_text = self.gamma_cipher.decrypt_vernam(text, self.current_vernam_key, alphabet_type)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, decrypted_text)
            self.status_var.set("Текст розшифровано методом Вернама")
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
    
    def encrypt_text(self):
        method = self.encryption_method_var.get()
        if method == "gamma":
            self.encrypt_with_gamma()
        elif method == "vernam":
            self.encrypt_with_vernam()
    
    def decrypt_text(self):
        method = self.encryption_method_var.get()
        if method == "gamma":
            self.decrypt_with_gamma()
        elif method == "vernam":
            self.decrypt_with_vernam()
    
    def encrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Вибрати файл для шифрування",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")]
        )
        
        if not file_path:
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Зберегти зашифрований файл як",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
            defaultextension=".txt"
        )
        
        if not save_path:
            return
            
        try:
            method = self.encryption_method_var.get()
            alphabet_type = self.alphabet_var.get()
            
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
                
            if method == "gamma":
                if not self.current_gamma:
                    messagebox.showerror("Помилка", "Спочатку згенеруйте гаму")
                    return
                encrypted_text = self.gamma_cipher.encrypt_gamma(text, self.current_gamma, alphabet_type)
            elif method == "vernam":
                if not self.current_vernam_key:
                    messagebox.showerror("Помилка", "Спочатку згенеруйте ключ Вернама")
                    return
                try:
                    encrypted_text = self.gamma_cipher.encrypt_vernam(text, self.current_vernam_key, alphabet_type)
                except ValueError as e:
                    messagebox.showerror("Помилка", str(e))
                    return
                    
                    
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_text)
                
            self.status_var.set(f"Файл зашифровано та збережено як {save_path}")
            messagebox.showinfo("Успіх", "Файл успішно зашифровано")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося зашифрувати файл: {e}")
    
    def decrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Вибрати файл для розшифрування",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")]
        )
        
        if not file_path:
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Зберегти розшифрований файл як",
            filetypes=[("Текстові файли", "*.txt"), ("Усі файли", "*.*")],
            defaultextension=".txt"
        )
        
        if not save_path:
            return
            
        try:
            method = self.encryption_method_var.get()
            alphabet_type = self.alphabet_var.get()
            
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
                
            if method == "gamma":
                if not self.current_gamma:
                    messagebox.showerror("Помилка", "Спочатку завантажте гаму")
                    return
                decrypted_text = self.gamma_cipher.decrypt_gamma(text, self.current_gamma, alphabet_type)
            elif method == "vernam":
                if not self.current_vernam_key:
                    messagebox.showerror("Помилка", "Спочатку завантажте ключ Вернама")
                    return
                try:
                    decrypted_text = self.gamma_cipher.decrypt_vernam(text, self.current_vernam_key, alphabet_type)
                except ValueError as e:
                    messagebox.showerror("Помилка", str(e))
                    return
                    
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_text)
                
            self.status_var.set(f"Файл розшифровано та збережено як {save_path}")
            messagebox.showinfo("Успіх", "Файл успішно розшифровано")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося розшифрувати файл: {e}")
    
          
    def print_file(self):
        try:
            import subprocess
            import tempfile
            import os

            # беремо текст для друку з результатів шифрування
            content = self.output_text.get(1.0, tk.END)
            
            if not content.strip():
                messagebox.showwarning("Друк", "Немає зашифрованого тексту для друку")
                return
            
            # створюємо тимчасовий файл
            with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w', encoding='utf-8') as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(content)
            
            self.status_var.set("Готуємо шифр до друку...")
            self.root.update_idletasks()
            
            # отримуємо список принтерів
            printers_output = subprocess.run(['lpstat', '-p'], capture_output=True, text=True)
            
            if printers_output.returncode == 0 and printers_output.stdout.strip():
                # вікно вибору принтера
                printer_window = tk.Toplevel(self.root)
                printer_window.title("Вибір принтера для шифру")
                printer_window.geometry("400x400")

                # парсимо список принтерів
                printers = []
                for line in printers_output.stdout.strip().split('\n'):
                    if line.startswith("printer"):
                        # достаємо ім'я принтера
                        printer_name = line.split()[1]
                        printers.append(printer_name)
                
                if not printers:
                    messagebox.showinfo("Друк", "Немає принтерів для шифру")
                    os.unlink(temp_file_path)
                    return
                
                # віджети вікна
                printers_frame = ttk.Frame(printer_window, padding="10")
                printers_frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(printers_frame, text="Вибери принтер для криптоданих:").pack(anchor=tk.W, pady=5)
                
                # список принтерів
                printer_var = tk.StringVar(value=printers[0])
                printer_listbox = tk.Listbox(printers_frame, listvariable=tk.StringVar(value=printers), height=10)
                printer_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
                printer_listbox.selection_set(0)
                
                button_frame = ttk.Frame(printer_window, padding="10")
                button_frame.pack(fill=tk.X)
                
                # функція друку на вибраний принтер
                def send_to_print():
                    selected_indices = printer_listbox.curselection()
                    if selected_indices:
                        selected_printer = printers[selected_indices[0]]
                        try:
                            print_process = subprocess.run(
                                ['lp', '-d', selected_printer, temp_file_path],
                                capture_output=True,
                                text=True
                            )
                            
                            if print_process.returncode == 0:
                                messagebox.showinfo("Друк", f"Шифр відправлено на {selected_printer}")
                                self.status_var.set(f"Шифр відправлено на {selected_printer}")
                            else:
                                messagebox.showerror("Помилка", f"Шифр не надруковано: {print_process.stderr}")
                                self.status_var.set("Помилка друку шифру")
                        except Exception as e:
                            messagebox.showerror("Помилка", f"Не вдалося надрукувати: {e}")
                            self.status_var.set("Помилка друку шифру")
                        finally:
                            printer_window.destroy()
                            os.unlink(temp_file_path)
                    else:
                        messagebox.showwarning("Друк", "Не вибрано принтер")
                
                # скасувати друк
                def cancel_print():
                    printer_window.destroy()
                    os.unlink(temp_file_path)
                    self.status_var.set("Друк скасовано")
                
                # кнопки дій
                ttk.Button(button_frame, text="Друкувати", command=send_to_print).pack(side=tk.RIGHT, padx=5)
                ttk.Button(button_frame, text="Скасувати", command=cancel_print).pack(side=tk.RIGHT, padx=5)
                
                # центруємо вікно на екрані
                printer_window.update_idletasks()
                width = printer_window.winfo_width()
                height = printer_window.winfo_height()
                x = (printer_window.winfo_screenwidth() // 2) - (width // 2)
                y = (printer_window.winfo_screenheight() // 2) - (height // 2)
                printer_window.geometry(f'{width}x{height}+{x}+{y}')
                
                printer_window.transient(self.root)
                printer_window.grab_set()
                self.root.wait_window(printer_window)
            else:
                # якщо lpstat не працює - друкуємо на дефолтний принтер
                try:
                    print_process = subprocess.run(
                        ['lp', temp_file_path],
                        capture_output=True,
                        text=True
                    )
                    
                    if print_process.returncode == 0:
                        messagebox.showinfo("Друк", "Шифр надруковано на стандартний принтер")
                        self.status_var.set("Шифр відправлено на принтер")
                    else:
                        messagebox.showerror("Помилка", f"Не вдалося надрукувати: {print_process.stderr}")
                        self.status_var.set("Помилка друку шифру")
                except Exception as e:
                    messagebox.showerror("Помилка", f"Проблема з друком: {e}")
                    self.status_var.set("Помилка друку шифру")
                finally:
                    os.unlink(temp_file_path)
        except ImportError:
            messagebox.showwarning("Друк", "Бібліотеки для друку не знайдено")
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка: {e}")
            self.status_var.set("Помилка друку")
    
    def exit_app(self):
        if messagebox.askokcancel("Вихід", "Ви дійсно хочете вийти з програми?"):
            self.root.destroy()
    
    def show_about(self):
        about_text = """
        Криптографічна система
        
        Версія: 1.0
        
        Підтримуються методи шифрування:
        - Метод гамування
        - Шифр Вернама (одноразовий блокнот)
        
        Підтримуються алфавіти:
        - Український
        - Латинський
        
        Розроблено для лабораторної роботи №3 з дисципліни "МОК"
        """
        messagebox.showinfo("Про програму", about_text)

class CipherValidator:
   # для перевірки даних
   
   def validate_text(self, text, alphabet_type):
       # перевірка тексту
       if not text:
           return False, "Текст не може бути порожнім"
       return True, text

class BinaryEncryption:
   # для роботи з двійковим кодом
   
   def text_to_binary(self, text):
       # текст -> біти
       binary = ''.join(format(ord(char), '08b') for char in text)
       return binary
   
   def binary_to_text(self, binary):
       # біти -> текст
       text = ''
       for i in range(0, len(binary), 8):
           byte = binary[i:i+8]
           if len(byte) == 8:  # повний байт
               text += chr(int(byte, 2))
       return text


if __name__ == "__main__":
   root = tk.Tk()
   app = CipherGUI(root)
   root.mainloop()