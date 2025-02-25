import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import string
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import Counter
import pickle

class CipherValidator:
    """Клас для валідації ключів та даних"""
    
    @staticmethod
    def validate_key(key, alphabet_type):
        """Валідація ключа шифрування"""
        try:
            key = int(key)
            if alphabet_type == "ukrainian":
                if key < 0 or key > 33:
                    return False, "Ключ для українського алфавіту має бути від 0 до 33"
            else:  # Латинський алфавіт
                if key < 0 or key > 26:
                    return False, "Ключ для латинського алфавіту має бути від 0 до 26"
            return True, key
        except ValueError:
            return False, "Ключ має бути цілим числом"

    @staticmethod
    def validate_text(text, alphabet_type):
        """Валідація тексту для шифрування"""
        if not text:
            return False, "Текст не може бути порожнім"
        return True, text

class CaesarCipher:
    """Клас для шифрування та розшифрування за допомогою шифру Цезаря"""
    
    def __init__(self):
        self.ua_alphabet = ' абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        self.ua_alphabet_upper = ' АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ'
        self.en_alphabet = ' abcdefghijklmnopqrstuvwxyz'
        self.en_alphabet_upper = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.punctuation = string.punctuation + '№«»—'
        
    def encrypt(self, text, key, alphabet_type):
        result = ""
        
        for char in text:
            if alphabet_type == "ukrainian":
                if char.lower() in self.ua_alphabet:
                    if char.isupper():
                        index = self.ua_alphabet_upper.find(char)
                        new_index = (index + key) % len(self.ua_alphabet_upper)
                        result += self.ua_alphabet_upper[new_index]
                    else:
                        index = self.ua_alphabet.find(char)
                        new_index = (index + key) % len(self.ua_alphabet)
                        result += self.ua_alphabet[new_index]
                elif char in self.punctuation:
                    punct_index = self.punctuation.find(char)
                    new_punct_index = (punct_index + key) % len(self.punctuation)
                    result += self.punctuation[new_punct_index]
                else:
                    # Залишаємо символ як є, якщо він не в алфавіті і не є знаком пунктуації
                    result += char
            else:
                if char.lower() in self.en_alphabet:
                    if char.isupper():
                        index = self.en_alphabet_upper.find(char)
                        new_index = (index + key) % len(self.en_alphabet_upper)
                        result += self.en_alphabet_upper[new_index]
                    else:
                        index = self.en_alphabet.find(char)
                        new_index = (index + key) % len(self.en_alphabet)
                        result += self.en_alphabet[new_index]
                elif char in self.punctuation:
                    punct_index = self.punctuation.find(char)
                    new_punct_index = (punct_index + key) % len(self.punctuation)
                    result += self.punctuation[new_punct_index]
                else:
                    result += char
                    
        return result
    
    def decrypt(self, text, key, alphabet_type):
        return self.encrypt(text, -key, alphabet_type)
    
    def brute_force(self, ciphertext, alphabet_type, progress_callback=None):
        results = []
        max_key = 34 if alphabet_type == "ukrainian" else 27
        
        for key in range(max_key):
            if progress_callback:
                progress_callback(key, max_key)
                
            decrypted = self.decrypt(ciphertext, key, alphabet_type)
            results.append((key, decrypted))
            
        return results
    
    def get_frequency_analysis(self, text, alphabet_type):
        if alphabet_type == "ukrainian":
            alphabet = self.ua_alphabet[1:] + self.ua_alphabet_upper[1:]
        else:
            alphabet = self.en_alphabet[1:] + self.en_alphabet_upper[1:]

        filtered_text = ''.join(char for char in text if char.lower() in alphabet.lower())
        
        counter = Counter(filtered_text.lower())
        total = sum(counter.values())

        frequency = {char: (count / total) * 100 for char, count in counter.items()}

        sorted_freq = {k: frequency.get(k, 0) for k in sorted(alphabet.lower())}
        
        return sorted_freq

class BinaryEncryption:
    
    @staticmethod
    def encrypt_file(input_file, output_file, key):
        with open(input_file, 'rb') as f_in:
            data = f_in.read()

        encrypted_data = bytearray()
        for byte in data:
            encrypted_byte = (byte + key) % 256
            encrypted_data.append(encrypted_byte)
            
        with open(output_file, 'wb') as f_out:
            f_out.write(encrypted_data)
            
    @staticmethod
    def decrypt_file(input_file, output_file, key):
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
  
        decrypted_data = bytearray()
        for byte in data:
            decrypted_byte = (byte - key) % 256
            decrypted_data.append(decrypted_byte)
            
        with open(output_file, 'wb') as f_out:
            f_out.write(decrypted_data)

class CipherGUI:    
    def __init__(self, root):
        self.root = root
        self.root.title("Криптосистема")
        self.root.geometry("800x600")
        
        self.cipher = CaesarCipher()
        self.validator = CipherValidator()
        self.binary_encryption = BinaryEncryption()
        
        self.current_file = None

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
        encryption_menu.add_command(label="Шифрувати", command=self.encrypt)
        encryption_menu.add_command(label="Розшифрувати", command=self.decrypt)
        encryption_menu.add_separator()
        encryption_menu.add_command(label="Шифрувати файл", command=self.encrypt_file)
        encryption_menu.add_command(label="Розшифрувати файл", command=self.decrypt_file)
        encryption_menu.add_separator()
        encryption_menu.add_command(label="Атака грубою силою", command=self.brute_force)
        encryption_menu.add_command(label="Частотний аналіз", command=self.frequency_analysis)
        menubar.add_cascade(label="Шифрування", menu=encryption_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Про програму", command=self.show_about)
        menubar.add_cascade(label="Допомога", menu=help_menu)
        
        self.root.config(menu=menubar)
        
    def create_main_interface(self):
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        ttk.Label(control_frame, text="Алфавіт:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.alphabet_var = tk.StringVar(value="ukrainian")
        ttk.Radiobutton(control_frame, text="Український", variable=self.alphabet_var, value="ukrainian").grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(control_frame, text="Латинський", variable=self.alphabet_var, value="latin").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Ключ:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(control_frame, textvariable=self.key_var, width=10)
        self.key_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Шифрувати", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Розшифрувати", command=self.decrypt).pack(side=tk.LEFT, padx=5)
        
        text_frame = ttk.Frame(self.root, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(text_frame, text="Вхідний текст:").pack(anchor=tk.W)
        
        self.input_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(text_frame, text="Результат:").pack(anchor=tk.W)
        
        self.output_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
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
            
    def print_file(self):
        try:
            import subprocess
            import tempfile
            import os

            content = self.output_text.get(1.0, tk.END)
            
            if not content.strip():
                messagebox.showwarning("Друк", "Немає тексту для друку")
                return
            
            with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w', encoding='utf-8') as temp_file:
                temp_file_path = temp_file.name
                temp_file.write(content)
            
            self.status_var.set("Підготовка до друку...")
            self.root.update_idletasks()
            
            printers_output = subprocess.run(['lpstat', '-p'], capture_output=True, text=True)
            
            if printers_output.returncode == 0 and printers_output.stdout.strip():
                printer_window = tk.Toplevel(self.root)
                printer_window.title("Вибір принтера")
                printer_window.geometry("400x400")

                printers = []
                for line in printers_output.stdout.strip().split('\n'):
                    if line.startswith("printer"):
                        # Формат: "printer PrinterName is idle. enabled since..."
                        printer_name = line.split()[1]
                        printers.append(printer_name)
                
                if not printers:
                    messagebox.showinfo("Друк", "Не знайдено жодного принтера")
                    os.unlink(temp_file_path)
                    return
                
                printers_frame = ttk.Frame(printer_window, padding="10")
                printers_frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(printers_frame, text="Доступні принтери:").pack(anchor=tk.W, pady=5)
                
                printer_var = tk.StringVar(value=printers[0])
                printer_listbox = tk.Listbox(printers_frame, listvariable=tk.StringVar(value=printers), height=10)
                printer_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
                printer_listbox.selection_set(0)
                
                button_frame = ttk.Frame(printer_window, padding="10")
                button_frame.pack(fill=tk.X)
                
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
                                messagebox.showinfo("Друк", f"Документ відправлено на принтер {selected_printer}")
                                self.status_var.set(f"Документ відправлено на принтер {selected_printer}")
                            else:
                                messagebox.showerror("Помилка", f"Помилка друку: {print_process.stderr}")
                                self.status_var.set("Помилка друку")
                        except Exception as e:
                            messagebox.showerror("Помилка", f"Помилка друку: {e}")
                            self.status_var.set("Помилка друку")
                        finally:
                            printer_window.destroy()
                            os.unlink(temp_file_path)
                    else:
                        messagebox.showwarning("Друк", "Не вибрано жодного принтера")
                
                def cancel_print():
                    printer_window.destroy()
                    os.unlink(temp_file_path)
                    self.status_var.set("Друк скасовано")
                
                ttk.Button(button_frame, text="Друкувати", command=send_to_print).pack(side=tk.RIGHT, padx=5)
                ttk.Button(button_frame, text="Скасувати", command=cancel_print).pack(side=tk.RIGHT, padx=5)
                
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
                try:
                    print_process = subprocess.run(
                        ['lp', temp_file_path],
                        capture_output=True,
                        text=True
                    )
                    
                    if print_process.returncode == 0:
                        messagebox.showinfo("Друк", "Документ відправлено на принтер за замовчуванням")
                        self.status_var.set("Документ відправлено на принтер за замовчуванням")
                    else:
                        messagebox.showerror("Помилка", f"Помилка друку: {print_process.stderr}")
                        self.status_var.set("Помилка друку")
                except Exception as e:
                    messagebox.showerror("Помилка", f"Помилка друку: {e}")
                    self.status_var.set("Помилка друку")
                finally:
                    os.unlink(temp_file_path)
        except ImportError:
            messagebox.showwarning("Друк", "Не вдалося завантажити необхідні модулі для друку")
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка під час друку: {e}")
            self.status_var.set("Помилка друку")
        
    def exit_app(self):
        if messagebox.askyesno("Вихід", "Ви впевнені, що хочете вийти?"):
            self.root.destroy()
            
    def encrypt(self):
        text = self.input_text.get(1.0, tk.END).strip()
        key = self.key_var.get()
        alphabet_type = self.alphabet_var.get()
        
        key_valid, key_result = self.validator.validate_key(key, alphabet_type)
        text_valid, text_result = self.validator.validate_text(text, alphabet_type)
        
        if key_valid and text_valid:
            encrypted_text = self.cipher.encrypt(text, key_result, alphabet_type)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, encrypted_text)
            self.status_var.set("Текст зашифровано")
        else:
            if not key_valid:
                messagebox.showerror("Помилка", key_result)
            if not text_valid:
                messagebox.showerror("Помилка", text_result)
                
    def decrypt(self):
        text = self.input_text.get(1.0, tk.END).strip()
        key = self.key_var.get()
        alphabet_type = self.alphabet_var.get()
        
        key_valid, key_result = self.validator.validate_key(key, alphabet_type)
        text_valid, text_result = self.validator.validate_text(text, alphabet_type)
        
        if key_valid and text_valid:
            decrypted_text = self.cipher.decrypt(text, key_result, alphabet_type)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, decrypted_text)
            self.status_var.set("Текст розшифровано")
        else:
            if not key_valid:
                messagebox.showerror("Помилка", key_result)
            if not text_valid:
                messagebox.showerror("Помилка", text_result)
                
    def encrypt_file(self):
        input_file = filedialog.askopenfilename(
            title="Виберіть файл для шифрування",
            filetypes=[("Усі файли", "*.*")]
        )
        
        if not input_file:
            return
            
        key = self.key_var.get()
        try:
            key = int(key)
        except ValueError:
            messagebox.showerror("Помилка", "Ключ має бути цілим числом")
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Зберегти зашифрований файл як",
            filetypes=[("Зашифровані файли", "*.enc"), ("Усі файли", "*.*")],
            defaultextension=".enc"
        )
        
        if not output_file:
            return
            
        try:
            self.binary_encryption.encrypt_file(input_file, output_file, key)
            messagebox.showinfo("Успіх", "Файл успішно зашифровано")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося зашифрувати файл: {e}")
            
    def decrypt_file(self):
        input_file = filedialog.askopenfilename(
            title="Виберіть файл для розшифрування",
            filetypes=[("Зашифровані файли", "*.enc"), ("Усі файли", "*.*")]
        )
        
        if not input_file:
            return
            
        key = self.key_var.get()
        try:
            key = int(key)
        except ValueError:
            messagebox.showerror("Помилка", "Ключ має бути цілим числом")
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Зберегти розшифрований файл як",
            filetypes=[("Усі файли", "*.*")]
        )
        
        if not output_file:
            return
            
        try:
            self.binary_encryption.decrypt_file(input_file, output_file, key)
            messagebox.showinfo("Успіх", "Файл успішно розшифровано")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося розшифрувати файл: {e}")
            
    def brute_force(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Необхідно ввести зашифрований текст")
            return
            
        brute_force_window = tk.Toplevel(self.root)
        brute_force_window.title("Результати атаки грубою силою")
        brute_force_window.geometry("600x400")
        
        progress_frame = ttk.Frame(brute_force_window, padding="10")
        progress_frame.pack(fill=tk.X)
        
        ttk.Label(progress_frame, text="Прогрес:").pack(side=tk.LEFT, padx=5)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=progress_var,
            maximum=100,
            length=400
        )
        progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        results_frame = ttk.Frame(brute_force_window, padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("key", "decrypted_text")
        results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        results_tree.heading("key", text="Ключ")
        results_tree.heading("decrypted_text", text="Розшифрований текст")
        
        results_tree.column("key", width=50, anchor=tk.CENTER)
        results_tree.column("decrypted_text", width=550)
        
        results_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        results_tree.configure(yscrollcommand=scrollbar.set)
        
        def update_progress(current, total):
            progress_var.set((current / total) * 100)
            brute_force_window.update_idletasks()
        
        results = self.cipher.brute_force(text, alphabet_type, update_progress)
        
        for key, decrypted_text in results:
            display_text = decrypted_text[:100] + "..." if len(decrypted_text) > 100 else decrypted_text
            results_tree.insert("", tk.END, values=(key, display_text))
            
        def on_item_double_click(event):
            selected_item = results_tree.selection()[0]
            key, decrypted_text_preview = results_tree.item(selected_item, "values")
            
            full_decrypted_text = next(text for k, text in results if int(k) == int(key))
            
            if messagebox.askyesno("Вибір результату", f"Використати результат з ключем {key}?"):
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, full_decrypted_text)
                self.key_var.set(key)  # Встановлюємо знайдений ключ
                brute_force_window.destroy()
                
        results_tree.bind("<Double-1>", on_item_double_click)
        
    def frequency_analysis(self):
        text = self.input_text.get(1.0, tk.END).strip()
        alphabet_type = self.alphabet_var.get()
        
        if not text:
            messagebox.showerror("Помилка", "Необхідно ввести текст для аналізу")
            return
            
        frequency_data = self.cipher.get_frequency_analysis(text, alphabet_type)
        
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Частотний аналіз")
        analysis_window.geometry("800x600")
        
        graph_frame = ttk.Frame(analysis_window, padding="10")
        graph_frame.pack(fill=tk.BOTH, expand=True)
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        letters = list(frequency_data.keys())
        frequencies = list(frequency_data.values())
        
        bars = ax.bar(range(len(letters)), frequencies, align='center')

        ax.set_xticks(range(len(letters)))
        ax.set_xticklabels(letters)
        ax.set_ylabel('Частота (%)')
        ax.set_title('Частотний аналіз тексту')
        
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2.,
                    height,
                    f'{height:.1f}',
                    ha='center',
                    va='bottom',
                    rotation=90,
                    fontsize=8
                )
        
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        table_frame = ttk.Frame(analysis_window, padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("letter", "frequency")
        frequency_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        frequency_tree.heading("letter", text="Буква")
        frequency_tree.heading("frequency", text="Частота (%)")
        
        frequency_tree.column("letter", width=100, anchor=tk.CENTER)
        frequency_tree.column("frequency", width=100, anchor=tk.CENTER)
        
        frequency_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=frequency_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        frequency_tree.configure(yscrollcommand=scrollbar.set)
        
        for letter, freq in frequency_data.items():
            if freq > 0:
                frequency_tree.insert("", tk.END, values=(letter, f"{freq:.2f}"))
        
    def show_about(self):
        messagebox.showinfo(
            "Про програму",
            "Криптосистема на основі шифру Цезаря\n\n"
            "Версія: 1.0\n"
            "Розробник: Гуменюк Станіслав ПМІ-33\n"
            "© 2025 Всі права захищені"
        )


def main():
    root = tk.Tk()
    app = CipherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()