import unittest
from tkinter import Tk
import os
import sys
import string

# Імпорт класів з вашого модуля
# Припускаємо, що ваш модуль називається 'gamma_cipher.py'
# Якщо назва інша, замініть на правильну

# Спочатку імпортуємо необхідні класи з вашого модуля
# Якщо файл називається інакше, змініть назву файлу відповідно
from cipher import GammaCipher, CipherValidator, BinaryEncryption

class TestGammaCipher(unittest.TestCase):
    """Тести для класу GammaCipher"""
    
    def setUp(self):
        """Виконується перед кожним тестом"""
        self.cipher = GammaCipher()
        self.test_text_ua = "Привіт, світ!"
        self.test_text_en = "Hello, world!"
    
    def test_generate_gamma(self):
        """Тест генерації гами"""
        length = 20
        gamma_ua = self.cipher.generate_gamma(length, "ukrainian")
        gamma_en = self.cipher.generate_gamma(length, "latin")
        
        # Перевіряємо довжину гами
        self.assertEqual(len(gamma_ua), length)
        self.assertEqual(len(gamma_en), length)
        
        # Перевіряємо, що символи гами належать до відповідного алфавіту
        for char in gamma_ua:
            self.assertIn(char.lower(), self.cipher.ua_alphabet)
        
        for char in gamma_en:
            self.assertIn(char.lower(), self.cipher.en_alphabet)
    
    def test_generate_vernam_key(self):
        """Тест генерації ключа Вернама"""
        length = 20
        key_ua = self.cipher.generate_vernam_key(length, "ukrainian")
        key_en = self.cipher.generate_vernam_key(length, "latin")
        
        # Перевіряємо довжину ключа
        self.assertEqual(len(key_ua), length)
        self.assertEqual(len(key_en), length)
    
    def test_encrypt_decrypt_gamma_ukrainian(self):
        """Тест шифрування та розшифрування методом гамування українською"""
        gamma = self.cipher.generate_gamma(30, "ukrainian")
        encrypted = self.cipher.encrypt_gamma(self.test_text_ua, gamma, "ukrainian")
        decrypted = self.cipher.decrypt_gamma(encrypted, gamma, "ukrainian")
        
        # Перевіряємо, що після шифрування та розшифрування отримуємо початковий текст
        self.assertEqual(decrypted, self.test_text_ua)
        
        # Перевіряємо, що шифрований текст відрізняється від початкового
        self.assertNotEqual(encrypted, self.test_text_ua)
    
    def test_encrypt_decrypt_gamma_latin(self):
        """Тест шифрування та розшифрування методом гамування англійською"""
        gamma = self.cipher.generate_gamma(30, "latin")
        encrypted = self.cipher.encrypt_gamma(self.test_text_en, gamma, "latin")
        decrypted = self.cipher.decrypt_gamma(encrypted, gamma, "latin")
        
        # Перевіряємо, що після шифрування та розшифрування отримуємо початковий текст
        self.assertEqual(decrypted, self.test_text_en)
        
        # Перевіряємо, що шифрований текст відрізняється від початкового
        self.assertNotEqual(encrypted, self.test_text_en)
    
    def test_encrypt_decrypt_vernam_ukrainian(self):
        """Тест шифрування та розшифрування шифром Вернама українською"""
        key = self.cipher.generate_vernam_key(len(self.test_text_ua), "ukrainian")
        encrypted = self.cipher.encrypt_vernam(self.test_text_ua, key, "ukrainian")
        decrypted = self.cipher.decrypt_vernam(encrypted, key, "ukrainian")
        
        self.assertEqual(decrypted, self.test_text_ua)
        self.assertNotEqual(encrypted, self.test_text_ua)
    
    def test_encrypt_decrypt_vernam_latin(self):
        """Тест шифрування та розшифрування шифром Вернама англійською"""
        key = self.cipher.generate_vernam_key(len(self.test_text_en), "latin")
        encrypted = self.cipher.encrypt_vernam(self.test_text_en, key, "latin")
        decrypted = self.cipher.decrypt_vernam(encrypted, key, "latin")
        
        self.assertEqual(decrypted, self.test_text_en)
        self.assertNotEqual(encrypted, self.test_text_en)
    
    def test_vernam_key_length_validation(self):
        """Тест валідації довжини ключа Вернама"""
        short_key = self.cipher.generate_vernam_key(5, "ukrainian")
        
        # Перевіряємо, що виникає виняток при короткому ключі
        with self.assertRaises(ValueError):
            self.cipher.encrypt_vernam(self.test_text_ua, short_key, "ukrainian")
    
    def test_save_load_key(self):
        """Тест збереження та завантаження ключа"""
        key = self.cipher.generate_vernam_key(20, "ukrainian")
        temp_file = "temp_key.txt"
        
        # Зберігаємо ключ
        self.cipher.save_key_to_file(key, temp_file)
        
        # Завантажуємо ключ
        loaded_key = self.cipher.load_key_from_file(temp_file)
        
        # Перевіряємо, що ключі співпадають
        self.assertEqual(key, loaded_key)
        
        # Видаляємо тимчасовий файл
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    def test_punctuation_handling(self):
        """Тест обробки пунктуації"""
        test_text = "Привіт, світ! Як справи?"
        gamma = self.cipher.generate_gamma(30, "ukrainian")
        encrypted = self.cipher.encrypt_gamma(test_text, gamma, "ukrainian")
        decrypted = self.cipher.decrypt_gamma(encrypted, gamma, "ukrainian")
        
        self.assertEqual(decrypted, test_text)
    
    def test_case_sensitivity(self):
        """Тест чутливості до регістру"""
        test_text = "ПриВіт, СвіТ!"
        gamma = self.cipher.generate_gamma(30, "ukrainian")
        encrypted = self.cipher.encrypt_gamma(test_text, gamma, "ukrainian")
        decrypted = self.cipher.decrypt_gamma(encrypted, gamma, "ukrainian")
        
        self.assertEqual(decrypted, test_text)
        
        # Перевіряємо, що зашифрований текст зберігає оригінальний регістр
        self.assertNotEqual(encrypted.lower(), encrypted)


class TestCipherValidator(unittest.TestCase):
    """Тести для класу CipherValidator"""
    
    def setUp(self):
        """Виконується перед кожним тестом"""
        self.validator = CipherValidator()
    
    def test_validate_text(self):
        """Тест валідації тексту"""
        # Валідний текст
        result, message = self.validator.validate_text("Привіт", "ukrainian")
        self.assertTrue(result)
        
        # Порожній текст
        result, message = self.validator.validate_text("", "ukrainian")
        self.assertFalse(result)


class TestBinaryEncryption(unittest.TestCase):
    """Тести для класу BinaryEncryption"""
    
    def setUp(self):
        """Виконується перед кожним тестом"""
        self.binary_encryption = BinaryEncryption()
    
    def test_text_to_binary_and_back(self):
        """Тест перетворення тексту в бінарний формат і назад"""
        test_text = "Hello, world!"
        binary = self.binary_encryption.text_to_binary(test_text)
        decoded_text = self.binary_encryption.binary_to_text(binary)
        
        self.assertEqual(decoded_text, test_text)
        
        # Перевіряємо, що бінарний формат складається лише з 0 та 1
        self.assertTrue(all(bit in '01' for bit in binary))


if __name__ == '__main__':
    unittest.main()