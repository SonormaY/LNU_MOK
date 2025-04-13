import unittest
from main import TrithemiusCipher
class TestTrithemiusCipher(unittest.TestCase):
    def setUp(self):
        self.cipher = TrithemiusCipher()
    def test_encrypt_linear_key_ukrainian(self):
        text = "привіт"
        key = (1, 2)  
        encrypted = self.cipher.encrypt(text, key, "linear", "ukrainian")
        self.assertEqual(encrypted, "сукєнщ")
    def test_decrypt_linear_key_ukrainian(self):
        text = "сукєнщ"
        key = (1, 2)  
        decrypted = self.cipher.decrypt(text, key, "linear", "ukrainian")
        self.assertEqual(decrypted, "привіт")
    def test_encrypt_nonlinear_key_english(self):
        text = "hello"
        key = (1, 2, 3)  
        encrypted = self.cipher.encrypt(text, key, "nonlinear", "latin")
        self.assertEqual(encrypted, "kkwco")
    def test_decrypt_nonlinear_key_english(self):
        text = "kkwco"
        key = (1, 2, 3)  
        decrypted = self.cipher.decrypt(text, key, "nonlinear", "latin")
        self.assertEqual(decrypted, "hello")
    def test_encrypt_text_key_ukrainian(self):
        text = "привіт"
        key = "ключ"  
        encrypted = self.cipher.encrypt(text, key, "text", "ukrainian")
        self.assertEqual(encrypted, "орщкит")
    def test_decrypt_text_key_ukrainian(self):
        text = "орщкит"
        key = "ключ"  
        decrypted = self.cipher.decrypt(text, key, "text", "ukrainian")
        self.assertEqual(decrypted, "привіт")
if __name__ == "__main__":
    unittest.main()