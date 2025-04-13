use std::fs::File;
use std::io::{Write};
use std::path::Path;
use gtk::prelude::*;
use gtk::{Application, ApplicationWindow, Button, Entry, Label, Box, Orientation, FileChooserDialog, FileChooserAction, MessageDialog, MessageType};
use gtk::traits::SettingsExt;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use num_integer::Integer;
use rand::thread_rng;


const APP_ID: &str = "org.example.RSACryptosystem";

fn main() {
    let app = Application::new(Some(APP_ID), Default::default());
    
    // перевіряємо чи застосунок створився нормально
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // налаштовуємо темну тему
    let settings = gtk::Settings::default().expect("Failed to get default settings");
    settings.set_gtk_application_prefer_dark_theme(true);

    // робимо головне вікно
    let window = ApplicationWindow::new(app);
    window.set_title("RSA Cryptosystem");
    window.set_default_size(1000, 400);
    window.set_position(gtk::WindowPosition::Center);

    // контейнер для всіх елементів
    let main_box = Box::new(Orientation::Vertical, 10);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(20);
    main_box.set_margin_start(20);
    main_box.set_margin_end(20);

    // пишемо заголовок
    let title_label = Label::new(Some("RSA Cryptosystem with Binary Exponentiation"));
    title_label.set_markup("<span font='16' weight='bold'>RSA Cryptosystem with Binary Exponentiation</span>");
    main_box.pack_start(&title_label, false, false, 10);

    // робимо місце для ключів
    let keys_box = Box::new(Orientation::Horizontal, 10);
    
    // частина для генерації ключів
    let key_gen_box = Box::new(Orientation::Vertical, 5);
    let key_gen_label = Label::new(Some("Key Generation"));
    key_gen_label.set_markup("<span font='14' weight='bold'>Key Generation</span>");
    key_gen_box.pack_start(&key_gen_label, false, false, 5);
    
    let p_label = Label::new(Some("Prime p:"));
    key_gen_box.pack_start(&p_label, false, false, 5);
    let p_entry = Entry::new();
    key_gen_box.pack_start(&p_entry, false, false, 5);
    
    let q_label = Label::new(Some("Prime q:"));
    key_gen_box.pack_start(&q_label, false, false, 5);
    let q_entry = Entry::new();
    key_gen_box.pack_start(&q_entry, false, false, 5);
    
    let e_label = Label::new(Some("Public exponent e:"));
    key_gen_box.pack_start(&e_label, false, false, 5);
    let e_entry = Entry::new();
    key_gen_box.pack_start(&e_entry, false, false, 5);
    
    let generate_button = Button::with_label("Generate Keys");
    key_gen_box.pack_start(&generate_button, false, false, 10);
    
    keys_box.pack_start(&key_gen_box, true, true, 5);

    let auto_generate_button = Button::with_label("Auto Generate Parameters");
    key_gen_box.pack_start(&auto_generate_button, false, false, 5);
    
    // частина для відображення ключів
    let keys_display_box = Box::new(Orientation::Vertical, 5);
    let keys_display_label = Label::new(Some("Generated Keys"));
    keys_display_label.set_markup("<span font='14' weight='bold'>Generated Keys</span>");
    keys_display_box.pack_start(&keys_display_label, false, false, 5);
    
    let public_key_label = Label::new(Some("Public Key (n, e):"));
    keys_display_box.pack_start(&public_key_label, false, false, 5);
    let public_key_entry = Entry::new();
    keys_display_box.pack_start(&public_key_entry, false, false, 5);
    
    let private_key_label = Label::new(Some("Private Key (n, d):"));
    keys_display_box.pack_start(&private_key_label, false, false, 5);
    let private_key_entry = Entry::new();
    keys_display_box.pack_start(&private_key_entry, false, false, 5);
    
    let save_keys_button = Button::with_label("Save Keys to File");
    keys_display_box.pack_start(&save_keys_button, false, false, 10);
    
    keys_box.pack_start(&keys_display_box, true, true, 5);
    main_box.pack_start(&keys_box, false, false, 10);
    
    // створюємо місце для шифрування/дешифрування
    let crypto_box = Box::new(Orientation::Horizontal, 10);
    
    // місце для шифрування
    let encrypt_box = Box::new(Orientation::Vertical, 5);
    let encrypt_label = Label::new(Some("Encryption"));
    encrypt_label.set_markup("<span font='14' weight='bold'>Encryption</span>");
    encrypt_box.pack_start(&encrypt_label, false, false, 5);
    
    let plaintext_label = Label::new(Some("Plaintext (number):"));
    encrypt_box.pack_start(&plaintext_label, false, false, 5);
    let plaintext_entry = Entry::new();
    encrypt_box.pack_start(&plaintext_entry, false, false, 5);
    
    let encrypt_button = Button::with_label("Encrypt");
    encrypt_box.pack_start(&encrypt_button, false, false, 5);
    
    let ciphertext_label = Label::new(Some("Ciphertext:"));
    encrypt_box.pack_start(&ciphertext_label, false, false, 5);
    let ciphertext_entry = Entry::new();
    ciphertext_entry.set_editable(false);
    encrypt_box.pack_start(&ciphertext_entry, false, false, 5);
    
    crypto_box.pack_start(&encrypt_box, true, true, 5);
    
    // місце для дешифрування
    let decrypt_box = Box::new(Orientation::Vertical, 5);
    let decrypt_label = Label::new(Some("Decryption"));
    decrypt_label.set_markup("<span font='14' weight='bold'>Decryption</span>");
    decrypt_box.pack_start(&decrypt_label, false, false, 5);
    
    let encrypted_label = Label::new(Some("Ciphertext (number):"));
    decrypt_box.pack_start(&encrypted_label, false, false, 5);
    let encrypted_entry = Entry::new();
    decrypt_box.pack_start(&encrypted_entry, false, false, 5);
    
    let decrypt_button = Button::with_label("Decrypt");
    decrypt_box.pack_start(&decrypt_button, false, false, 5);
    
    let decrypted_label = Label::new(Some("Decrypted text:"));
    decrypt_box.pack_start(&decrypted_label, false, false, 5);
    let decrypted_entry = Entry::new();
    decrypted_entry.set_editable(false);
    decrypt_box.pack_start(&decrypted_entry, false, false, 5);
    
    crypto_box.pack_start(&decrypt_box, true, true, 5);
    main_box.pack_start(&crypto_box, true, true, 10);

    // клонуємо змінні щоб використати їх у подіях
    let p_entry_clone = p_entry.clone();
    let q_entry_clone = q_entry.clone();
    let e_entry_clone = e_entry.clone();
    let public_key_entry_clone = public_key_entry.clone();
    let private_key_entry_clone = private_key_entry.clone();
    let window_clone = window.clone();
    
    // подія коли натискаємо кнопку генерації ключів
    generate_button.connect_clicked(move |_| {
        let p_str = p_entry_clone.text();
        let q_str = q_entry_clone.text();
        let e_str = e_entry_clone.text();
        
        // перевірка чи всі поля заповнені
        if p_str.is_empty() || q_str.is_empty() || e_str.is_empty() {
            show_error_dialog(&window_clone, "All fields must be filled");
            return;
        }
        
        // пробуємо зробити з введеного числа BigUint
        let p = match p_str.parse::<BigUint>() {
            Ok(p) => {
                if !is_prime(&p) {
                    show_error_dialog(&window_clone, "p must be a prime number");
                    return;
                }
                p
            },
            Err(_) => {
                show_error_dialog(&window_clone, "Invalid p value");
                return;
            }
        };
        
        let q = match q_str.parse::<BigUint>() {
            Ok(q) => {
                if !is_prime(&q) {
                    show_error_dialog(&window_clone, "q must be a prime number");
                    return;
                }
                q
            },
            Err(_) => {
                show_error_dialog(&window_clone, "Invalid q value");
                return;
            }
        };
        
        let e = match e_str.parse::<BigUint>() {
            Ok(e) => e,
            Err(_) => {
                show_error_dialog(&window_clone, "Invalid e value");
                return;
            }
        };
        
        // генеруємо ключі
        match generate_keys(&p, &q, &e) {
            Ok((n, e, d)) => {
                public_key_entry_clone.set_text(&format!("n = {}, e = {}", n, e));
                private_key_entry_clone.set_text(&format!("n = {}, d = {}", n, d));
            },
            Err(err) => {
                show_error_dialog(&window_clone, &err);
            }
        }
    });
   
    let p_entry_auto = p_entry.clone();
    let q_entry_auto = q_entry.clone();
    let e_entry_auto = e_entry.clone();
    let window_auto = window.clone();

    // подія для автоматичної генерації
    auto_generate_button.connect_clicked(move |_| {
        // генеруємо випадкові прості числа (32-біт щоб простіше)
        let mut rng = thread_rng();
    
        // шукаємо p (випадкове просте)
        let mut p = rng.gen_biguint(32);
        while !is_prime(&p) || p < BigUint::from(2u32) {
            p = rng.gen_biguint(32);
        }
    
        // шукаємо q (інше випадкове просте число)
        let mut q = rng.gen_biguint(32);
        while !is_prime(&q) || q < BigUint::from(2u32) || p == q {
            q = rng.gen_biguint(32);
        }
    
        // рахуємо phi(n) = (p-1)(q-1)
        let p_minus_one = &p - BigUint::one();
        let q_minus_one = &q - BigUint::one();
        let phi = &p_minus_one * &q_minus_one;
    
        // шукаємо e (взаємно просте з phi де 1 < e < phi)
        // часто беруть 65537 (якщо працює для наших p і q)
        let common_e = BigUint::from(65537u32);
        let e = if &common_e < &phi && are_coprime(&common_e, &phi) {
            common_e
        } else {
            // шукаємо інший e
            let mut e_candidate = BigUint::from(3u32);
            while &e_candidate < &phi {
                if are_coprime(&e_candidate, &phi) {
                    break;
                }
                e_candidate += BigUint::from(2u32);
            }
            e_candidate
        };
    
        // оновлюємо значення в полях
        p_entry_auto.set_text(&p.to_string());
        q_entry_auto.set_text(&q.to_string());
        e_entry_auto.set_text(&e.to_string());
    
        show_info_dialog(&window_auto, "Parameters automatically generated");
    });

    // клонуємо змінні для шифрування
    let public_key_entry_clone2 = public_key_entry.clone();
    let plaintext_entry_clone = plaintext_entry.clone();
    let ciphertext_entry_clone = ciphertext_entry.clone();
    let window_clone2 = window.clone();
    
    // подія коли тиснемо кнопку шифрування
    encrypt_button.connect_clicked(move |_| {
        let public_key_text = public_key_entry_clone2.text();
        let plaintext = plaintext_entry_clone.text();
        
        if public_key_text.is_empty() {
            show_error_dialog(&window_clone2, "Please generate keys first");
            return;
        }
        
        if plaintext.is_empty() {
            show_error_dialog(&window_clone2, "Please enter plaintext");
            return;
        }
        
        // витягуємо n та e з публічного ключа
        let (n, e) = parse_key(&public_key_text);
        
        // перетворюємо текст у число
        let m = match plaintext.parse::<BigUint>() {
            Ok(m) => {
                if m >= n {
                    show_error_dialog(&window_clone2, "Plaintext must be less than n");
                    return;
                }
                m
            },
            Err(_) => {
                show_error_dialog(&window_clone2, "Invalid plaintext value");
                return;
            }
        };
        
        // шифруємо повідомлення
        let c = mod_pow(&m, &e, &n);
        ciphertext_entry_clone.set_text(&c.to_string());
    });
    
    // клонуємо змінні для дешифрування
    let private_key_entry_clone2 = private_key_entry.clone();
    let encrypted_entry_clone = encrypted_entry.clone();
    let decrypted_entry_clone = decrypted_entry.clone();
    let window_clone3 = window.clone();
    
    // подія коли тиснемо кнопку дешифрування
    decrypt_button.connect_clicked(move |_| {
        let private_key_text = private_key_entry_clone2.text();
        let ciphertext = encrypted_entry_clone.text();
        
        if private_key_text.is_empty() {
            show_error_dialog(&window_clone3, "Please generate keys first");
            return;
        }
        
        if ciphertext.is_empty() {
            show_error_dialog(&window_clone3, "Please enter ciphertext");
            return;
        }
        
        // витягуємо n та d з приватного ключа
        let (n, d) = parse_key(&private_key_text);
        
        // перетворюємо шифротекст у число
        let c = match ciphertext.parse::<BigUint>() {
            Ok(c) => {
                if c >= n {
                    show_error_dialog(&window_clone3, "Ciphertext must be less than n");
                    return;
                }
                c
            },
            Err(_) => {
                show_error_dialog(&window_clone3, "Invalid ciphertext value");
                return;
            }
        };
        
        // дешифруємо повідомлення
        let m = mod_pow(&c, &d, &n);
        decrypted_entry_clone.set_text(&m.to_string());
    });
    
    // клонуємо змінні для збереження ключів
    let public_key_entry_clone3 = public_key_entry.clone();
    let private_key_entry_clone3 = private_key_entry.clone();
    let window_clone4 = window.clone();
    
    // подія коли тиснемо кнопку збереження ключів
    save_keys_button.connect_clicked(move |_| {
        let public_key = public_key_entry_clone3.text();
        let private_key = private_key_entry_clone3.text();
        
        if public_key.is_empty() || private_key.is_empty() {
            show_error_dialog(&window_clone4, "Please generate keys first");
            return;
        }
        
        // вікно для вибору файлу куди зберегти
        let file_chooser = FileChooserDialog::with_buttons(
            Some("Save Keys"),
            Some(&window_clone4),
            FileChooserAction::Save,
            &[("Cancel", gtk::ResponseType::Cancel), ("Save", gtk::ResponseType::Accept)]
        );
        
        file_chooser.set_current_name("rsa_keys.txt");
        file_chooser.set_do_overwrite_confirmation(true);
        
        let response = file_chooser.run();
        
        if response == gtk::ResponseType::Accept {
            if let Some(file_path) = file_chooser.filename() {
                match save_keys_to_file(&file_path, &public_key, &private_key) {
                    Ok(_) => {
                        show_info_dialog(&window_clone4, &format!("Keys saved to {:?}", file_path));
                    },
                    Err(err) => {
                        show_error_dialog(&window_clone4, &format!("Error saving keys: {}", err));
                    }
                }
            }
        }
        
        unsafe { file_chooser.destroy(); }
    });

    window.add(&main_box);
    window.show_all();
}

// перевіряємо чи число просте (швидкий спосіб)
fn is_prime(n: &BigUint) -> bool {
    if n <= &BigUint::from(1u32) {
        return false;
    }
    if n <= &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }
    
    // перевіряємо ділення на непарні числа до кореня
    let mut i = BigUint::from(3u32);
    let sqrt_n = n.sqrt();
    
    while i <= sqrt_n {
        if n % &i == BigUint::zero() {
            return false;
        }
        i += BigUint::from(2u32);
    }
    
    true
}

// генеруємо ключі RSA
fn generate_keys(p: &BigUint, q: &BigUint, e: &BigUint) 
    -> Result<(BigUint, BigUint, BigUint), String> {
    
    // рахуємо n = p * q
    let n = p * q;
    
    // рахуємо функцію Ейлера: phi = (p-1) * (q-1)
    let p_minus_one = p - BigUint::one();
    let q_minus_one = q - BigUint::one();
    let phi = &p_minus_one * &q_minus_one;
    
    // перевіряємо щоб e було менше phi і взаємно просте з phi
    if e >= &phi {
        return Err("e must be less than phi(n)".to_string());
    }
    
    if !are_coprime(e, &phi) {
        return Err("e must be coprime with phi(n)".to_string());
    }
    
    // рахуємо закритий ключ d
    let d = mod_inverse(e, &phi).ok_or("Failed to compute d (modular inverse)")?;
    
    Ok((n, e.clone(), d))
}

// перевіряємо чи два числа взаємно прості
fn are_coprime(a: &BigUint, b: &BigUint) -> bool {
    let gcd = a.gcd(b);
    gcd == BigUint::one()
}

// шукаємо обернене за модулем
fn mod_inverse(a: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    // розширений алгоритм Евкліда для BigUint
    let (mut s, mut old_s) = (BigUint::zero(), BigUint::one());
    let (mut t, mut old_t) = (BigUint::one(), BigUint::zero());
    let (mut r, mut old_r) = (modulus.clone(), a.clone());
    
    while r != BigUint::zero() {
        let quotient = &old_r / &r;
        
        let temp_r = old_r.clone();
        old_r = r.clone();
        r = temp_r - &quotient * &r;
        
        let temp_s = old_s.clone();
        old_s = s.clone();
        
        // складно з від'ємними числами в BigUint
        if quotient.clone() * &s <= temp_s {
            s = temp_s - quotient.clone() * &s;
        } else {
            s = &temp_s + modulus - (&quotient.clone() * &s % modulus);
        }
        
        let temp_t = old_t.clone();
        old_t = t.clone();
        
        // теж складно з від'ємними числами
        if quotient.clone() * &t <= temp_t {
            t = temp_t - quotient.clone() * &t;
        } else {
            t = &temp_t + modulus - (&quotient * &t % modulus);
        }
    }
    
    if old_r > BigUint::one() {
        return None; // числа не взаємно прості
    }
    
    Some(old_s)
}

// бінарне піднесення до степеня за модулем (швидкий спосіб)
fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = BigUint::one();
    let mut base = base.clone() % modulus;
    let mut exp = exponent.clone();
    
    while exp > BigUint::zero() {
        if &exp % BigUint::from(2u32) == BigUint::one() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }
    
    result
}

// витягуємо ключі з тексту
fn parse_key(key_text: &str) -> (BigUint, BigUint) {
    let parts: Vec<&str> = key_text.split(", ").collect();
    
    let n_part = parts[0].trim().strip_prefix("n = ").unwrap_or(parts[0]);
    let e_or_d_part = parts[1].trim();
    
    let e_or_d_value = if e_or_d_part.starts_with("e = ") {
        e_or_d_part.strip_prefix("e = ").unwrap_or(e_or_d_part)
    } else if e_or_d_part.starts_with("d = ") {
        e_or_d_part.strip_prefix("d = ").unwrap_or(e_or_d_part)
    } else {
        e_or_d_part
    };
    
    let n = n_part.parse::<BigUint>().unwrap_or_else(|_| BigUint::zero());
    let e_or_d = e_or_d_value.parse::<BigUint>().unwrap_or_else(|_| BigUint::zero());
    
    (n, e_or_d)
}

// зберігаємо ключі у файл
fn save_keys_to_file(path: &Path, public_key: &str, private_key: &str) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| e.to_string())?;
    
    let content = format!("Public Key: {}\nPrivate Key: {}\n", public_key, private_key);
    file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    
    Ok(())
}

// показуємо вікно з помилкою
fn show_error_dialog(parent: &ApplicationWindow, message: &str) {
    let dialog = MessageDialog::new(
        Some(parent),
        gtk::DialogFlags::MODAL,
        MessageType::Error,
        gtk::ButtonsType::Ok,
        message
    );
    
    dialog.run();
    unsafe { dialog.destroy(); }
}

// показуємо вікно з інформацією
fn show_info_dialog(parent: &ApplicationWindow, message: &str) {
    let dialog = MessageDialog::new(
        Some(parent),
        gtk::DialogFlags::MODAL,
        MessageType::Info,
        gtk::ButtonsType::Ok,
        message
    );
    
    dialog.run();
    unsafe { dialog.destroy(); }
}
