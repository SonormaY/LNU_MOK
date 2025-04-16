use std::fs::File;
use std::io::Write;
use std::path::Path;
use gtk::prelude::*;
use gtk::{Application, ApplicationWindow, Button, Entry, Label, Box, Orientation, FileChooserDialog, FileChooserAction, MessageDialog, MessageType, ScrolledWindow, TextView, TextBuffer, Frame};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use num_integer::Integer;

const APP_ID: &str = "org.example.DiffieHellmanKeyExchange";

fn main() {
    let app = Application::new(Some(APP_ID), Default::default());
    
    // Перевіряємо чи застосунок створився нормально
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // Робимо головне вікно
    let window = ApplicationWindow::new(app);
    window.set_title("Diffie-Hellman Key Exchange");
    window.set_default_size(600, 900);
    window.set_position(gtk::WindowPosition::Center);
    
    // Включаємо темну тему
    let settings = gtk::Settings::default().expect("Failed to get default settings");
    settings.set_gtk_application_prefer_dark_theme(true);

    // Створюємо ScrolledWindow для прокрутки
    let scrolled_window = ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    scrolled_window.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic); // Дозволяємо лише вертикальну прокрутку

    // Контейнер для всіх елементів
    let main_box = Box::new(Orientation::Vertical, 10);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(20);
    main_box.set_margin_start(20);
    main_box.set_margin_end(20);

    // Пишемо заголовок
    let title_label = Label::new(Some("Diffie-Hellman Key Exchange Protocol"));
    title_label.set_markup("<span font='16' weight='bold'>Diffie-Hellman Key Exchange Protocol</span>");
    main_box.pack_start(&title_label, false, false, 10);

    // Параметри протоколу
    let params_box = Box::new(Orientation::Vertical, 5);
    let params_label = Label::new(Some("Protocol Parameters"));
    params_label.set_markup("<span font='14' weight='bold'>Protocol Parameters</span>");
    params_box.pack_start(&params_label, false, false, 5);
    
    // Обираємо простий модуль p
    let p_box = Box::new(Orientation::Horizontal, 5);
    let p_label = Label::new(Some("Prime modulus p:"));
    p_box.pack_start(&p_label, false, false, 5);
    let p_entry = Entry::new();
    p_box.pack_start(&p_entry, true, true, 5);
    params_box.pack_start(&p_box, false, false, 5);
    
    // Обираємо генератор g
    let g_box = Box::new(Orientation::Horizontal, 5);
    let g_label = Label::new(Some("Generator g:"));
    g_box.pack_start(&g_label, false, false, 5);
    let g_entry = Entry::new();
    g_box.pack_start(&g_entry, true, true, 5);
    params_box.pack_start(&g_box, false, false, 5);
    
    // Кнопка для автогенерації параметрів
    let auto_params_button = Button::with_label("Auto Generate Parameters");
    params_box.pack_start(&auto_params_button, false, false, 10);
    
    main_box.pack_start(&params_box, false, false, 10);

    // Учасник A (Аліса)
    let alice_box = Box::new(Orientation::Vertical, 5);
    let alice_label = Label::new(Some("Alice"));
    alice_label.set_markup("<span font='14' weight='bold'>Alice</span>");
    alice_box.pack_start(&alice_label, false, false, 5);
    
    // Приватний ключ Аліси
    let alice_private_box = Box::new(Orientation::Horizontal, 5);
    let alice_private_label = Label::new(Some("Private key a:"));
    alice_private_box.pack_start(&alice_private_label, false, false, 5);
    let alice_private_entry = Entry::new();
    alice_private_box.pack_start(&alice_private_entry, true, true, 5);
    alice_box.pack_start(&alice_private_box, false, false, 5);
    
    // Публічний ключ Аліси
    let alice_public_box = Box::new(Orientation::Horizontal, 5);
    let alice_public_label = Label::new(Some("Public key A:"));
    alice_public_box.pack_start(&alice_public_label, false, false, 5);
    let alice_public_entry = Entry::new();
    alice_public_entry.set_editable(false);
    alice_public_box.pack_start(&alice_public_entry, true, true, 5);
    alice_box.pack_start(&alice_public_box, false, false, 5);
    
    // Кнопка для генерації ключа Аліси
    let generate_alice_button = Button::with_label("Generate Alice's Keys");
    alice_box.pack_start(&generate_alice_button, false, false, 5);
    
    main_box.pack_start(&alice_box, false, false, 10);

    // Учасник B (Боб)
    let bob_box = Box::new(Orientation::Vertical, 5);
    let bob_label = Label::new(Some("Bob"));
    bob_label.set_markup("<span font='14' weight='bold'>Bob</span>");
    bob_box.pack_start(&bob_label, false, false, 5);
    
    // Приватний ключ Боба
    let bob_private_box = Box::new(Orientation::Horizontal, 5);
    let bob_private_label = Label::new(Some("Private key b:"));
    bob_private_box.pack_start(&bob_private_label, false, false, 5);
    let bob_private_entry = Entry::new();
    bob_private_box.pack_start(&bob_private_entry, true, true, 5);
    bob_box.pack_start(&bob_private_box, false, false, 5);
    
    // Публічний ключ Боба
    let bob_public_box = Box::new(Orientation::Horizontal, 5);
    let bob_public_label = Label::new(Some("Public key B:"));
    bob_public_box.pack_start(&bob_public_label, false, false, 5);
    let bob_public_entry = Entry::new();
    bob_public_entry.set_editable(false);
    bob_public_box.pack_start(&bob_public_entry, true, true, 5);
    bob_box.pack_start(&bob_public_box, false, false, 5);
    
    // Кнопка для генерації ключа Боба
    let generate_bob_button = Button::with_label("Generate Bob's Keys");
    bob_box.pack_start(&generate_bob_button, false, false, 5);
    
    main_box.pack_start(&bob_box, false, false, 10);

    // Секція спільного ключа
    let shared_key_box = Box::new(Orientation::Vertical, 5);
    let shared_key_label = Label::new(Some("Shared Secret Key"));
    shared_key_label.set_markup("<span font='14' weight='bold'>Shared Secret Key</span>");
    shared_key_box.pack_start(&shared_key_label, false, false, 5);
    
    // Спільний ключ для Аліси
    let alice_secret_box = Box::new(Orientation::Horizontal, 5);
    let alice_secret_label = Label::new(Some("Alice's shared key:"));
    alice_secret_box.pack_start(&alice_secret_label, false, false, 5);
    let alice_secret_entry = Entry::new();
    alice_secret_entry.set_editable(false);
    alice_secret_box.pack_start(&alice_secret_entry, true, true, 5);
    shared_key_box.pack_start(&alice_secret_box, false, false, 5);
    
    // Спільний ключ для Боба
    let bob_secret_box = Box::new(Orientation::Horizontal, 5);
    let bob_secret_label = Label::new(Some("Bob's shared key:"));
    bob_secret_box.pack_start(&bob_secret_label, false, false, 5);
    let bob_secret_entry = Entry::new();
    bob_secret_entry.set_editable(false);
    bob_secret_box.pack_start(&bob_secret_entry, true, true, 5);
    shared_key_box.pack_start(&bob_secret_box, false, false, 5);
    
    // Кнопка для розрахунку спільного ключа
    let calculate_shared_button = Button::with_label("Calculate Shared Secret Keys");
    shared_key_box.pack_start(&calculate_shared_button, false, false, 5);
    
    main_box.pack_start(&shared_key_box, false, false, 10);

    // *** НОВИЙ РОЗДІЛ ДЛЯ ШИФРУВАННЯ/ДЕШИФРУВАННЯ ***
    let encryption_box = Box::new(Orientation::Vertical, 5);
    let encryption_label = Label::new(Some("Message Encryption & Decryption"));
    encryption_label.set_markup("<span font='14' weight='bold'>Message Encryption &amp; Decryption</span>");
    encryption_box.pack_start(&encryption_label, false, false, 5);
    
    // Розділ для Аліси
    let alice_encryption_frame = Frame::new(Some("Alice's Message Center"));
    let alice_encryption_box = Box::new(Orientation::Vertical, 5);
    alice_encryption_box.set_margin_top(10);
    alice_encryption_box.set_margin_bottom(10);
    alice_encryption_box.set_margin_start(10);
    alice_encryption_box.set_margin_end(10);
    
    // Текстове поле для введення повідомлення Аліси
    let alice_message_label = Label::new(Some("Enter message:"));
    alice_encryption_box.pack_start(&alice_message_label, false, false, 5);
    
    let alice_message_buffer = TextBuffer::new(None::<&gtk::TextTagTable>);
    let alice_message_view = TextView::with_buffer(&alice_message_buffer);
    alice_message_view.set_wrap_mode(gtk::WrapMode::Word);
    
    let alice_message_scroll = ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    alice_message_scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    alice_message_scroll.set_min_content_height(60);
    alice_message_scroll.add(&alice_message_view);
    
    alice_encryption_box.pack_start(&alice_message_scroll, true, true, 5);
    
    // Кнопки шифрування для Аліси
    let alice_buttons_box = Box::new(Orientation::Horizontal, 5);
    let alice_encrypt_button = Button::with_label("Encrypt");
    let alice_decrypt_button = Button::with_label("Decrypt");
    
    alice_buttons_box.pack_start(&alice_encrypt_button, true, true, 5);
    alice_buttons_box.pack_start(&alice_decrypt_button, true, true, 5);
    alice_encryption_box.pack_start(&alice_buttons_box, false, false, 5);
    
    alice_encryption_frame.add(&alice_encryption_box);
    encryption_box.pack_start(&alice_encryption_frame, true, true, 10);
    
    // Розділ для Боба
    let bob_encryption_frame = Frame::new(Some("Bob's Message Center"));
    let bob_encryption_box = Box::new(Orientation::Vertical, 5);
    bob_encryption_box.set_margin_top(10);
    bob_encryption_box.set_margin_bottom(10);
    bob_encryption_box.set_margin_start(10);
    bob_encryption_box.set_margin_end(10);
    
    // Текстове поле для введення повідомлення Боба
    let bob_message_label = Label::new(Some("Enter message:"));
    bob_encryption_box.pack_start(&bob_message_label, false, false, 5);
    
    let bob_message_buffer = TextBuffer::new(None::<&gtk::TextTagTable>);
    let bob_message_view = TextView::with_buffer(&bob_message_buffer);
    bob_message_view.set_wrap_mode(gtk::WrapMode::Word);
    
    let bob_message_scroll = ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    bob_message_scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    bob_message_scroll.set_min_content_height(60);
    bob_message_scroll.add(&bob_message_view);
    
    bob_encryption_box.pack_start(&bob_message_scroll, true, true, 5);
    
    // Кнопки шифрування для Боба
    let bob_buttons_box = Box::new(Orientation::Horizontal, 5);
    let bob_encrypt_button = Button::with_label("Encrypt");
    let bob_decrypt_button = Button::with_label("Decrypt");
    
    bob_buttons_box.pack_start(&bob_encrypt_button, true, true, 5);
    bob_buttons_box.pack_start(&bob_decrypt_button, true, true, 5);
    bob_encryption_box.pack_start(&bob_buttons_box, false, false, 5);
    
    bob_encryption_frame.add(&bob_encryption_box);
    encryption_box.pack_start(&bob_encryption_frame, true, true, 10);
    
    main_box.pack_start(&encryption_box, true, true, 10);
    
    // Кнопка для збереження даних
    let save_data_button = Button::with_label("Save Protocol Data");
    main_box.pack_start(&save_data_button, false, false, 10);

    // Клонуємо змінні для подій
    let p_entry_clone = p_entry.clone();
    let g_entry_clone = g_entry.clone();
    let window_clone = window.clone();
    
    // Подія для автогенерації параметрів
    auto_params_button.connect_clicked(move |_| {
        // Генеруємо велике просте число p (для прикладу робимо 32-бітове)
        let mut rng = thread_rng();
        let mut p = rng.gen_biguint(32);
        
        // Шукаємо просте число p
        while !is_prime(&p) || p < BigUint::from(3u32) {
            p = rng.gen_biguint(32);
        }
        
        // Для спрощення беремо g=2 (примітивний корінь для багатьох простих чисел)
        // В реальних системах треба перевіряти чи g є генератором для p
        let g = BigUint::from(2u32);
        
        // Заповнюємо поля
        p_entry_clone.set_text(&p.to_string());
        g_entry_clone.set_text(&g.to_string());
        
        show_info_dialog(&window_clone, "Parameters automatically generated");
    });
    
    // Клонуємо змінні для генерації ключа Аліси
    let p_entry_alice = p_entry.clone();
    let g_entry_alice = g_entry.clone();
    let alice_private_entry_clone = alice_private_entry.clone();
    let alice_public_entry_clone = alice_public_entry.clone();
    let window_alice = window.clone();
    
    // Подія для генерації ключа Аліси
    generate_alice_button.connect_clicked(move |_| {
        let p_str = p_entry_alice.text();
        let g_str = g_entry_alice.text();
        let a_str = alice_private_entry_clone.text();
        
        // Перевіряємо чи параметри задані
        if p_str.is_empty() || g_str.is_empty() {
            show_error_dialog(&window_alice, "Please define protocol parameters first");
            return;
        }
        
        // Перетворюємо рядки у числа
        let p = match p_str.parse::<BigUint>() {
            Ok(p) => {
                if !is_prime(&p) {
                    show_error_dialog(&window_alice, "p must be a prime number");
                    return;
                }
                p
            },
            Err(_) => {
                show_error_dialog(&window_alice, "Invalid p value");
                return;
            }
        };
        
        let g = match g_str.parse::<BigUint>() {
            Ok(g) => g,
            Err(_) => {
                show_error_dialog(&window_alice, "Invalid g value");
                return;
            }
        };
        
        // Отримуємо приватний ключ a
        let a = if a_str.is_empty() {
            // Якщо користувач не ввів ключ, генеруємо випадковий
            let mut rng = thread_rng();
            let a = rng.gen_biguint_below(&p);
            alice_private_entry_clone.set_text(&a.to_string());
            a
        } else {
            match a_str.parse::<BigUint>() {
                Ok(a) => {
                    if a >= p {
                        show_error_dialog(&window_alice, "Private key must be less than p");
                        return;
                    }
                    a
                },
                Err(_) => {
                    show_error_dialog(&window_alice, "Invalid private key value");
                    return;
                }
            }
        };
        
        // Обчислюємо публічний ключ: A = g^a mod p
        let public_key_a = mod_pow(&g, &a, &p);
        alice_public_entry_clone.set_text(&public_key_a.to_string());
    });
    
    // Клонуємо змінні для генерації ключа Боба
    let p_entry_bob = p_entry.clone();
    let g_entry_bob = g_entry.clone();
    let bob_private_entry_clone = bob_private_entry.clone();
    let bob_public_entry_clone = bob_public_entry.clone();
    let window_bob = window.clone();
    
    // Подія для генерації ключа Боба
    generate_bob_button.connect_clicked(move |_| {
        let p_str = p_entry_bob.text();
        let g_str = g_entry_bob.text();
        let b_str = bob_private_entry_clone.text();
        
        // Перевіряємо чи параметри задані
        if p_str.is_empty() || g_str.is_empty() {
            show_error_dialog(&window_bob, "Please define protocol parameters first");
            return;
        }
        
        // Перетворюємо рядки у числа
        let p = match p_str.parse::<BigUint>() {
            Ok(p) => {
                if !is_prime(&p) {
                    show_error_dialog(&window_bob, "p must be a prime number");
                    return;
                }
                p
            },
            Err(_) => {
                show_error_dialog(&window_bob, "Invalid p value");
                return;
            }
        };
        
        let g = match g_str.parse::<BigUint>() {
            Ok(g) => g,
            Err(_) => {
                show_error_dialog(&window_bob, "Invalid g value");
                return;
            }
        };
        
        // Отримуємо приватний ключ b
        let b = if b_str.is_empty() {
            // Якщо користувач не ввів ключ, генеруємо випадковий
            let mut rng = thread_rng();
            let b = rng.gen_biguint_below(&p);
            bob_private_entry_clone.set_text(&b.to_string());
            b
        } else {
            match b_str.parse::<BigUint>() {
                Ok(b) => {
                    if b >= p {
                        show_error_dialog(&window_bob, "Private key must be less than p");
                        return;
                    }
                    b
                },
                Err(_) => {
                    show_error_dialog(&window_bob, "Invalid private key value");
                    return;
                }
            }
        };
        
        // Обчислюємо публічний ключ: B = g^b mod p
        let public_key_b = mod_pow(&g, &b, &p);
        bob_public_entry_clone.set_text(&public_key_b.to_string());
    });
    
    // Клонуємо змінні для розрахунку спільного ключа
    let p_entry_shared = p_entry.clone();
    let alice_private_entry_shared = alice_private_entry.clone();
    let alice_public_entry_shared = alice_public_entry.clone();
    let bob_private_entry_shared = bob_private_entry.clone();
    let bob_public_entry_shared = bob_public_entry.clone();
    let alice_secret_entry_clone = alice_secret_entry.clone();
    let bob_secret_entry_clone = bob_secret_entry.clone();
    let window_shared = window.clone();
    
    // Подія для розрахунку спільного ключа
    calculate_shared_button.connect_clicked(move |_| {
        let p_str = p_entry_shared.text();
        let a_str = alice_private_entry_shared.text();
        let b_str = bob_private_entry_shared.text();
        let a_public_str = alice_public_entry_shared.text();
        let b_public_str = bob_public_entry_shared.text();
        
        // Перевіряємо чи всі потрібні значення задані
        if p_str.is_empty() || a_str.is_empty() || b_str.is_empty() || 
           a_public_str.is_empty() || b_public_str.is_empty() {
            show_error_dialog(&window_shared, "Please generate keys for both Alice and Bob first");
            return;
        }
        
        // Перетворюємо рядки у числа
        let p = match p_str.parse::<BigUint>() {
            Ok(p) => p,
            Err(_) => {
                show_error_dialog(&window_shared, "Invalid p value");
                return;
            }
        };
        
        let a = match a_str.parse::<BigUint>() {
            Ok(a) => a,
            Err(_) => {
                show_error_dialog(&window_shared, "Invalid Alice's private key");
                return;
            }
        };
        
        let b = match b_str.parse::<BigUint>() {
            Ok(b) => b,
            Err(_) => {
                show_error_dialog(&window_shared, "Invalid Bob's private key");
                return;
            }
        };
        
        let a_public = match a_public_str.parse::<BigUint>() {
            Ok(a_pub) => a_pub,
            Err(_) => {
                show_error_dialog(&window_shared, "Invalid Alice's public key");
                return;
            }
        };
        
        let b_public = match b_public_str.parse::<BigUint>() {
            Ok(b_pub) => b_pub,
            Err(_) => {
                show_error_dialog(&window_shared, "Invalid Bob's public key");
                return;
            }
        };
        
        // Аліса розраховує спільний ключ: K_alice = B^a mod p
        let alice_shared_key = mod_pow(&b_public, &a, &p);
        
        // Боб розраховує спільний ключ: K_bob = A^b mod p
        let bob_shared_key = mod_pow(&a_public, &b, &p);
        
        // Заповнюємо поля
        alice_secret_entry_clone.set_text(&alice_shared_key.to_string());
        bob_secret_entry_clone.set_text(&bob_shared_key.to_string());
        
        // Перевіряємо чи співпадають ключі (повинні бути однакові)
        if alice_shared_key == bob_shared_key {
            show_info_dialog(&window_shared, "Success! Shared keys match! You can now encrypt and decrypt messages.");
        } else {
            show_error_dialog(&window_shared, "Error: Shared keys do not match!");
        }
    });
    
    // *** ПОДІЇ ДЛЯ ШИФРУВАННЯ/ДЕШИФРУВАННЯ ***
    
    // Обробник шифрування для Аліси
    let alice_secret_entry_encrypt = alice_secret_entry.clone();
    let alice_message_buffer_encrypt = alice_message_buffer.clone();
    let window_alice_encrypt = window.clone();
    
    alice_encrypt_button.connect_clicked(move |_| {
        let alice_key_str = alice_secret_entry_encrypt.text();
        
        // Перевіряємо чи ключ згенеровано
        if alice_key_str.is_empty() {
            show_error_dialog(&window_alice_encrypt, "Please calculate shared key first");
            return;
        }
        
        // Отримуємо текст для шифрування
        let start_iter = alice_message_buffer_encrypt.start_iter();
        let end_iter = alice_message_buffer_encrypt.end_iter();
        match alice_message_buffer_encrypt.text(&start_iter, &end_iter, false) {
            Some(text) => {
                if text.is_empty() {
                    show_error_dialog(&window_alice_encrypt, "Please enter a message to encrypt");
                    return;
                }
                
                // Шифруємо повідомлення
                match encrypt_message(&text, &alice_key_str) {
                    Ok(encrypted) => {
                        // Замінюємо текст у буфері на зашифрований
                        alice_message_buffer_encrypt.set_text(&encrypted);
                        show_info_dialog(&window_alice_encrypt, "Message encrypted");
                    },
                    Err(err) => {
                        show_error_dialog(&window_alice_encrypt, &format!("Encryption error: {}", err));
                    }
                }
            },
            None => {
                show_error_dialog(&window_alice_encrypt, "Failed to get text from buffer");
            }
        }
    });
    
    // Обробник дешифрування для Аліси
    let alice_secret_entry_decrypt = alice_secret_entry.clone();
    let alice_message_buffer_decrypt = alice_message_buffer.clone();
    let window_alice_decrypt = window.clone();
    
    alice_decrypt_button.connect_clicked(move |_| {
        let alice_key_str = alice_secret_entry_decrypt.text();
        
        // Перевіряємо чи ключ згенеровано
        if alice_key_str.is_empty() {
            show_error_dialog(&window_alice_decrypt, "Please calculate shared key first");
            return;
        }
        
        // Отримуємо текст для дешифрування
        let start_iter = alice_message_buffer_decrypt.start_iter();
        let end_iter = alice_message_buffer_decrypt.end_iter();
        match alice_message_buffer_decrypt.text(&start_iter, &end_iter, false) {
            Some(text) => {
                if text.is_empty() {
                    show_error_dialog(&window_alice_decrypt, "Please enter a message to decrypt");
                    return;
                }
                
                // Дешифруємо повідомлення
                match decrypt_message(&text, &alice_key_str) {
                    Ok(decrypted) => {
                        // Замінюємо текст у буфері на дешифрований
                        alice_message_buffer_decrypt.set_text(&decrypted);
                        show_info_dialog(&window_alice_decrypt, "Message decrypted");
                    },
                    Err(err) => {
                        show_error_dialog(&window_alice_decrypt, &format!("Decryption error: {}", err));
                    }
                }
            },
            None => {
                show_error_dialog(&window_alice_decrypt, "Failed to get text from buffer");
            }
        }
    });
    
    // Обробник шифрування для Боба
    let bob_secret_entry_encrypt = bob_secret_entry.clone();
    let bob_message_buffer_encrypt = bob_message_buffer.clone();
    let window_bob_encrypt = window.clone();
    
    bob_encrypt_button.connect_clicked(move |_| {
        let bob_key_str = bob_secret_entry_encrypt.text();
        
        // Перевіряємо чи ключ згенеровано
        if bob_key_str.is_empty() {
            show_error_dialog(&window_bob_encrypt, "Please calculate shared key first");
            return;
        }
        
        // Отримуємо текст для шифрування
        let start_iter = bob_message_buffer_encrypt.start_iter();
        let end_iter = bob_message_buffer_encrypt.end_iter();
        match bob_message_buffer_encrypt.text(&start_iter, &end_iter, false) {
            Some(text) => {
                if text.is_empty() {
                    show_error_dialog(&window_bob_encrypt, "Please enter a message to encrypt");
                    return;
                }
                
                // Шифруємо повідомлення
                match encrypt_message(&text, &bob_key_str) {
                    Ok(encrypted) => {
                        // Замінюємо текст у буфері на зашифрований
                        bob_message_buffer_encrypt.set_text(&encrypted);
                        show_info_dialog(&window_bob_encrypt, "Message encrypted");
                    },
                    Err(err) => {
                        show_error_dialog(&window_bob_encrypt, &format!("Encryption error: {}", err));
                    }
                }
            },
            None => {
                show_error_dialog(&window_bob_encrypt, "Failed to get text from buffer");
            }
        }
    });
    
    // Обробник дешифрування для Боба
    let bob_secret_entry_decrypt = bob_secret_entry.clone();
    let bob_message_buffer_decrypt = bob_message_buffer.clone();
    let window_bob_decrypt = window.clone();
    
    bob_decrypt_button.connect_clicked(move |_| {
        let bob_key_str = bob_secret_entry_decrypt.text();
        
        // Перевіряємо чи ключ згенеровано
        if bob_key_str.is_empty() {
            show_error_dialog(&window_bob_decrypt, "Please calculate shared key first");
            return;
        }
        
        // Отримуємо текст для дешифрування
        let start_iter = bob_message_buffer_decrypt.start_iter();
        let end_iter = bob_message_buffer_decrypt.end_iter();
        match bob_message_buffer_decrypt.text(&start_iter, &end_iter, false) {
            Some(text) => {
                if text.is_empty() {
                    show_error_dialog(&window_bob_decrypt, "Please enter a message to decrypt");
                    return;
                }
                
                // Дешифруємо повідомлення
                match decrypt_message(&text, &bob_key_str) {
                    Ok(decrypted) => {
                        // Замінюємо текст у буфері на дешифрований
                        bob_message_buffer_decrypt.set_text(&decrypted);
                        show_info_dialog(&window_bob_decrypt, "Message decrypted");
                    },
                    Err(err) => {
                        show_error_dialog(&window_bob_decrypt, &format!("Decryption error: {}", err));
                    }
                }
            },
            None => {
                show_error_dialog(&window_bob_decrypt, "Failed to get text from buffer");
            }
        }
    });
    
    // Клонуємо змінні для збереження даних
    let p_entry_save = p_entry.clone();
    let g_entry_save = g_entry.clone();
    let alice_private_entry_save = alice_private_entry.clone();
    let alice_public_entry_save = alice_public_entry.clone();
    let bob_private_entry_save = bob_private_entry.clone();
    let bob_public_entry_save = bob_public_entry.clone();
    let alice_secret_entry_save = alice_secret_entry.clone();
    let bob_secret_entry_save = bob_secret_entry.clone();
    let window_save = window.clone();
    
    // Подія для збереження даних
    save_data_button.connect_clicked(move |_| {
        // Збираємо всі дані
        let p = p_entry_save.text();
        let g = g_entry_save.text();
        let alice_private = alice_private_entry_save.text();
        let alice_public = alice_public_entry_save.text();
        let bob_private = bob_private_entry_save.text();
        let bob_public = bob_public_entry_save.text();
        let alice_secret = alice_secret_entry_save.text();
        let bob_secret = bob_secret_entry_save.text();
        
        // Перевіряємо чи є основні дані
        if p.is_empty() || g.is_empty() {
            show_error_dialog(&window_save, "Please define protocol parameters first");
            return;
        }
        
        // Вікно для вибору файлу куди зберегти
        let file_chooser = FileChooserDialog::with_buttons(
            Some("Save Protocol Data"),
            Some(&window_save),
            FileChooserAction::Save,
            &[("Cancel", gtk::ResponseType::Cancel), ("Save", gtk::ResponseType::Accept)]
        );
        
        file_chooser.set_current_name("diffie_hellman_data.txt");
        file_chooser.set_do_overwrite_confirmation(true);
        
        let response = file_chooser.run();
        
        if response == gtk::ResponseType::Accept {
            if let Some(file_path) = file_chooser.filename() {
                match save_data_to_file(&file_path, &p, &g, 
                                        &alice_private, &alice_public, 
                                        &bob_private, &bob_public, 
                                        &alice_secret, &bob_secret) {
                    Ok(_) => {
                        show_info_dialog(&window_save, &format!("Data saved to {:?}", file_path));
                    },
                    Err(err) => {
                        show_error_dialog(&window_save, &format!("Error saving data: {}", err));
                    }
                }
            }
        }
        
        unsafe { file_chooser.destroy(); }
    });
    
    scrolled_window.add(&main_box);
    window.add(&scrolled_window);
    window.show_all();
}

// Функція для перевірки чи число просте
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
    
    // Перевіряємо ділення на непарні числа до кореня
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

// Бінарне піднесення до степеня за модулем (швидкий спосіб)
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

// Функція для шифрування повідомлення
fn encrypt_message(plaintext: &str, key: &str) -> Result<String, String> {
    // Перетворюємо ключ на дійсне числове значення
    let key_value = match key.parse::<BigUint>() {
        Ok(k) => k,
        Err(_) => return Err("Invalid key format".to_string())
    };
    
    // Вилучаємо останні 8 байтів ключа для використання в XOR шифруванні
    // (або менше, якщо ключ коротший)
    let key_bytes = key_value.to_bytes_le();
    let key_len = key_bytes.len();
    
    if key_len == 0 {
        return Err("Key has zero length".to_string());
    }
    
    // Перетворюємо текст у байти
    let plaintext_bytes = plaintext.as_bytes();
    
    // Шифруємо за допомогою XOR з циклічним повторенням ключа
    let mut encrypted_bytes = Vec::with_capacity(plaintext_bytes.len());
    for (i, &byte) in plaintext_bytes.iter().enumerate() {
        let key_byte = key_bytes[i % key_len];
        encrypted_bytes.push(byte ^ key_byte);
    }
    
    // Конвертуємо у base64 для безпечного зберігання
    let base64_encrypted = base64_encode(&encrypted_bytes);
    
    Ok(base64_encrypted)
}

// Функція для дешифрування повідомлення
fn decrypt_message(ciphertext: &str, key: &str) -> Result<String, String> {
    // Перетворюємо ключ на дійсне числове значення
    let key_value = match key.parse::<BigUint>() {
        Ok(k) => k,
        Err(_) => return Err("Invalid key format".to_string())
    };
    
    // Вилучаємо останні 8 байтів ключа для використання в XOR шифруванні
    // (або менше, якщо ключ коротший)
    let key_bytes = key_value.to_bytes_le();
    let key_len = key_bytes.len();
    
    if key_len == 0 {
        return Err("Key has zero length".to_string());
    }
    
    // Декодуємо base64
    let encrypted_bytes = match base64_decode(ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid base64 format".to_string())
    };
    
    // Дешифруємо за допомогою XOR з циклічним повторенням ключа
    let mut decrypted_bytes = Vec::with_capacity(encrypted_bytes.len());
    for (i, &byte) in encrypted_bytes.iter().enumerate() {
        let key_byte = key_bytes[i % key_len];
        decrypted_bytes.push(byte ^ key_byte);
    }
    
    // Конвертуємо назад у текст
    match String::from_utf8(decrypted_bytes) {
        Ok(text) => Ok(text),
        Err(_) => Err("Decryption failed - invalid UTF-8 result".to_string())
    }
}

// Функція для кодування у base64
fn base64_encode(data: &[u8]) -> String {
    let base64_chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    
    while i < data.len() {
        let mut n = (data[i] as u32) << 16;
        if i + 1 < data.len() { n |= (data[i + 1] as u32) << 8; }
        if i + 2 < data.len() { n |= data[i + 2] as u32; }
        
        // Кожні 3 байти даних перетворюються у 4 символи base64
        result.push(base64_chars[(n >> 18 & 0x3F) as usize] as char);
        result.push(base64_chars[(n >> 12 & 0x3F) as usize] as char);
        
        if i + 1 < data.len() {
            result.push(base64_chars[(n >> 6 & 0x3F) as usize] as char);
        } else {
            result.push('='); // Додаємо padding
        }
        
        if i + 2 < data.len() {
            result.push(base64_chars[(n & 0x3F) as usize] as char);
        } else {
            result.push('='); // Додаємо padding
        }
        
        i += 3;
    }
    
    result
}

// Функція для декодування з base64
fn base64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    // Відображення символів base64 на їхні значення
    let mut base64_map = [0u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        base64_map[c as usize] = i as u8;
    }
    
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    
    for c in encoded.chars() {
        // Пропускаємо символи padding
        if c == '=' {
            continue;
        }
        
        if !c.is_ascii() || c as usize >= base64_map.len() {
            return Err(format!("Invalid base64 character: {}", c));
        }
        
        let val = base64_map[c as usize];
        if val > 63 {
            return Err(format!("Invalid base64 character: {}", c));
        }
        
        buffer = (buffer << 6) | val as u32;
        bits += 6;
        
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    
    Ok(result)
}

// Зберігаємо протокольні дані у файл
fn save_data_to_file(
    path: &Path, 
    p: &str, 
    g: &str, 
    alice_private: &str, 
    alice_public: &str, 
    bob_private: &str, 
    bob_public: &str, 
    alice_secret: &str, 
    bob_secret: &str
) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| e.to_string())?;
    
    let content = format!(
        "Diffie-Hellman Key Exchange Protocol\n\n\
         Protocol Parameters:\n\
         Prime modulus (p) = {}\n\
         Generator (g) = {}\n\n\
         Alice:\n\
         Private key (a) = {}\n\
         Public key (A) = g^a mod p = {}\n\n\
         Bob:\n\
         Private key (b) = {}\n\
         Public key (B) = g^b mod p = {}\n\n\
         Shared Secret Keys:\n\
         Alice's key = B^a mod p = {}\n\
         Bob's key = A^b mod p = {}\n\n\
         Verification: {}\n\n\
         Note: The shared secret key can be used for symmetric encryption/decryption of messages between Alice and Bob.",
        p, g, 
        alice_private, alice_public, 
        bob_private, bob_public, 
        alice_secret, bob_secret, 
        if alice_secret == bob_secret { 
            "Shared keys match! The protocol was successful."
        } else { 
            "Shared keys do not match! There was an error in the protocol."
        }
    );
    
    file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
    
    Ok(())
}

// Показуємо вікно з помилкою
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

// Показуємо вікно з інформацією
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
