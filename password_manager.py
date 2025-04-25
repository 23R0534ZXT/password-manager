# Password Manager and Generator
# Auteur/Author: 23R
# Créé/Created: April 2025
# Description (FR): Générateur et gestionnaire de mots de passe sécurisés avec chiffrement AES et interface Tkinter.
# Description (EN): Secure password manager and generator with AES encryption and Tkinter GUI.
# Dépendances/Requirements: Python 3.8+, tkinter (inclus/included), pycryptodome

import tkinter as tk
from tkinter import messagebox, ttk
import secrets
import string
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os

# Variables globales / Global variables
passwords = []
MASTER_KEY = None
SHOW_PASSWORDS = False


def derive_key(master_password, salt):
    """
    FR: Dérive une clé AES à partir du mot de passe maître avec PBKDF2.
    EN: Derives an AES key from the master password using PBKDF2.
    """
    return PBKDF2(master_password, salt, dkLen=32, count=100000)


def encrypt_data(data, key):
    """
    FR: Chiffre les données avec AES-256.
    EN: Encrypts data with AES-256.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return {'iv': iv, 'ciphertext': ct}


def decrypt_data(encrypted_data, key):
    """
    FR: Déchiffre les données avec AES-256.
    EN: Decrypts data with AES-256.
    """
    try:
        iv = base64.b64decode(encrypted_data['iv'])
        ct = base64.b64decode(encrypted_data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None


def generate_password(length, use_upper, use_lower, use_digits, use_special):
    """
    FR: Génère un mot de passe sécurisé avec les options choisies.
    EN: Generates a secure password with the selected options.
    """
    chars = ''
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    if not chars:
        return None

    return ''.join(secrets.choice(chars) for _ in range(length))


def check_password_strength(password):
    """
    FR: Évalue la force du mot de passe.
    EN: Evaluates the password strength.
    """
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Trop court (< 8 caractères) / Too short (< 8 characters)")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des majuscules / Add uppercase letters")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des minuscules / Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres / Add digits")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux / Add special characters")

    if score >= 5:
        return "Fort/Strong", feedback
    elif score >= 3:
        return "Moyen/Medium", feedback
    else:
        return "Faible/Weak", feedback


def save_passwords(master_key):
    """
    FR: Sauvegarde les mots de passe chiffrés dans passwords.json.
    EN: Saves encrypted passwords to passwords.json.
    """
    if not passwords or not master_key:
        return

    salt = os.urandom(16)
    key = derive_key(master_key, salt)
    data = json.dumps(passwords)
    encrypted = encrypt_data(data, key)

    with open("passwords.json", "w") as f:
        json.dump({'salt': base64.b64encode(salt).decode('utf-8'), 'data': encrypted}, f)


def load_passwords(master_key):
    """
    FR: Charge les mots de passe chiffrés depuis passwords.json.
    EN: Loads encrypted passwords from passwords.json.
    """
    global passwords
    try:
        with open("passwords.json", "r") as f:
            encrypted = json.load(f)

        salt = base64.b64decode(encrypted['salt'])
        key = derive_key(master_key, salt)
        decrypted = decrypt_data(encrypted['data'], key)

        if decrypted:
            passwords = json.loads(decrypted)
            return True
        return False
    except FileNotFoundError:
        passwords = []
        return True
    except Exception:
        return False


def start_gui():
    """
    FR: Crée l'interface graphique Tkinter pour le gestionnaire.
    EN: Sets up the Tkinter GUI for the manager.
    """

    def login():
        """FR: Valide la clé maître et charge les données.
           EN: Validates the master key and loads data."""
        global MASTER_KEY
        MASTER_KEY = master_entry.get()
        if not MASTER_KEY:
            messagebox.showerror("Erreur/Error", "Entrez une clé maître / Enter a master key")
            return

        if load_passwords(MASTER_KEY):
            login_frame.pack_forget()
            main_frame.pack()
            update_listbox()
        else:
            messagebox.showerror("Erreur/Error", "Clé maître incorrecte / Incorrect master key")

    def generate():
        """FR: Génère un mot de passe et affiche sa force.
           EN: Generates a password and shows its strength."""
        try:
            length = int(length_entry.get())
            if length < 8 or length > 50:
                raise ValueError
        except ValueError:
            messagebox.showerror("Erreur/Error", "Longueur entre 8 et 50 / Length between 8 and 50")
            return

        password = generate_password(
            length,
            upper_var.get(),
            lower_var.get(),
            digits_var.get(),
            special_var.get()
        )

        if not password:
            messagebox.showerror("Erreur/Error",
                                 "Choisissez au moins un type de caractère / Select at least one character type")
            return

        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)

        strength, feedback = check_password_strength(password)
        strength_label.config(text=f"Force/Strength: {strength}")
        feedback_text.delete(1.0, tk.END)
        feedback_text.insert(tk.END, "\n".join(feedback) or "Bon mot de passe / Good password")

    def add_password():
        """FR: Ajoute un mot de passe à la liste.
           EN: Adds a password to the list."""
        site = site_entry.get()
        login = login_entry.get()
        password = password_entry.get()

        if not (site and login and password):
            messagebox.showerror("Erreur/Error", "Remplissez tous les champs / Fill all fields")
            return

        passwords.append({'site': site, 'login': login, 'password': password})
        save_passwords(MASTER_KEY)
        update_listbox()

        site_entry.delete(0, tk.END)
        login_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        strength_label.config(text="Force/Strength: ")
        feedback_text.delete(1.0, tk.END)

    def delete_password():
        """FR: Supprime un mot de passe sélectionné.
           EN: Deletes a selected password."""
        try:
            index = listbox.curselection()[0]
            passwords.pop(index)
            save_passwords(MASTER_KEY)
            update_listbox()
        except IndexError:
            messagebox.showerror("Erreur/Error", "Sélectionnez un mot de passe / Select a password")

    def toggle_show_passwords():
        """FR: Affiche ou masque les mots de passe dans la liste.
           EN: Shows or hides passwords in the list."""
        global SHOW_PASSWORDS
        SHOW_PASSWORDS = not SHOW_PASSWORDS
        show_button.config(text="Masquer/Hide" if SHOW_PASSWORDS else "Afficher/Show")
        update_listbox()

    def update_listbox():
        """FR: Met à jour la liste des mots de passe affichés.
           EN: Updates the displayed password list."""
        listbox.delete(0, tk.END)
        for p in passwords:
            password_display = p['password'] if SHOW_PASSWORDS else '********'
            listbox.insert(tk.END, f"{p['site']} - {p['login']} - {password_display}")

    # FR: Configure la fenêtre / EN: Set up the window
    root = tk.Tk()
    root.title("Password Manager - by 23R")

    # FR: Écran de connexion / EN: Login screen
    login_frame = tk.Frame(root)
    login_frame.pack(pady=20)

    tk.Label(login_frame, text="Clé maître/Master key:").pack()
    master_entry = tk.Entry(login_frame, show="*")
    master_entry.pack(pady=5)
    tk.Button(login_frame, text="Connexion/Login", bg="blue", fg="white", command=login).pack(pady=10)

    # FR: Écran principal / EN: Main screen
    main_frame = tk.Frame(root)

    # Générateur / Generator
    tk.Label(main_frame, text="Générer un mot de passe / Generate a password").grid(row=0, column=0, columnspan=2,
                                                                                    pady=10)

    tk.Label(main_frame, text="Longueur/Length:").grid(row=1, column=0, sticky='e')
    length_entry = tk.Entry(main_frame)
    length_entry.grid(row=1, column=1)
    length_entry.insert(0, "12")

    upper_var = tk.BooleanVar(value=True)
    lower_var = tk.BooleanVar(value=True)
    digits_var = tk.BooleanVar(value=True)
    special_var = tk.BooleanVar(value=True)

    tk.Checkbutton(main_frame, text="Majuscules/Uppercase", variable=upper_var).grid(row=2, column=0, columnspan=2,
                                                                                     sticky='w')
    tk.Checkbutton(main_frame, text="Minuscules/Lowercase", variable=lower_var).grid(row=3, column=0, columnspan=2,
                                                                                     sticky='w')
    tk.Checkbutton(main_frame, text="Chiffres/Digits", variable=digits_var).grid(row=4, column=0, columnspan=2,
                                                                                 sticky='w')
    tk.Checkbutton(main_frame, text="Spéciaux/Special chars", variable=special_var).grid(row=5, column=0, columnspan=2,
                                                                                         sticky='w')

    tk.Button(main_frame, text="Générer/Generate", bg="green", fg="white", command=generate).grid(row=6, column=1,
                                                                                                  pady=10)

    # Résultats / Results
    tk.Label(main_frame, text="Mot de passe/Password:").grid(row=7, column=0, sticky='e')
    password_entry = tk.Entry(main_frame)
    password_entry.grid(row=7, column=1)

    strength_label = tk.Label(main_frame, text="Force/Strength: ")
    strength_label.grid(row=8, column=0, columnspan=2)

    feedback_text = tk.Text(main_frame, height=4, width=30)
    feedback_text.grid(row=9, column=0, columnspan=2, pady=5)

    # Gestion / Management
    tk.Label(main_frame, text="Site:").grid(row=10, column=0, sticky='e')
    site_entry = tk.Entry(main_frame)
    site_entry.grid(row=10, column=1)

    tk.Label(main_frame, text="Login:").grid(row=11, column=0, sticky='e')
    login_entry = tk.Entry(main_frame)
    login_entry.grid(row=11, column=1)

    tk.Button(main_frame, text="Ajouter/Add", bg="blue", fg="white", command=add_password).grid(row=12, column=1,
                                                                                                pady=10)
    tk.Button(main_frame, text="Supprimer/Delete", bg="red", fg="white", command=delete_password).grid(row=13, column=1,
                                                                                                       pady=10)
    show_button = tk.Button(main_frame, text="Afficher/Show", bg="purple", fg="white", command=toggle_show_passwords)
    show_button.grid(row=14, column=1, pady=10)

    listbox = tk.Listbox(main_frame, height=5, width=40)
    listbox.grid(row=15, column=0, columnspan=2, pady=5)

    root.mainloop()


if __name__ == "__main__":
    start_gui()
