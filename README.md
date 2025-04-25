# Password Manager and Generator

**FR** : Un gestionnaire et générateur de mots de passe sécurisés en Python, créé par **23R**.  
**EN** : A secure password manager and generator in Python, built by **23R**.

Ce projet utilise **chiffrement AES-256**, **génération sécurisée**, et **Tkinter** pour gérer et générer des mots de passe.  
This project uses **AES-256 encryption**, **secure generation**, and **Tkinter** to manage and generate passwords.

---

## Fonctionnalités / Features

- **Interface intuitive / Intuitive GUI**  
  Champs pour générer, ajouter, gérer, et afficher les mots de passe, avec connexion par clé maître.

- **Génération sécurisée / Secure generation**  
  Crée des mots de passe aléatoires avec options personnalisées (longueur, types de caractères).

- **Gestion sécurisée / Secure management**  
  Stocke les mots de passe chiffrés (AES-256) et permet de les afficher, masquer, ou supprimer.

- **Sauvegarde / Storage**  
  Enregistre les données dans `passwords.json` (chiffré).

---

## Prérequis / Requirements

- Python 3.8+
- Bibliothèques : `tkinter`, `secrets`, `json`, `base64` (inclus avec Python), `pycryptodome`

Installez les dépendances / Install dependencies:
```bash
pip install -r requirements.txt
```

## Installation / Setup

1. Clonez le dépôt / Clone the repo:
   ```bash
   git clone https://github.com/yourusername/password-manager.git
   ```
2. Installez les dépendances / Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Lancez le gestionnaire / Run the manager:
   ```bash
   python password_manager.py
   ```

## Utilisation / Usage

1. Ouvrez l’interface / Open the GUI.  
2. Entrez une clé maître et connectez-vous / Enter a master key and login.  
3. Pour générer un mot de passe, choisissez la longueur et les types de caractères, puis cliquez sur **Générer** / For a password, select length and character types, then click **Generate**.  
4. Ajoutez un mot de passe avec site et login via **Ajouter** / Add a password with site and login via **Add**.  
5. Cliquez sur **Afficher** pour voir les mots de passe ou **Masquer** pour les cacher / Click **Show** to view passwords or **Hide** to mask them.  
6. Sélectionnez un mot de passe dans la liste et cliquez sur **Supprimer** pour le retirer / Select a password and click **Delete** to remove it.  
7. Les mots de passe sont sauvegardés dans `passwords.json` (chiffré) / Passwords are saved in `passwords.json` (encrypted).

## Notes

- **FR** : Ce projet est pour apprendre la gestion sécurisée des mots de passe, pas pour un usage critique. Utilisez un gestionnaire commercial pour des données sensibles.  
- **EN** : This project is for learning secure password management, not for critical use. Use a commercial manager for sensitive data.  
- Gardez votre clé maître en sécurité, elle est nécessaire pour déchiffrer les données.

## Licence / License

Sous **licence MIT**. Voir [LICENSE](LICENSE) pour plus d’infos.  
Under **MIT License**. See [LICENSE](LICENSE) for details.

## Auteur / Author

**23R** 
