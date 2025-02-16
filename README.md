# Secure Encryption and Deletion Application

This Python application allows you to securely encrypt files and directories using the **Fernet** library and permanently delete them with the **shred** command. It is useful for protecting sensitive data and ensuring it cannot be recovered.

## **Main Features**

- **Secure Encryption:** Uses the Fernet library to encrypt files and directories with a user-provided key.
- **Permanent Deletion:** Securely removes files and directories using the **shred** command.
- **Recursive Processing:** Supports encrypting and deleting files within directories recursively.
- **User Confirmation Options:** Can be configured to require user confirmation before encrypting or deleting files.

## **Requirements**

- Python 3.x
- Required libraries: `cryptography`, `hashlib`

---

## **Usage**

### **Running `cryptshield`**

#### Basic syntax:

```sh
cryptshield [COMMAND] [OPTION1] [OPTION2]
```

#### Examples:

```sh
# Encrypt a file
cryptshield encrypt /path/to/file secret_key

# Decrypt a file
cryptshield decrypt /path/to/file.encrypted secret_key

# Encrypt a text
cryptshield encrypt_text "Sample text" secret_key
"gAAAAABnsO0xV07ndDmt-fO..."

# Decrypt a text
cryptshield decrypt_text "gAAAAABnsO0xV07ndDmt-fO..." secret_key
"Sample text"

# Secure file deletion
cryptshield delete /path/to/file
```

---

## Release Information

### Version 1.0.0

You can download the latest release of the **Cryptshield** package as a `.deb` file from the following link:

[Download Cryptshield 1.0.0 (.deb)](https://github.com/wilmerm/cryptshield/releases/download/v1.0.0/cryptshield_1.0.0_all.deb)

### Installation

To install the package on your system, run the following command:

```bash
wget https://github.com/wilmerm/cryptshield/releases/download/v1.0.0/cryptshield_1.0.0_all.deb

sudo dpkg -i cryptshield_1.0.0_all.deb
```

After installation, you can run the `cryptshield` command by simply typing:

```bash
cryptshield encrypt [FILE] [KEY]
```

If you encounter any issues with dependencies, you can resolve them using:

```bash
sudo apt-get install -f
```

---

## **Setup**

Ensure the required libraries are installed using the following command:

```sh
pip install -r requirements.txt
```

If you plan to use **secure deletion**, make sure you have administrator (`sudo`) privileges.

---

### Installation and `.deb` Package Creation

Follow these steps to create and install the `.deb` package for *Cryptshield*:

#### 1. Build the Package
Run:
```bash
dpkg-buildpackage -us -uc
```

#### 2. Install and Test
```bash
sudo dpkg -i ../cryptshield_<version>_all.deb
cryptshield
```

If there are dependency issues, fix them with:
```bash
sudo apt-get install -f
```

---

## **Contributing**

If you'd like to contribute to this project or report an issue, feel free to open an issue or submit a pull request on GitHub.

---

## **License**

This application is distributed under the **MIT License**.