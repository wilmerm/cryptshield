# Secure Encryption, Deletion, and Metadata Cleaning Application

This Python application allows you to securely encrypt files and directories using the **Fernet** library, permanently delete them with the **shred** command, and clean metadata from various file formats. It is useful for protecting sensitive data and ensuring it cannot be recovered.

## **Main Features**

- **Secure Encryption:** Uses the Fernet library to encrypt files and directories with a user-provided key.
- **Permanent Deletion:** Securely removes files and directories using the **shred** command.
- **Metadata Cleaning:** Removes metadata from images, documents, PDFs, and multimedia files while preserving file functionality.
- **Recursive Processing:** Supports encrypting and deleting files within directories recursively.
- **User Confirmation Options:** Can be configured to require user confirmation before encrypting or deleting files.

## **Requirements**

- Python 3.x
- Required libraries: `cryptography`, `piexif`, `pillow`, `PyPDF2`, `python-docx`, `openpyxl`, `mutagen`

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

# Clean metadata from files
cryptshield clean_metadata /path/to/image.jpg /path/to/document.pdf

# Clean metadata with essential information preserved
cryptshield clean_metadata /path/to/file.jpg true true true

# Clean metadata without backup (not recommended)
cryptshield clean_metadata /path/to/file.pdf false false true
```

---

## **Metadata Cleaning Feature**

The metadata cleaning feature provides secure removal of metadata from various file formats while maintaining the primary functionality of files. This feature complies with DoD 5220.22-M standards for secure deletion.

### **Supported File Formats**

- **Images:** JPEG, PNG, TIFF, GIF
  - Removes: EXIF data, GPS coordinates, camera information, comments, timestamps
- **Documents:** PDF, DOCX, XLSX, PPTX
  - Removes: Author information, creation/modification dates, comments, document properties, edit history
- **Multimedia:** MP3, MP4, AVI, MOV, WAV, FLAC
  - Removes: ID3 tags, artist, album, comments, metadata
- **Text Files:** TXT, RTF
  - Removes: File system metadata where applicable

### **Metadata Cleaning Options**

1. **preserve_essential** (true/false): Whether to preserve essential metadata like title and creator
2. **backup** (true/false): Whether to create backups before cleaning (recommended)
3. **verify** (true/false): Whether to verify metadata removal after cleaning

### **Security Features**

- **Secure Backup Management:** Creates temporary backups during processing, removes them after successful verification
- **Verification Process:** Confirms metadata has been successfully removed
- **Audit Logging:** Detailed logs of all metadata cleaning operations
- **DoD 5220.22-M Compliance:** Follows secure deletion standards
- **Forensic Recovery Prevention:** Ensures metadata cannot be recovered

### **Examples**

```sh
# Basic metadata cleaning
cryptshield clean_metadata /path/to/photo.jpg

# Clean multiple files
cryptshield clean_metadata /path/to/photo.jpg /path/to/document.pdf /path/to/music.mp3

# Preserve essential metadata (title, creator)
cryptshield clean_metadata /path/to/document.pdf true

# Clean without backup (faster, but less safe)
cryptshield clean_metadata /path/to/file.jpg false

# Full control: preserve_essential=false, backup=true, verify=true
cryptshield clean_metadata /path/to/file.jpg false true true
```

---

## Release Information

### Version 1.1.0

You can download the latest release of the **Cryptshield** package as a `.deb` file from the following link:

[Download Cryptshield 1.1.0 (.deb)](https://github.com/wilmerm/cryptshield/releases/download/v1.1.0/cryptshield_1.1.0_all.deb)

### Installation

To install the package on your system, run the following command:

```bash
wget https://github.com/wilmerm/cryptshield/releases/download/v1.1.0/cryptshield_1.1.0_all.deb

sudo dpkg -i cryptshield_1.1.0_all.deb
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

### Building and Publishing the Library

To compile and upload the library to PyPI, follow these steps:

1. Ensure you have the necessary dependencies:

    ```sh
    pip install build twine
    ```

2. Build the package:

    ```sh
    python -m build
    ```

3. (Optional) Verify the package:

    ```sh
    twine check dist/*
    ```

4. Upload the package to PyPI:

    ```sh
    python -m twine upload dist/*
    ```

---

## **Contributing**

If you'd like to contribute to this project or report an issue, feel free to open an issue or submit a pull request on GitHub.

---

## **License**

This application is distributed under the **MIT License**.

## Contribution 💗

If you find value in this project and would like to show your support, please consider making a donation via PayPal:

[Donate on PayPal](https://paypal.me/martinezwilmer?country.x=DO&locale.x=es_XC)

Your generosity helps us to continue improving and maintaining this project. We appreciate every contribution, however small. Thanks for being part of our community!
