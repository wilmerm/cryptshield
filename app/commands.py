import os
import subprocess
import hashlib
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)


ENCRYPTED = 'encrypted'
ZIPENCRYPTED = 'zipencrypted'


class GuardianError(Exception):
    pass


def secure_delete(path: str):
    """
    Securely deletes a file or directory at the specified path.

    Args:
        path (str): The path to the file or directory to be securely deleted.

    This function ensures that the file or directory is permanently deleted u
    sing a secure method. If the path points to a directory, it recursively
    deletes all files and subdirectories within it. For files, it uses the
    `shred` command to overwrite the file multiple times before deletion.
    """
    if not os.path.exists(path):
        logger.error(f"Path '{path}' does not exist.")
        return

    if os.path.isdir(path):
        for filename in os.listdir(path):
            _path = os.path.join(path, filename)
            secure_delete(_path)

        try:
            os.rmdir(path)
        except OSError as e:
            logger.error(f"Error deleting directory '{path}': {e}")

    else:
        try:
            subprocess.run(["shred", "-f", "-u", "-n", "3", "-z", path], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error deleting file '{path}': {e}")


def encrypt(path: str, key: str, delete: bool = True):
    """
    Encrypts files at a given path using a provided key.

    Args:
        path (str): The path to the file or directory to be encrypted.
        key (str): The key to be used for encryption.
        delete (bool, optional): If True, the original file will be deleted
            after encryption. Defaults to True.

    This function recursively encrypts all files in the specified directory.
    Encrypted files are saved with the '.encrypted' extension. If the path is a
    directory, it will be compressed into a ZIP file before encryption.

    Example:
        ```
        key = 'secret_key'
        path = '/path/to/file_or_directory'
        encrypt(path, key)
        ```
    """

    if delete and has_non_writable(path):
        if not confirm(f'At least one file in "{path}" is not writable. Continue? [y/N] '):
            return

    if os.path.isdir(path):

        # First, compress the directory into a ZIP file
        logger.info(f'Compressing directory "{path}"...')
        subprocess.run(['zip', '-r', f'{path}.zip', path], check=True)

        # Encrypt the ZIP file
        encrypt(f'{path}.zip', key, delete=False)

        # Rename the encrypted ZIP file to '.zipencrypted'.
        os.rename(f'{path}.zip.{ENCRYPTED}', f'{path}.{ZIPENCRYPTED}')

        # Delete the original directory and ZIP file
        logger.info(f'Deleting "{path}.zip"...')
        secure_delete(f'{path}.zip')
        if delete:
            logger.info(f'Deleting "{path}"...')
            secure_delete(path)

    elif os.path.isfile(path) or os.path.islink(path):
        logger.info(f'Encrypting "{path}"...')
        with open(path, 'rb') as file:
            text = file.read()
            encrypted_text = encrypt_text(text, key)
            with open(path + f'.{ENCRYPTED}', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_text)

        if delete:
            logger.info(f'Deleting "{path}"...')
            secure_delete(path)

    else:
        raise GuardianError(f'"{path}" is not a valid file or directory.')


def decrypt(path: str, key: str, delete: bool = True):
    """
    Decrypts encrypted files at a given path using a provided key.

    Args:
        path (str): The path to the file or directory to be decrypted.
        key (str): The key to be used for decryption.
        delete (bool, optional): If True, the encrypted file will be deleted
            after decryption. Defaults to True.

    This function recursively decrypts all files in the specified directory.
    If the path is a directory, it will decrypt all files within it. Files with
    the '.zipencrypted' extension will be decompressed after decryption.

    Example:
        ```
        key = 'secret_key'
        path = '/path/to/encrypted_file_or_directory'
        decrypt(path, key)
        ```
    """
    if delete and has_non_writable(path):
        if not confirm(f'At least one file in "{path}" is not writable. Continue? [y/N] '):
            return

    if os.path.isdir(path):
        for filename in os.listdir(path):
            _path = os.path.join(path, filename)
            decrypt(_path, key, delete=delete)

    elif os.path.isfile(path) or os.path.islink(path):
        logger.info(f'Decrypting "{path}"...')
        with open(path, 'rb') as encrypted_file:
            encrypted_text = encrypted_file.read()
            text = decrypt_text(encrypted_text, key, to_str=False)

            # Check if the file is a ZIP file that was encrypted
            if path.endswith(f'.{ZIPENCRYPTED}'):
                # Save the decrypted ZIP file
                with open(path.replace(f'.{ZIPENCRYPTED}', '.zip', 1), 'wb') as file:
                    file.write(text)

                # Decompress the ZIP file
                logger.info(f'Decompressing "{path.replace(f".{ZIPENCRYPTED}", ".zip", 1)}"...')
                subprocess.run(['unzip', path.replace(f'.{ZIPENCRYPTED}', '.zip', 1)], check=True)

                # Delete the encrypted ZIP file
                if delete:
                    logger.info(f'Deleting "{path}"...')
                    secure_delete(path.replace(f'.{ZIPENCRYPTED}', '.zip', 1))
                    secure_delete(path)
            else:
                with open(path.replace(f'.{ENCRYPTED}', '', 1), 'wb') as file:
                    file.write(text)

                # Delete the encrypted file
                if delete:
                    logger.info(f'Deleting "{path}"...')
                    secure_delete(path)

    else:
        raise GuardianError(f'"{path}" is not valid file or directory.')


def encrypt_text(text: str | bytes, key: str) -> bytes:
    """
    Encrypts a text or bytes using a provided key.

    Args:
        text (str | bytes): The text or bytes to be encrypted.
        key (str): The key to be used for encryption.

    Returns:
        bytes: The encrypted text as bytes.

    This function uses the Fernet symmetric encryption algorithm to encrypt
    the provided text or bytes.

    Example:
        ```
        key = 'secret_key'
        text = 'This is a confidential message.'
        encrypted_text = encrypt_text(text, key)
        print(encrypted_text)
        ```
    """
    bkey = get_fernet_key(key)
    fernet = Fernet(bkey)
    bytes_text = text if isinstance(text, bytes) else text.encode()
    encrypted_text = fernet.encrypt(bytes_text)
    return encrypted_text


def decrypt_text(encrypted_text: str, key: str, to_str: bool = True) -> str | bytes:
    """
    Decrypts an encrypted text using the provided key.

    Args:
        encrypted_text (str): The encrypted text to be decrypted.
        key (str): The key to be used for decryption.

    Returns:
        str | bytes: The decrypted text.

    This function uses the Fernet symmetric encryption algorithm to decrypt the
    provided text. The key must match the one used for encryption, otherwise
    a GuardianError will be raised.

    Example:
        ```
        key = 'secret_key'
        encrypted_text = '...'
        decrypted_text = decrypt_text(encrypted_text, key)
        print(decrypted_text)
        ```
    """
    bkey = get_fernet_key(key)
    fernet = Fernet(bkey)

    try:
        decrypted_bytes = fernet.decrypt(encrypted_text)
    except InvalidToken as e:
        raise GuardianError(f'Invalid key: {e}')

    if to_str:
        return decrypted_bytes.decode('utf-8', errors='ignore')

    return decrypted_bytes


def get_fernet_key(key: str) -> bytes:
    """
    Generates a Fernet key from a provided key.

    Args:
        key (str): The key to be used for generating the Fernet key.

    Returns:
        bytes: The generated Fernet key.

    This function generates a Fernet key using the MD5 hash algorithm.
    The key is necessary for securely encrypting and decrypting text using
    the Fernet encryption scheme.
    """
    passcode = key.encode()
    assert isinstance(passcode, bytes)
    hlib = hashlib.md5()
    hlib.update(passcode)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode())


def has_non_writable(path: str) -> bool:
    """
    Checks whether a file or directory (including its contents if it's a directory)
    contains at least one file or subdirectory without write permissions.

    Args:
        path (str): The path to the file or directory to be checked.

    Returns:
        bool: True if at least one file or subdirectory lacks write permissions,
            False otherwise.

    Raises:
        FileNotFoundError: If the specified path does not exist.

    This function recursively checks the write permissions of all files and
    subdirectories within the given path. If the path points to a file, it
    checks the write permissions of that file directly. If the path points to a
    directory, it traverses the directory tree and checks the write permissions
    of all files and subdirectories.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path '{path}' does not exist.")

    if os.path.isfile(path):
        return not os.access(path, os.W_OK)

    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            if not os.access(os.path.join(root, name), os.W_OK):
                return True

    return False


def confirm(prompt: str) -> bool:
    confirm = input(prompt)
    if confirm.lower() in ('y', 'yes'):
        return True
    return False
