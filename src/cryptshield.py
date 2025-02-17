import logging
import sys
import os
import subprocess
import hashlib
import base64
import glob
from typing import List

from cryptography.fernet import Fernet, InvalidToken

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))


ENCRYPTED = 'encrypted'
ZIPENCRYPTED = 'zipencrypted'


class CryptshieldError(Exception):
    pass


def secure_delete(path: str):
    """
    Securely deletes a file or directory at the specified path.

    Args:
        path (str): The path to the file or directory to be deleted.

    """
    deleted_paths = []
    paths = expand_path(path)
    total = count_files_and_dirs(paths)
    deleted_count = 0

    for path in paths:
        if not os.path.exists(path):
            logging.error(f"Path '{path}' does not exist.")
            continue

        if os.path.isdir(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        logging.info(f"({deleted_count + 1}/{total}) Deleting '{file_path}'...")
                        subprocess.run(["shred", "-f", "-u", "-n", "3", "-z", file_path], check=True)
                        deleted_paths.append(file_path)
                        deleted_count += 1
                    except subprocess.CalledProcessError as e:
                        logging.error(f"Error deleting file '{file_path}': {e}")

                for dir_ in dirs:
                    dir_path = os.path.join(root, dir_)
                    try:
                        logging.info(f"({deleted_count + 1}/{total}) Deleting '{dir_path}'...")
                        os.rmdir(dir_path)
                        deleted_paths.append(dir_path)
                        deleted_count += 1
                    except OSError as e:
                        logging.error(f"Error deleting directory '{dir_path}': {e}")

            try:
                logging.info(f"({deleted_count + 1}/{total}) Deleting '{path}'...")
                os.rmdir(path)
                deleted_paths.append(path)
                deleted_count += 1
            except OSError as e:
                logging.error(f"Error deleting directory '{path}': {e}")

        else:
            try:
                logging.info(f"({deleted_count + 1}/{total}) Deleting '{path}'...")
                subprocess.run(["shred", "-f", "-u", "-n", "3", "-z", path], check=True)
                deleted_paths.append(path)
                deleted_count += 1
            except subprocess.CalledProcessError as e:
                logging.error(f"Error deleting file '{path}': {e}")

    logging.info(f"Deleted {deleted_count} files and directories.")
    return deleted_paths


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
        logging.info(f'Compressing directory "{path}"...')
        subprocess.run(['zip', '-r', f'{path}.zip', path], check=True)

        # Encrypt the ZIP file
        encrypt(f'{path}.zip', key, delete=False)

        # Rename the encrypted ZIP file to '.zipencrypted'.
        os.rename(f'{path}.zip.{ENCRYPTED}', f'{path}.{ZIPENCRYPTED}')

        # Delete the original directory and ZIP file
        logging.info(f'Deleting "{path}.zip"...')
        secure_delete(f'{path}.zip')
        if delete:
            logging.info(f'Deleting "{path}"...')
            secure_delete(path)

    elif os.path.isfile(path) or os.path.islink(path):
        logging.info(f'Encrypting "{path}"...')
        with open(path, 'rb') as file:
            text = file.read()
            encrypted_text = encrypt_text(text, key)
            with open(path + f'.{ENCRYPTED}', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_text)

        if delete:
            logging.info(f'Deleting "{path}"...')
            secure_delete(path)

    else:
        raise CryptshieldError(f'"{path}" is not a valid file or directory.')


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
        logging.info(f'Decrypting "{path}"...')
        with open(path, 'rb') as encrypted_file:
            encrypted_text = encrypted_file.read()
            text = decrypt_text(encrypted_text, key, to_str=False)

            # Check if the file is a ZIP file that was encrypted
            if path.endswith(f'.{ZIPENCRYPTED}'):
                # Save the decrypted ZIP file
                with open(path.replace(f'.{ZIPENCRYPTED}', '.zip', 1), 'wb') as file:
                    file.write(text)

                # Decompress the ZIP file
                logging.info(f'Decompressing "{path.replace(f".{ZIPENCRYPTED}", ".zip", 1)}"...')
                subprocess.run(['unzip', path.replace(f'.{ZIPENCRYPTED}', '.zip', 1)], check=True)

                # Delete the encrypted ZIP file
                if delete:
                    logging.info(f'Deleting "{path}"...')
                    secure_delete(path.replace(f'.{ZIPENCRYPTED}', '.zip', 1))
                    secure_delete(path)
            else:
                with open(path.replace(f'.{ENCRYPTED}', '', 1), 'wb') as file:
                    file.write(text)

                # Delete the encrypted file
                if delete:
                    logging.info(f'Deleting "{path}"...')
                    secure_delete(path)

    else:
        raise CryptshieldError(f'"{path}" is not valid file or directory.')


def encrypt_text(text: str | bytes, key: str = None) -> bytes:
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
        ```
    """
    if not key:
        key = get_default_key()
        logging.debug(f'Using default key: {key}')

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
    a CryptshieldError will be raised.

    Example:
        ```
        key = 'secret_key'
        encrypted_text = '...'
        decrypted_text = decrypt_text(encrypted_text, key)
        ```
    """
    if not key:
        key = get_default_key()
        logging.debug(f'Using default key: {key}')

    bkey = get_fernet_key(key)
    fernet = Fernet(bkey)

    try:
        decrypted_bytes = fernet.decrypt(encrypted_text)
    except InvalidToken as e:
        raise CryptshieldError(f'Invalid key: {e}')

    if to_str:
        return decrypted_bytes.decode('utf-8', errors='ignore')

    return decrypted_bytes


def get_default_key() -> str:
    machine_id = subprocess.run(['cat', '/etc/machine-id'], capture_output=True, text=True).stdout.strip()
    user_id = subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip()
    combined = f"{machine_id}-{user_id}"
    key = hashlib.sha256(combined.encode()).hexdigest()
    return key


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


def expand_path(pattern: str) -> List[str]:
    """
    Expands a file path pattern to a list of matching files.
    """
    expanded = os.path.expanduser(pattern)
    matches = glob.glob(expanded)
    return matches


def count_files_and_dirs(paths):
    """
    Counts the number of files and directories in the specified paths.
    """
    total = 0
    for path in paths:
        if os.path.isdir(path):
            for _, dirs, files in os.walk(path):
                total += len(files) + len(dirs)
            total += 1
        elif os.path.isfile(path):
            total += 1
    return total


def confirm(prompt: str) -> bool:
    confirm = input(prompt)
    if confirm.lower() in ('y', 'yes'):
        return True
    return False


def set_logging(
    name=None,
    level=logging.DEBUG,
    filename='app.log',
    formatter='%(levelname)s - %(message)s',
):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create console handler and set level to INFO
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    if filename:
        # Create file handler and set level to INFO
        file_info_handler = logging.FileHandler(filename, mode='w')
        file_info_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(formatter)
        file_info_handler.setFormatter(file_formatter)
        logger.addHandler(file_info_handler)


# Mapping commands to their respective functions
COMMAND_MAP = {
    "delete": secure_delete,
    "encrypt": encrypt,
    "decrypt": decrypt,
    "encrypt_text": encrypt_text,
    "decrypt_text": decrypt_text,
}


def show_help():
    """Displays usage instructions."""
    print("Usage: python secure_app.py [COMMAND] [OPTIONS]")
    print("Available commands:")
    for command, function in COMMAND_MAP.items():
        print(f">> python secure_app.py {command} - {function.__doc__.strip()}")


def main():
    if len(sys.argv) < 2:
        print(f"Missing arguments. {sys.argv=}")
        show_help()
        sys.exit(1)

    command_name = sys.argv[1]
    options = sys.argv[2:]

    if command_name in ("help", "h"):
        print("Showing help:")
        show_help()
        sys.exit(0)

    if command_name not in COMMAND_MAP:
        print(f'Invalid command: "{command_name}".')
        show_help()
        sys.exit(1)

    command = COMMAND_MAP[command_name]

    # Execute command
    try:
        result = command(*options)
        if result is not None:
            print(result)
    except CryptshieldError as e:
        print(f'Error executing command "{command_name}": {str(e)}')
        sys.exit(1)


if __name__ == "__main__":
    set_logging()
    main()