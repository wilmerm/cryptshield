import logging
import sys
import os
import subprocess
import hashlib
import base64
import glob
from typing import List

from cryptography.fernet import Fernet, InvalidToken

try:
    from .metadata_cleaner import clean_metadata, MetadataCleaner
except ImportError:
    # For direct script execution
    from metadata_cleaner import clean_metadata, MetadataCleaner

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))


ENCRYPTED = 'encrypted'
ZIPENCRYPTED = 'zipencrypted'


class CryptshieldError(Exception):
    pass


def get_logger(
    name='cryptshield',
    level=logging.INFO,
    filename=None,
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

    return logger


logger = get_logger()


def secure_delete(*paths) -> List[str]:
    """
    Securely deletes a file or directory at the specified path.

    Args:
        path (str): The path to the file or directory to be deleted.

    """
    deleted_paths = []
    paths = expand_path(paths)
    total = count_files_and_dirs(paths)
    deleted_count = 0

    for path in paths:
        if not os.path.exists(path):
            logger.error(f"Path '{path}' does not exist.")
            continue

        if os.path.isdir(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        logger.info(f"({deleted_count + 1}/{total}) Deleting '{file_path}'...")
                        subprocess.run(["shred", "-f", "-u", "-n", "3", "-z", file_path], check=True)
                        deleted_paths.append(file_path)
                        deleted_count += 1
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Error deleting file '{file_path}': {e}")

                for dir_ in dirs:
                    dir_path = os.path.join(root, dir_)
                    try:
                        logger.info(f"({deleted_count + 1}/{total}) Deleting '{dir_path}'...")
                        os.rmdir(dir_path)
                        deleted_paths.append(dir_path)
                        deleted_count += 1
                    except OSError as e:
                        logger.error(f"Error deleting directory '{dir_path}': {e}")

            try:
                logger.info(f"({deleted_count + 1}/{total}) Deleting '{path}'...")
                os.rmdir(path)
                deleted_paths.append(path)
                deleted_count += 1
            except OSError as e:
                logger.error(f"Error deleting directory '{path}': {e}")

        else:
            try:
                logger.info(f"({deleted_count + 1}/{total}) Deleting '{path}'...")
                subprocess.run(["shred", "-f", "-u", "-n", "3", "-z", path], check=True)
                deleted_paths.append(path)
                deleted_count += 1
            except subprocess.CalledProcessError as e:
                logger.error(f"Error deleting file '{path}': {e}")

    logger.info(f"Deleted {deleted_count} files and directories.")
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
        logger.debug(f'Using default key: {key}')

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
        logger.debug(f'Using default key: {key}')

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


def expand_path(pattern: str | List[str]) -> List[str]:
    """
    Expands a path pattern into a list of matching file paths.

    Args:
        pattern (str | List[str]): The path pattern to be expanded.

    Returns:
        List[str]: A list of matching file paths.
    """
    if isinstance(pattern, str):
        pattern = [pattern]

    matches = []
    for p in pattern:
        expanded = os.path.expanduser(p)
        # Include hidden files and directories
        _matches = glob.glob(expanded, recursive=True) + glob.glob(os.path.join(expanded, '.*'), recursive=True)
        matches.extend(_matches)
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


def clean_file_metadata(*args):
    """
    Clean metadata from files while preserving primary functionality.
    
    This function removes metadata from various file formats including:
    - Images: EXIF, GPS, camera info, comments
    - Documents: Author, creation date, edit history, comments
    - Multimedia: ID3 tags, artist, album, etc.
    - PDFs: Document properties, metadata, annotations
    """
    
    # Parse command line arguments
    file_paths = []
    preserve_essential = False
    backup = True
    verify = True
    
    for arg in args:
        # Check if it's a boolean-like argument
        if isinstance(arg, str):
            if arg.lower() in ('true', 'yes', '1', 'on'):
                if not file_paths:  # First non-file argument is preserve_essential
                    preserve_essential = True
                elif preserve_essential is not None:  # Second is backup
                    backup = True
                else:  # Third is verify
                    verify = True
                continue
            elif arg.lower() in ('false', 'no', '0', 'off'):
                if not file_paths:  # First non-file argument is preserve_essential
                    preserve_essential = False
                elif preserve_essential is not None:  # Second is backup
                    backup = False
                else:  # Third is verify
                    verify = False
                continue
        
        # Otherwise, treat as file path
        file_paths.append(arg)
    
    # If we got boolean arguments, we need to re-parse correctly
    # Arguments order: file_paths... preserve_essential backup verify
    if len(args) > 1:
        # Check if last few arguments are booleans
        bool_args = []
        file_args = list(args)
        
        # Process from the end to find boolean arguments
        while file_args and isinstance(file_args[-1], str) and file_args[-1].lower() in ('true', 'false', 'yes', 'no', '1', '0', 'on', 'off'):
            bool_args.insert(0, file_args.pop())
        
        file_paths = file_args
        
        # Parse boolean arguments
        if len(bool_args) >= 1:
            preserve_essential = bool_args[0].lower() in ('true', 'yes', '1', 'on')
        if len(bool_args) >= 2:
            backup = bool_args[1].lower() in ('true', 'yes', '1', 'on')
        if len(bool_args) >= 3:
            verify = bool_args[2].lower() in ('true', 'yes', '1', 'on')
    
    expanded_paths = expand_path(file_paths)
    
    if not expanded_paths:
        logger.error("No valid files found to process.")
        return
    
    logger.info(f"Starting metadata cleaning for {len(expanded_paths)} files...")
    logger.info(f"Settings: preserve_essential={preserve_essential}, backup={backup}, verify={verify}")
    
    results = clean_metadata(
        *expanded_paths,
        preserve_essential=preserve_essential,
        backup=backup,
        verify=verify,
        logger=logger
    )
    
    # Summary statistics
    successful = sum(1 for r in results if r.success)
    verified = sum(1 for r in results if r.verified)
    failed = len(results) - successful
    
    logger.info(f"Metadata cleaning completed:")
    logger.info(f"  Successful: {successful}/{len(results)}")
    if verify:
        logger.info(f"  Verified: {verified}/{successful}")
    if failed > 0:
        logger.info(f"  Failed: {failed}")
        
    # List failed files
    failed_files = [r for r in results if not r.success]
    if failed_files:
        logger.error("Failed to clean metadata from:")
        for result in failed_files:
            logger.error(f"  {result.file_path}: {result.error}")
    
    # Audit summary
    total_metadata_removed = sum(len(r.metadata_removed) for r in results if r.success)
    logger.info(f"AUDIT SUMMARY: Removed {total_metadata_removed} metadata entries from {successful} files")


# Mapping commands to their respective functions
COMMAND_MAP = {
    "delete": secure_delete,
    "encrypt": encrypt,
    "decrypt": decrypt,
    "encrypt_text": encrypt_text,
    "decrypt_text": decrypt_text,
    "clean_metadata": clean_file_metadata,
}


def show_help():
    """
    Displays usage instructions.
    """
    print(
        """
        Usage: cryptshield <command> [options]

        Commands:
            delete <path>...: Securely delete files or directories.
            encrypt <path> <key> [--delete]: Encrypt files or directories.
            decrypt <path> <key> [--delete]: Decrypt encrypted files or directories.
            encrypt_text <text> <key>: Encrypt text using a key.
            decrypt_text <text> <key>: Decrypt encrypted text using a key.
            clean_metadata <path>... [preserve_essential] [backup] [verify]: Clean metadata from files.
            help: Show this help message.
            
        Examples:
            # Clean metadata from files
            cryptshield clean_metadata /path/to/image.jpg /path/to/document.pdf
            
            # Clean metadata with essential preservation
            cryptshield clean_metadata /path/to/file.jpg true true true
            
            # Clean without backup (not recommended)
            cryptshield clean_metadata /path/to/file.pdf false false true
        """
    )


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
        command(*options)
    except CryptshieldError as e:
        print(f'Error executing command "{command_name}": {str(e)}')
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()