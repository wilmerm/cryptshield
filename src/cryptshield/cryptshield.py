import logging
import sys
import os
import subprocess
import hashlib
import base64
import glob
import gc
import time
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken

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


def encrypt(path: str, key: str, delete: bool = True, cleanup_meta: bool = True):
    """
    Encrypts files at a given path using a provided key.

    Args:
        path (str): The path to the file or directory to be encrypted.
        key (str): The key to be used for encryption.
        delete (bool, optional): If True, the original file will be deleted
            after encryption. Defaults to True.
        cleanup_meta (bool, optional): If True, metadata will be cleaned up
            from encrypted files. Defaults to True.

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
        encrypt(f'{path}.zip', key, delete=False, cleanup_meta=cleanup_meta)

        # Rename the encrypted ZIP file to '.zipencrypted'.
        os.rename(f'{path}.zip.{ENCRYPTED}', f'{path}.{ZIPENCRYPTED}')

        # Clean up metadata on the encrypted file
        if cleanup_meta:
            logger.info(f'Cleaning up metadata for "{path}.{ZIPENCRYPTED}"...')
            cleanup_result = cleanup_metadata(f'{path}.{ZIPENCRYPTED}')
            if cleanup_result.get('errors'):
                logger.warning(f"Metadata cleanup warnings: {cleanup_result['errors']}")

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
            encrypted_path = path + f'.{ENCRYPTED}'
            with open(encrypted_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_text)

        # Clean up metadata on the encrypted file
        if cleanup_meta:
            logger.info(f'Cleaning up metadata for "{encrypted_path}"...')
            cleanup_result = cleanup_metadata(encrypted_path)
            if cleanup_result.get('errors'):
                logger.warning(f"Metadata cleanup warnings: {cleanup_result['errors']}")

        if delete:
            logger.info(f'Deleting "{path}"...')
            secure_delete(path)
        
        # Clear sensitive data from memory
        clear_sensitive_memory(text, encrypted_text)

    else:
        raise CryptshieldError(f'"{path}" is not a valid file or directory.')


def decrypt(path: str, key: str, delete: bool = True, cleanup_meta: bool = True):
    """
    Decrypts encrypted files at a given path using a provided key.

    Args:
        path (str): The path to the file or directory to be decrypted.
        key (str): The key to be used for decryption.
        delete (bool, optional): If True, the encrypted file will be deleted
            after decryption. Defaults to True.
        cleanup_meta (bool, optional): If True, metadata will be cleaned up
            from decrypted files. Defaults to True.

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
            decrypt(_path, key, delete=delete, cleanup_meta=cleanup_meta)

    elif os.path.isfile(path) or os.path.islink(path):
        logger.info(f'Decrypting "{path}"...')
        with open(path, 'rb') as encrypted_file:
            encrypted_text = encrypted_file.read()
            text = decrypt_text(encrypted_text, key, to_str=False)

            # Check if the file is a ZIP file that was encrypted
            if path.endswith(f'.{ZIPENCRYPTED}'):
                # Save the decrypted ZIP file
                zip_path = path.replace(f'.{ZIPENCRYPTED}', '.zip', 1)
                with open(zip_path, 'wb') as file:
                    file.write(text)

                # Clean up metadata on the decrypted ZIP file
                if cleanup_meta:
                    logger.info(f'Cleaning up metadata for "{zip_path}"...')
                    cleanup_result = cleanup_metadata(zip_path)
                    if cleanup_result.get('errors'):
                        logger.warning(f"Metadata cleanup warnings: {cleanup_result['errors']}")

                # Decompress the ZIP file
                logger.info(f'Decompressing "{zip_path}"...')
                subprocess.run(['unzip', zip_path], check=True)

                # Delete the encrypted ZIP file
                if delete:
                    logger.info(f'Deleting "{path}"...')
                    secure_delete(zip_path)
                    secure_delete(path)
            else:
                decrypted_path = path.replace(f'.{ENCRYPTED}', '', 1)
                with open(decrypted_path, 'wb') as file:
                    file.write(text)

                # Clean up metadata on the decrypted file
                if cleanup_meta:
                    logger.info(f'Cleaning up metadata for "{decrypted_path}"...')
                    cleanup_result = cleanup_metadata(decrypted_path)
                    if cleanup_result.get('errors'):
                        logger.warning(f"Metadata cleanup warnings: {cleanup_result['errors']}")

                # Delete the encrypted file
                if delete:
                    logger.info(f'Deleting "{path}"...')
                    secure_delete(path)
            
            # Clear sensitive data from memory
            clear_sensitive_memory(encrypted_text, text)

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
    
    # Clear sensitive data from memory
    clear_sensitive_memory(bytes_text)
    
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
        result = decrypted_bytes.decode('utf-8', errors='ignore')
        # Clear sensitive data from memory
        clear_sensitive_memory(decrypted_bytes)
        return result

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


def clear_extended_attributes(path: str) -> bool:
    """
    Clears all extended attributes from a file or directory.
    
    Args:
        path (str): The path to the file or directory.
        
    Returns:
        bool: True if extended attributes were cleared, False if none existed or operation failed.
    """
    try:
        # List all extended attributes
        result = subprocess.run(['getfattr', '-d', path], capture_output=True, text=True)
        if result.returncode != 0:
            return False
            
        # Parse the output to get attribute names
        lines = result.stdout.strip().split('\n')
        attributes = []
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            if '=' in line:
                attr_name = line.split('=')[0]
                attributes.append(attr_name)
        
        # Remove each extended attribute
        for attr in attributes:
            subprocess.run(['setfattr', '-x', attr, path], check=True)
            logger.debug(f"Removed extended attribute '{attr}' from '{path}'")
        
        return len(attributes) > 0
        
    except (subprocess.CalledProcessError, FileNotFoundError):
        # getfattr/setfattr not available or other error
        return False


def normalize_timestamps(path: str, timestamp: Optional[float] = None) -> bool:
    """
    Normalizes the timestamps of a file to a fixed value or current time.
    
    Args:
        path (str): The path to the file or directory.
        timestamp (Optional[float]): The timestamp to set. If None, uses current time.
        
    Returns:
        bool: True if timestamps were normalized, False otherwise.
    """
    try:
        if timestamp is None:
            timestamp = time.time()
        
        # Set both access and modification times
        os.utime(path, (timestamp, timestamp))
        logger.debug(f"Normalized timestamps for '{path}'")
        return True
    except OSError as e:
        logger.error(f"Failed to normalize timestamps for '{path}': {e}")
        return False


def clear_sensitive_memory(*variables) -> None:
    """
    Attempts to clear sensitive data from memory by overwriting variables.
    
    Args:
        *variables: Variables containing sensitive data to clear.
    """
    for var in variables:
        if isinstance(var, str):
            # Overwrite string with zeros (Python strings are immutable, so this is limited)
            var = '\x00' * len(var)
        elif isinstance(var, bytes):
            # For bytes, we can overwrite the underlying buffer in some cases
            if hasattr(var, 'decode'):
                var = b'\x00' * len(var)
        elif isinstance(var, list):
            var.clear()
        elif isinstance(var, dict):
            var.clear()
    
    # Force garbage collection to clean up unreferenced objects
    gc.collect()


def sync_filesystem() -> bool:
    """
    Forces the filesystem to sync all pending write operations.
    
    Returns:
        bool: True if sync was successful, False otherwise.
    """
    try:
        subprocess.run(['sync'], check=True)
        logger.debug("Filesystem sync completed")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to sync filesystem: {e}")
        return False


def cleanup_metadata(path: str, clear_xattrs: bool = True, normalize_time: bool = True, 
                    timestamp: Optional[float] = None) -> dict:
    """
    Comprehensive metadata cleanup for a file or directory.
    
    Args:
        path (str): The path to clean metadata for.
        clear_xattrs (bool): Whether to clear extended attributes.
        normalize_time (bool): Whether to normalize timestamps.
        timestamp (Optional[float]): The timestamp to set if normalizing.
        
    Returns:
        dict: Summary of cleanup operations performed.
    """
    results = {
        'path': path,
        'extended_attributes_cleared': False,
        'timestamps_normalized': False,
        'filesystem_synced': False,
        'errors': []
    }
    
    if not os.path.exists(path):
        results['errors'].append(f"Path '{path}' does not exist")
        return results
    
    # Clear extended attributes
    if clear_xattrs:
        try:
            results['extended_attributes_cleared'] = clear_extended_attributes(path)
        except Exception as e:
            results['errors'].append(f"Failed to clear extended attributes: {e}")
    
    # Normalize timestamps
    if normalize_time:
        try:
            results['timestamps_normalized'] = normalize_timestamps(path, timestamp)
        except Exception as e:
            results['errors'].append(f"Failed to normalize timestamps: {e}")
    
    # Sync filesystem
    try:
        results['filesystem_synced'] = sync_filesystem()
    except Exception as e:
        results['errors'].append(f"Failed to sync filesystem: {e}")
    
    return results


def cleanup_metadata_cli(*paths):
    """
    CLI wrapper for metadata cleanup functionality.
    
    Args:
        *paths: File or directory paths to clean metadata for.
    """
    if not paths:
        logger.error("No paths provided for metadata cleanup")
        return
    
    expanded_paths = expand_path(list(paths))
    if not expanded_paths:
        logger.error("No valid paths found")
        return
    
    for path in expanded_paths:
        logger.info(f'Cleaning up metadata for "{path}"...')
        result = cleanup_metadata(path)
        
        # Report results
        operations = []
        if result.get('extended_attributes_cleared'):
            operations.append("extended attributes cleared")
        if result.get('timestamps_normalized'):
            operations.append("timestamps normalized")
        if result.get('filesystem_synced'):
            operations.append("filesystem synced")
        
        if operations:
            logger.info(f'  → {", ".join(operations)}')
        else:
            logger.info('  → no metadata changes needed')
        
        if result.get('errors'):
            for error in result['errors']:
                logger.warning(f'  → warning: {error}')
    
    logger.info(f"Metadata cleanup completed for {len(expanded_paths)} path(s)")


def encrypt_text_cli(text: str, key: str = None):
    """
    CLI wrapper for text encryption.
    
    Args:
        text (str): The text to encrypt.
        key (str): The encryption key.
    """
    result = encrypt_text(text, key)
    print(result.decode() if isinstance(result, bytes) else result)


def decrypt_text_cli(encrypted_text: str, key: str):
    """
    CLI wrapper for text decryption.
    
    Args:
        encrypted_text (str): The encrypted text to decrypt.
        key (str): The decryption key.
    """
    result = decrypt_text(encrypted_text, key)
    print(result)


# Mapping commands to their respective functions
COMMAND_MAP = {
    "delete": secure_delete,
    "encrypt": encrypt,
    "decrypt": decrypt,
    "encrypt_text": encrypt_text_cli,
    "decrypt_text": decrypt_text_cli,
    "cleanup": cleanup_metadata_cli,
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
            cleanup <path>: Clean up metadata from files or directories.
            help: Show this help message.
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