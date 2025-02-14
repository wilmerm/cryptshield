import sys
from commands import (
    decrypt,
    decrypt_text,
    encrypt,
    encrypt_text,
    secure_delete,
    GuardianError,
)

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


if __name__ == "__main__":
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
    except GuardianError as e:
        print(f'Error executing command "{command_name}": {str(e)}')
        sys.exit(1)

