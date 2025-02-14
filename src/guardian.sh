#!/bin/bash

PYTHONPATH=$(dirname $(dirname $(realpath $0)))/src python3 -m guardian "$@"

# Validate if at least one argument is provided
if [ -z "$1" ]; then
    echo "Error: Missing command."
    echo "Usage: $0 <command> [option1] [option2]"
    exit 1
fi

command_name="$1"
option1="${2:-}"
option2="${3:-}"

python3 guardian.py "$command_name" "$option1" "$option2"
