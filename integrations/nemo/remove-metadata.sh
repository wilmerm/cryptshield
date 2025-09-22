#!/bin/bash

# Get selected files from Nemo environment variable or fallback to command line arguments
if [ -n "$NEMO_SCRIPT_SELECTED_FILE_PATHS" ]; then
    # Use Nemo's multi-selection environment variable
    SELECTED_FILES="$NEMO_SCRIPT_SELECTED_FILE_PATHS"
elif [ -n "$1" ]; then
    # Fallback to command line argument for backward compatibility
    SELECTED_FILES="$1"
else
    echo "Por favor, selecciona uno o más archivos o directorios."
    exit 1
fi

# Count number of selected files
FILE_COUNT=0
while IFS= read -r file; do
    if [ -n "$file" ]; then
        FILE_COUNT=$((FILE_COUNT + 1))
    fi
done <<< "$SELECTED_FILES"

if [ $FILE_COUNT -eq 0 ]; then
    echo "No se seleccionaron archivos."
    exit 1
fi

# Create appropriate dialog text based on selection count
if [ $FILE_COUNT -eq 1 ]; then
    # Single file selected
    FIRST_FILE=$(echo "$SELECTED_FILES" | head -n 1)
    DIALOG_TEXT="¿Estás seguro de que deseas borrar los métadatos de \"$(basename "$FIRST_FILE")\"?"
else
    # Multiple files selected
    DIALOG_TEXT="¿Estás seguro de que deseas borrar los métadatos de $FILE_COUNT archivos seleccionados?"
fi

# Muestra una ventana de confirmación con zenity
zenity --question --text="$DIALOG_TEXT" --title="Confirmación de eliminación de metadatos"

# Si el usuario acepta, ejecuta el comando
if [ $? -eq 0 ]; then
    # Prepare command to execute for all selected files
    COMMANDS=""
    while IFS= read -r file; do
        if [ -n "$file" ] && [ -e "$file" ]; then
            COMMANDS="${COMMANDS}echo 'Eliminando \"$file\"...';"
            COMMANDS="${COMMANDS}if command -v cryptshield >/dev/null 2>&1; then cryptshield clean_metadata \"$file\"; else python3 -m cryptshield clean_metadata \"$file\" 2>/dev/null || echo 'Error: cryptshield no está instalado correctamente'; fi;"
        elif [ -n "$file" ]; then
            COMMANDS="${COMMANDS}echo 'Error: El archivo \"$file\" no existe.';"
        fi
    done <<< "$SELECTED_FILES"

    # Ejecuta el comando de eliminación en una nueva terminal
    if [ -n "$COMMANDS" ]; then
        gnome-terminal -- bash -c "
            $COMMANDS
            echo 'Operación de eliminación de metadatos completada.'
            echo 'Presiona Enter para cerrar...'
            read
        "
    fi
else
    echo "Operación cancelada."
fi

