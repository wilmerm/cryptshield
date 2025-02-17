#!/bin/bash

if [ -z "$1" ]; then
    echo "Por favor, pasa un archivo o directorio como argumento."
    exit 1
fi

# Verifica si el archivo o directorio existe
if [ -e "$1" ]; then
    # Solicita la clave de descifrado con zenity
    KEY=$(zenity --entry --text="Ingresa la clave para descifrar \"$1\":" --title="Clave de descifrado")

    # Si el usuario no ingresa la clave, cancela la operación
    if [ -z "$KEY" ]; then
        echo "Operación cancelada. No se proporcionó una clave."
        exit 1
    fi

    # Ejecuta el comando de descifrado en una nueva terminal
    gnome-terminal -- bash -c "
        echo 'Descifrando \"$1\" con la clave proporcionada...'
        cryptshield decrypt \"$1\" \"$KEY\"
        exec bash
    "
else
    echo "El archivo o directorio no existe."
    exit 1
fi

