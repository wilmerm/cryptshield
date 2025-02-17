#!/bin/bash

# Verifica si se ha pasado un argumento (archivo o directorio)
if [ -z "$1" ]; then
    echo "Por favor, pasa un archivo o directorio como argumento."
    exit 1
fi

# Verifica si el archivo o directorio existe
if [ -e "$1" ]; then
    # Solicita la clave de cifrado con zenity
    KEY=$(zenity --entry --text="Ingresa la clave para cifrar \"$1\":" --title="Clave de cifrado")

    # Si el usuario no ingresa la clave, cancela la operación
    if [ -z "$KEY" ]; then
        echo "Operación cancelada. No se proporcionó una clave."
        exit 1
    fi

    # Ejecuta el comando de cifrado en una nueva terminal
    gnome-terminal -- bash -c "
        echo 'Cifrando \"$1\" con la clave proporcionada...'
        cryptshield encrypt \"$1\" \"$KEY\"
        exec bash
    "
else
    echo "El archivo o directorio no existe."
    exit 1
fi
