#!/bin/bash

# Verifica si se ha pasado un argumento
if [ -z "$1" ]; then
    echo "Por favor, pasa un archivo o directorio como argumento."
    exit 1
fi

# Verifica si el archivo o directorio existe
if [ -e "$1" ]; then
    # Muestra una ventana de confirmación con zenity
    zenity --question --text="¿Estás seguro de que deseas eliminar \"$1\"?" --title="Confirmación de eliminación"

    # Si el usuario acepta, ejecuta el comando
    if [ $? -eq 0 ]; then
        gnome-terminal -- bash -c "
            echo 'Eliminando \"$1\"...'
            cryptshield delete \"$1\"
            exec bash
        "
    else
        echo "Operación cancelada."
    fi
else
    echo "El archivo o directorio no existe."
    exit 1
fi

