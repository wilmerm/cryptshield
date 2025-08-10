# Instrucciones para usar los scripts en el sistema Nemo

Para agregar scripts personalizados al menú contextual de Nemo, sigue estos pasos:

1. **Crear el script**:
    - Escribe tu script y guárdalo en un archivo con la extensión `.sh`.
    - Asegúrate de que el script tenga permisos de ejecución. Puedes hacerlo con el siguiente comando:
      ```bash
      chmod +x tu_script.sh
      ```

2. **Ubicar el script en la carpeta de scripts de Nemo**:
    - Copia tu script a la carpeta de scripts de Nemo. La ruta por defecto es `~/.local/share/nemo/scripts/`.
    - Puedes hacerlo con el siguiente comando:
      ```bash
      cp tu_script.sh ~/.local/share/nemo/scripts/
      ```

3. **Verificar en Nemo**:
    - Abre Nemo y haz clic derecho en cualquier archivo o carpeta.
    - Deberías ver tu script en el menú contextual bajo la sección "Scripts".

¡Listo! Ahora puedes ejecutar tu script directamente desde el menú contextual de Nemo.

## Scripts de Cryptshield para Nemo

Este directorio contiene scripts de integración con Nemo para el uso de Cryptshield:

### Scripts disponibles:

- **`encrypt.sh`**: Cifra archivos y directorios seleccionados
- **`decrypt.sh`**: Descifra archivos y directorios seleccionados  
- **`secure-delete.sh`**: Elimina de forma segura archivos y directorios seleccionados

### Características de Multi-selección

**Nueva funcionalidad**: Los scripts ahora soportan la selección múltiple de archivos y directorios en Nemo.

#### Cómo usar la multi-selección:
1. En Nemo, selecciona múltiples archivos y/o directorios usando:
   - `Ctrl + clic` para seleccionar archivos individuales
   - `Shift + clic` para seleccionar un rango de archivos
   - `Ctrl + A` para seleccionar todos los archivos
2. Haz clic derecho sobre la selección
3. Selecciona el script deseado del menú "Scripts"
4. El script procesará todos los archivos seleccionados

#### Beneficios de la multi-selección:
- **Eficiencia**: Cifra/descifra/elimina múltiples archivos en una sola operación
- **Interfaz intuitiva**: Los diálogos se adaptan automáticamente:
  - Archivo individual: "Ingresa la clave para cifrar 'archivo.txt':"
  - Múltiples archivos: "Ingresa la clave para cifrar 5 archivos seleccionados:"
- **Manejo de errores**: Reporta errores individualmente para cada archivo
- **Compatibilidad**: Mantiene compatibilidad total con la selección de archivos individuales

#### Instalación de los scripts:

```bash
# Copia todos los scripts a la carpeta de Nemo
cp /path/to/cryptshield/integrations/nemo/*.sh ~/.local/share/nemo/scripts/

# Asegúrate de que tengan permisos de ejecución
chmod +x ~/.local/share/nemo/scripts/*.sh
```

### Requisitos:
- Cryptshield instalado en el sistema
- Zenity (para diálogos gráficos)
- Gnome Terminal (para mostrar el progreso de las operaciones)
