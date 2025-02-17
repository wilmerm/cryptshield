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
