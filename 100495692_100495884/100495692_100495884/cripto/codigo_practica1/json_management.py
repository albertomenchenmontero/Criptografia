import os
import json

ARCHIVO_USUARIOS = "usuarios.json"


# =====================
# FUNCIONES DE MANEJO DE JSON
# =====================

def cargar_usuarios():
    """
    Carga la información de los usuarios desde un archivo JSON.

    - Comprueba si el archivo 'usuarios.json' existe.
    - Si existe, intenta leer el contenido y convertirlo en un diccionario.
    - Si hay un error en el formato JSON, devuelve un diccionario vacío.
    - Si el archivo no existe, también devuelve un diccionario vacío.

    Retorna un diccionario con los usuarios cargados.
    """
    if os.path.exists(ARCHIVO_USUARIOS):
        with open(ARCHIVO_USUARIOS, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}


def guardar_usuarios(usuarios):
    """
    Guarda la información de los usuarios en un archivo JSON.

    - Recibe un diccionario de usuarios como parámetro.
    - Escribe el contenido en el archivo 'usuarios.json' en formato JSON.
    - Utiliza una indentación de 4 espacios para hacer el archivo más legible.
    """
    with open(ARCHIVO_USUARIOS, "w") as file:
        json.dump(usuarios, file, indent=4)
