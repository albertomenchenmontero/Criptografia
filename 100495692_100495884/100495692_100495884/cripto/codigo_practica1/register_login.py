import json_management
import password_hashing
import data_validation
import encryption
import base64
from exceptions import ValidationError
from encryption import generar_claves_rsa

# =====================
# FUNCIONES DE REGISTRO Y AUTENTICACIÓN
# =====================
def registrar_usuario(nombre_usuario, password, email, telefono):
    """
    Registra un nuevo usuario en el sistema.

    - Carga la lista de usuarios existentes.
    - Valida que todos los campos necesarios estén presentes.
    - Verifica que el nombre de usuario no exista previamente.
    - Valida los formatos de nombre de usuario, contraseña, correo electrónico y teléfono.
    - Genera y almacena de manera segura los valores 'salt' para la contraseña y el cifrado.
    - Cifra el email y el teléfono usando la clave derivada de la contraseña del usuario.
    - Guarda la información cifrada y en formato seguro en un archivo JSON.
    """

    usuarios = json_management.cargar_usuarios()

    # Validación de los campos requeridos
    if not nombre_usuario:
        raise ValidationError("Error: Debes proporcionar un nombre de usuario.")
    if not password:
        raise ValidationError("Error: Debes proporcionar una contraseña.")
    if not email:
        raise ValidationError("Error: Debes proporcionar un correo electrónico.")
    if not telefono:
        raise ValidationError("Error: Debes proporcionar un número de teléfono.")

    # Verificar si el usuario ya existe
    if nombre_usuario in usuarios:
        raise ValidationError(f"Error: El usuario '{nombre_usuario}' ya existe.")

    # Validaciones específicas de formato para cada campo
    try:
        data_validation.validar_nombre_usuario(nombre_usuario)
        data_validation.validar_contraseña(password)
        data_validation.validar_email(email)
        data_validation.validar_telefono(telefono)
    except ValidationError as e:
        raise e

    # Generación de valores 'salt' para la contraseña y el cifrado
    salt_password = password_hashing.generar_salt()
    salt_cifrado = password_hashing.generar_salt()

    # Hash de la contraseña con el 'salt' generado
    hashed_password = password_hashing.hash_password(password, salt_password)

    # Derivación de la clave para cifrado usando la contraseña del usuario
    clave = encryption.derivar_clave_cifrado(password, salt_cifrado)

    # Cifrado de la información sensible (email y teléfono) usando la clave derivada
    email_cifrado = encryption.cifrar_aes_gcm(email, clave)
    telefono_cifrado = encryption.cifrar_aes_gcm(telefono, clave)

    # Generación de cifrado asimétrico
    rsa_keys = generar_claves_rsa(clave)

    # Almacenar la información del usuario de manera cifrada y segura
    usuarios[nombre_usuario] = {
        'salt_password': base64.urlsafe_b64encode(salt_password).decode('utf-8'),
        'salt_cifrado': base64.urlsafe_b64encode(salt_cifrado).decode('utf-8'),
        'hashed_password': hashed_password.decode('utf-8'),
        'email': {
            'cifrado': base64.urlsafe_b64encode(email_cifrado['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(email_cifrado['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(email_cifrado['tag']).decode('utf-8')
        },
        'telefono': {
            'cifrado': base64.urlsafe_b64encode(telefono_cifrado['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(telefono_cifrado['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(telefono_cifrado['tag']).decode('utf-8')
        },
        'clave_privada_cifrada': rsa_keys['clave_privada_cifrada'],
        'clave_publica': rsa_keys['clave_publica']
    }

    # Guardar la información del usuario en el archivo JSON
    json_management.guardar_usuarios(usuarios)
    return True


def autenticar_usuario(nombre_usuario, password):
    """
    Autentica a un usuario en el sistema.

    - Carga la lista de usuarios existentes.
    - Verifica si el nombre de usuario está registrado.
    - Valida la contraseña ingresada comparándola con el hash almacenado.
    - Deriva la clave de cifrado usando la contraseña ingresada.
    - Retorna la información del usuario autenticado si la contraseña es correcta.
    """

    usuarios = json_management.cargar_usuarios()

    # Verificar si el nombre de usuario existe en la base de datos
    if nombre_usuario not in usuarios:
        raise ValidationError(f"Error: El usuario '{nombre_usuario}' no está registrado.")

    # Recuperación de la información del usuario
    user_data = usuarios[nombre_usuario]
    salt_password = base64.urlsafe_b64decode(user_data['salt_password'])
    salt_cifrado = base64.urlsafe_b64decode(user_data['salt_cifrado'])
    hashed_password = user_data['hashed_password']

    # Verificación de la contraseña proporcionada con el hash almacenado
    if password_hashing.verificar_password(password, salt_password, hashed_password):
        # Deriva la clave de cifrado usando la contraseña correcta
        clave = encryption.derivar_clave_cifrado(password, salt_cifrado)
        return {
            'nombre_usuario': nombre_usuario,
            'clave': clave
        }
    else:
        # Si la contraseña no es correcta, se lanza un error
        raise ValidationError("Error: Contraseña incorrecta.")
