import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# =====================
# FUNCIONES PARA HASHING Y VERIFICACIÓN DE CONTRASEÑAS
# =====================

def generar_salt():
    """
    Genera un valor aleatorio (salt) de 16 bytes.

    - Este 'salt' se usa para aumentar la seguridad del hash de la contraseña.
    - Asegura que la misma contraseña no produzca el mismo hash.

    Devuelve el 'salt' generado como un byte array.
    """
    return os.urandom(16)


def hash_password(password, salt):
    """
    Genera un hash seguro de la contraseña proporcionada utilizando PBKDF2-HMAC-SHA256.

    - Recibe la contraseña y un 'salt' como parámetros.
    - Realiza 100,000 iteraciones del algoritmo PBKDF2 usando SHA256.
    - Devuelve el hash de la contraseña codificado en base64.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return hashed_password


def verificar_password(password, salt, hashed_password):
    """
    Verifica si una contraseña proporcionada coincide con el hash almacenado.

    - Recibe la contraseña, el 'salt' utilizado para generar el hash y el hash almacenado.
    - Utiliza PBKDF2-HMAC-SHA256 con las mismas configuraciones para verificar la coincidencia.
    - Devuelve True si la contraseña coincide, False en caso contrario.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        # Verifica si el hash generado coincide con el almacenado
        kdf.verify(password.encode(), base64.urlsafe_b64decode(hashed_password))
        return True
    except:
        # Devuelve False si hay un error en la verificación
        return False
