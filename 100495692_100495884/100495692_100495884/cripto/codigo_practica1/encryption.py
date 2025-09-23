import os
import base64
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
import cryptography.hazmat.primitives.serialization as serialization




# =====================
# FUNCIONES DE CIFRADO Y DESCIFRADO AES-GCM
# =====================

# Configuración del sistema de logging para mostrar mensajes de depuración
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')


def derivar_clave_cifrado(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave de cifrado a partir de una contraseña usando el algoritmo PBKDF2-HMAC-SHA256.

    - Toma una contraseña y un 'salt' como entrada.
    - Usa un KDF (Key Derivation Function) con SHA256 para generar una clave segura de 32 bytes.
    - Realiza 100,000 iteraciones para aumentar la seguridad.

    Devuelve la clave generada como un byte array.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    clave = kdf.derive(password.encode())
    logging.debug(f"Clave derivada con KDF. Algoritmo: SHA256, Longitud de clave: {len(clave) * 8} bits")
    return clave


def cifrar_aes_gcm(mensaje: str, clave: bytes, aad: bytes = None) -> dict:
    """
    Cifra un mensaje usando el algoritmo AES en modo GCM (Galois/Counter Mode).

    - Genera un 'nonce' de 12 bytes de manera aleatoria para este cifrado.
    - Cifra el mensaje usando la clave proporcionada.
    - Opción de agregar datos adicionales (AAD) para la autenticación.
    - Devuelve un diccionario con el 'nonce', el texto cifrado y la etiqueta de autenticación (tag).
    """
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    if aad:
        encryptor.authenticate_additional_data(aad)

    if isinstance(mensaje, bytes):
        cifrado = encryptor.update(mensaje) + encryptor.finalize()
    else:
        cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
    tag = encryptor.tag

    # Mensajes de depuración para rastrear el proceso de cifrado
    logging.debug(f"Cifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave) * 8} bits")
    logging.debug(f"Nonce utilizado: {base64.urlsafe_b64encode(nonce).decode('utf-8')}")
    logging.debug(f"Etiqueta de autenticación (tag): {base64.urlsafe_b64encode(tag).decode('utf-8')}")

    return {
        'nonce': nonce,
        'cifrado': cifrado,
        'tag': tag
    }


def descifrar_aes_gcm(cifrado: bytes, clave: bytes, nonce: bytes, tag: bytes, aad: bytes = None) -> str:
    """
    Descifra un mensaje cifrado usando el algoritmo AES en modo GCM.

    - Requiere el texto cifrado, la clave, el 'nonce' y la etiqueta de autenticación (tag) para descifrar.
    - Opción de validar datos adicionales (AAD) si se usaron durante el cifrado.
    - Devuelve el mensaje descifrado como una cadena de texto.
    """
    cipher = Cipher(algorithms.AES(clave), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)

    mensaje_descifrado = decryptor.update(cifrado) + decryptor.finalize()

    # Mensaje de depuración para confirmar el descifrado exitoso
    logging.debug(f"Descifrado AES realizado. Algoritmo: AES, Longitud de clave: {len(clave) * 8} bits")
    return mensaje_descifrado.decode()


def generar_claves_rsa(clave_sesion):
    """
    Genera un par de claves RSA y cifra la clave privada usando AES-GCM con una clave de sesión.

    :param password: Contraseña del usuario, utilizada para derivar la clave privada.
    :param clave_sesion: Clave simétrica utilizada para cifrar la clave privada RSA.
    :return: Un diccionario con la clave privada cifrada y la clave pública.
    """
    # Generar clave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serializar clave privada en formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Sin cifrar inicialmente
    )

    # Serializar clave pública en formato PEM
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Cifrar la clave privada con AES-GCM
    private_key_cifrada = cifrar_aes_gcm(private_key_pem, clave_sesion)

    return {
        'clave_privada_cifrada': {
            'cifrado': base64.urlsafe_b64encode(private_key_cifrada['cifrado']).decode('utf-8'),
            'nonce': base64.urlsafe_b64encode(private_key_cifrada['nonce']).decode('utf-8'),
            'tag': base64.urlsafe_b64encode(private_key_cifrada['tag']).decode('utf-8')
        },
        'clave_publica': base64.urlsafe_b64encode(public_key_pem).decode('utf-8')
    }


def descifrar_clave_privada(clave_privada_cifrada, clave_sesion):
    """
    Descifra una clave privada RSA que ha sido cifrada con AES-GCM.

    :param clave_privada_cifrada: Diccionario con los datos cifrados, el nonce y la etiqueta (tag).
    :param clave_sesion: Clave simétrica utilizada para descifrar la clave privada RSA.
    :return: La clave privada en formato PEM.
    """
    cifrado = base64.urlsafe_b64decode(clave_privada_cifrada['cifrado'])
    nonce = base64.urlsafe_b64decode(clave_privada_cifrada['nonce'])
    tag = base64.urlsafe_b64decode(clave_privada_cifrada['tag'])

    # Descifrar la clave privada
    private_key_pem = descifrar_aes_gcm(cifrado, clave_sesion, nonce, tag)

    return private_key_pem
