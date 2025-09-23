import base64
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, BestAvailableEncryption, PrivateFormat, PublicFormat, load_pem_private_key
)
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import (
    CertificateBuilder, Name, NameOID, random_serial_number, BasicConstraints, SubjectAlternativeName,
    load_pem_x509_certificate
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography import x509
import encryption  # Usaremos las funciones de cifrado simétrico existentes
from cryptography.hazmat.primitives import hashes


# =====================
# FUNCIONES PARA LA CA Y CERTIFICADOS
# =====================

def generar_ca(master_password):
    """
    Genera el certificado raíz (CA) y una clave privada, cifrando esta última con la contraseña maestra.

    :param master_password: Contraseña maestra para cifrar la clave privada de la CA.
    :return: Un diccionario con la clave privada cifrada y el certificado raíz.
    """
    # Crear una nueva clave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generar un certificado X.509 para la CA
    subject = issuer = Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiAplicacion"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MiAplicacion CA"),
    ])
    certificate = CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650)) \
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True) \
        .sign(private_key, SHA256())

    # Serializar la clave privada en formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # Serializar el certificado en formato PEM
    cert_pem = certificate.public_bytes(Encoding.PEM)

    # Generar una clave de cifrado para la clave privada
    salt = encryption.os.urandom(16)
    clave_cifrado = encryption.derivar_clave_cifrado(master_password, salt)

    # Cifrar la clave privada
    private_key_cifrada = encryption.cifrar_aes_gcm(private_key_pem, clave_cifrado)

    return {
        'private_key': {
            'cifrado': private_key_cifrada['cifrado'],
            'nonce': private_key_cifrada['nonce'],
            'tag': private_key_cifrada['tag'],
            'salt': salt
        },
        'certificado': cert_pem
    }


def emitir_certificado(user_public_key_pem, ca_private_key_data, ca_cert_pem, admin_password):
    """
    Emite un certificado para un usuario usando la clave pública del usuario, la clave privada de la CA y su certificado.

    :param user_public_key_pem: Clave pública del usuario en formato PEM.
    :param ca_private_key_data: Clave privada de la CA cifrada (diccionario con cifrado, nonce, tag, y salt).
    :param ca_cert_pem: Certificado de la CA en formato PEM.
    :param admin_password: Contraseña maestra para descifrar la clave privada de la CA.
    :return: Certificado del usuario en formato PEM.
    """
    try:
        # Verificar los tipos de datos y descifrar la clave privada de la CA
        if isinstance(ca_private_key_data, dict):
            print("DEBUG: Descifrando la clave privada de la CA...")
            clave_cifrado = encryption.derivar_clave_cifrado(admin_password, ca_private_key_data['salt'])
            descifrado = encryption.descifrar_aes_gcm(
                ca_private_key_data['cifrado'],
                clave_cifrado,
                ca_private_key_data['nonce'],
                ca_private_key_data['tag']
            )

            # Convertir el resultado a bytes si es necesario
            if isinstance(descifrado, str):
                ca_private_key_pem = descifrado.encode('utf-8')
            else:
                ca_private_key_pem = descifrado
        else:
            raise ValueError("La clave privada de la CA debe ser un diccionario con los datos cifrados.")

        # Asegurar que el certificado CA esté en formato bytes
        if isinstance(ca_cert_pem, str):
            ca_cert_pem = ca_cert_pem.encode('utf-8')

        # Cargar la clave pública del usuario
        print("DEBUG: Cargando la clave pública del usuario...")
        user_public_key = serialization.load_pem_public_key(user_public_key_pem)

        # Cargar la clave privada descifrada de la CA
        print("DEBUG: Cargando la clave privada de la CA...")
        ca_private_key = load_pem_private_key(
            ca_private_key_pem,
            password=None  # Ya está descifrada, no necesita contraseña
        )

        # Cargar el certificado de la CA
        print("DEBUG: Cargando el certificado de la CA...")
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        # Construir el sujeto del certificado del usuario
        print("DEBUG: Construyendo el sujeto del certificado...")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MiAplicacion"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Usuario MiAplicacion"),
        ])

        # El emisor del certificado es la CA
        print("DEBUG: Construyendo el emisor del certificado...")
        issuer = ca_cert.subject

        # Construir y firmar el certificado
        print("DEBUG: Creando el certificado...")
        certificado = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(user_public_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"example.com")]),
                critical=False
            ) \
            .sign(private_key=ca_private_key, algorithm=hashes.SHA256())

        # Serializar el certificado en formato PEM
        print("DEBUG: Serializando el certificado en formato PEM...")
        return certificado.public_bytes(serialization.Encoding.PEM)

    except Exception as e:
        print("DEBUG: Error en emitir_certificado -", str(e))
        raise ValueError(f"Error al emitir el certificado: {e}")



def validar_certificado(user_cert_pem, ca_cert_pem):
    """
    Valida que un certificado de usuario fue emitido por la CA.

    :param user_cert_pem: Certificado del usuario en formato PEM.
    :param ca_cert_pem: Certificado raíz de la CA en formato PEM.
    :return: True si el certificado es válido, False en caso contrario.
    """
    try:
        # Validar entradas
        if not user_cert_pem or not ca_cert_pem:
            raise ValueError("Certificados proporcionados están vacíos o no son válidos.")

        # Cargar certificados
        user_cert = load_pem_x509_certificate(user_cert_pem)
        ca_cert = load_pem_x509_certificate(ca_cert_pem)

        # Verificar la firma
        ca_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            PKCS1v15(),
            user_cert.signature_hash_algorithm
        )
        print(f"DEBUG: Certificado válido. Algoritmo de firma: {user_cert.signature_hash_algorithm}")
        return True
    except ValueError as ve:
        print(f"DEBUG: Error de entrada - {ve}")
        return False
    except Exception as e:
        print(f"DEBUG: Error al validar certificado - {e}")
        return False



def pedir_contraseña_admin():
    """
    Solicita al administrador la contraseña para acceder a la CA.
    :return: La contraseña ingresada.
    """
    from tkinter.simpledialog import askstring
    master_password = askstring("Contraseña de Administrador", "Introduce la contraseña maestra de la CA:", show='*')
    if not master_password:
        raise ValueError("La contraseña de administrador es obligatoria.")
    return master_password
