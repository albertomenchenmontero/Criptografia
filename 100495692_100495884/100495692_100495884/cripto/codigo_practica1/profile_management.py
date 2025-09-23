import base64
import json_management
import encryption
from exceptions import ValidationError
from digital_signature import generar_firma_digital, verificar_firma_digital
import certificate_management


# =====================
# FUNCIONES DE PERFIL DE USUARIO
# =====================

def consultar_usuario(nombre_usuario, clave):
    """
    Consulta la información de un usuario, descifrando su correo electrónico y número de teléfono.

    - Recupera los datos del usuario a partir del nombre proporcionado.
    - Verifica si el usuario existe; si no, lanza una excepción.
    - Descifra el correo electrónico y el número de teléfono del usuario utilizando claves derivadas.

    Devuelve un diccionario con el nombre de usuario, email descifrado y teléfono descifrado.
    """
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]

    # Derivar la clave para descifrar el email
    clave_email = encryption.derivar_clave_cifrado(nombre_usuario)
    email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
    email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
    email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])
    email = encryption.descifrar_aes_gcm(email_cifrado, clave_email, email_nonce, email_tag)

    # Descifrar el número de teléfono usando la clave proporcionada
    telefono_cifrado = base64.urlsafe_b64decode(user_data['telefono']['cifrado'])
    telefono_nonce = base64.urlsafe_b64decode(user_data['telefono']['nonce'])
    telefono_tag = base64.urlsafe_b64decode(user_data['telefono']['tag'])
    telefono = encryption.descifrar_aes_gcm(telefono_cifrado, clave, telefono_nonce, telefono_tag)

    return {
        'nombre_usuario': nombre_usuario,
        'email': email,
        'telefono': telefono
    }


def guardar_contraseña(nombre_usuario, asunto, contraseña, clave_sesion, private_key_pem):
    """
    Guarda una nueva contraseña asociada a un usuario.
    Cifra la contraseña y genera una firma digital para garantizar su autenticidad.
    """
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios:
        raise ValidationError("Usuario no encontrado.")

    user_data = usuarios[nombre_usuario]

    # Cifrar la contraseña
    contraseña_cifrada = encryption.cifrar_aes_gcm(contraseña, clave_sesion)

    # Generar la firma digital para esta contraseña
    datos_a_firmar = {
        "asunto": asunto,
        "contraseña": base64.urlsafe_b64encode(contraseña_cifrada['cifrado']).decode('utf-8')
    }
    firma = generar_firma_digital(datos_a_firmar, private_key_pem)

    # Inicializar la lista de contraseñas si no existe
    if 'contraseñas' not in user_data:
        user_data['contraseñas'] = []

    # Guardar la contraseña cifrada con su firma
    user_data['contraseñas'].append({
        'asunto': asunto,
        'contraseña': base64.urlsafe_b64encode(contraseña_cifrada['cifrado']).decode('utf-8'),
        'nonce': base64.urlsafe_b64encode(contraseña_cifrada['nonce']).decode('utf-8'),
        'tag': base64.urlsafe_b64encode(contraseña_cifrada['tag']).decode('utf-8'),
        'firma': firma  # Guardar la firma
    })

    # Guardar los datos actualizados
    json_management.guardar_usuarios(usuarios)


def obtener_contraseñas(nombre_usuario, clave, public_key_pem, ca_cert_pem):
    """
    Recupera y descifra todas las contraseñas asociadas a un usuario, verificando sus firmas digitales.
    """
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        return []

    # Asegurar que public_key_pem está en bytes
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode()

    user_data = usuarios[nombre_usuario]
    user_cert_pem = base64.urlsafe_b64decode(user_data.get('certificado', ''))

    # Validar el certificado del usuario
    #if not validar_certificado(user_cert_pem, ca_cert_pem):
    #    raise ValidationError("Tu certificado no es válido o no ha sido emitido por la CA.")

    contraseñas_descifradas = []

    # Iterar sobre cada contraseña almacenada
    for item in user_data['contraseñas']:
        datos_a_verificar = {
            "asunto": item['asunto'],
            "contraseña": item['contraseña']
        }

        # Verificar la firma
        if not verificar_firma_digital(datos_a_verificar, item['firma'], public_key_pem):
            raise ValidationError(f"La firma de la contraseña con asunto '{item['asunto']}' no es válida.")

        # Descifrar la contraseña
        contraseña_cifrada = base64.urlsafe_b64decode(item['contraseña'])
        nonce = base64.urlsafe_b64decode(item['nonce'])
        tag = base64.urlsafe_b64decode(item['tag'])
        contraseña = encryption.descifrar_aes_gcm(contraseña_cifrada, clave, nonce, tag)

        contraseñas_descifradas.append({
            'asunto': item['asunto'],
            'contraseña': contraseña
        })

    return contraseñas_descifradas




def eliminar_contraseña(nombre_usuario, asunto):
    """
    Elimina una contraseña específica asociada a un usuario.

    - Verifica si el usuario tiene contraseñas almacenadas.
    - Filtra la lista de contraseñas, eliminando aquella que coincide con el asunto proporcionado.
    - Guarda los cambios en el archivo JSON.
    """
    usuarios = json_management.cargar_usuarios()
    if nombre_usuario not in usuarios or 'contraseñas' not in usuarios[nombre_usuario]:
        raise ValidationError("Usuario o contraseñas no encontrados.")

    # Filtrar y eliminar la contraseña con el asunto proporcionado
    contraseñas = usuarios[nombre_usuario]['contraseñas']
    usuarios[nombre_usuario]['contraseñas'] = [c for c in contraseñas if c['asunto'] != asunto]

    json_management.guardar_usuarios(usuarios)
