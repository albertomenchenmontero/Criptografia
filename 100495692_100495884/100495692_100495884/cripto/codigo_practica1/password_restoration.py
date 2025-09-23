import base64
import random
import smtplib
import json_management
import encryption
from exceptions import ValidationError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# =====================
# FUNCIONES DE RESTAURACIÓN DE CONTRASEÑA
# =====================

def enviar_correo_aviso_cambio_contraseña(nombre_usuario, clave):
    """
    Envía un correo electrónico de aviso cuando se realiza un cambio de contraseña.

    - Recupera la información del usuario a partir de su nombre.
    - Descifra el correo electrónico almacenado en la base de datos utilizando la clave proporcionada.
    - Envía un correo utilizando un servidor SMTP de Gmail.
    - Si ocurre algún error durante el proceso de envío, lanza una excepción de ValidationError.

    Parámetros:
    - nombre_usuario: El nombre del usuario al que se le enviará el correo.
    - clave: La clave utilizada para descifrar el correo electrónico almacenado.
    """

    # Cargar la lista de usuarios y obtener los datos del usuario actual
    usuarios = json_management.cargar_usuarios()
    user_data = usuarios[nombre_usuario]

    # Descifrar el correo electrónico del usuario almacenado en la base de datos
    email_cifrado = base64.urlsafe_b64decode(user_data['email']['cifrado'])
    email_nonce = base64.urlsafe_b64decode(user_data['email']['nonce'])
    email_tag = base64.urlsafe_b64decode(user_data['email']['tag'])
    email = encryption.descifrar_aes_gcm(email_cifrado, clave, email_nonce, email_tag)

    # Configuración del servidor de correo
    servidor_correo = "smtp.gmail.com"
    puerto = 587
    correo_envio = "100495692@alumnos.uc3m.es"
    contraseña_correo = "miep iewr zlmc ycfp"

    # Crear el mensaje del correo
    mensaje = MIMEMultipart()
    mensaje['From'] = correo_envio
    mensaje['To'] = email
    mensaje['Subject'] = "Cambio de contraseña"
    cuerpo_mensaje = (
        f"Hola {nombre_usuario},\n\n"
        "Tu contraseña ha sido cambiada exitosamente. "
        "Si no has sido tú, por favor contacta con el personal de mantenimiento escribiendo a este mismo email."
    )
    mensaje.attach(MIMEText(cuerpo_mensaje, 'plain'))

    # Enviar el correo utilizando el servidor SMTP
    try:
        servidor = smtplib.SMTP(servidor_correo, puerto)
        servidor.starttls()  # Iniciar la conexión segura con TLS
        servidor.login(correo_envio, contraseña_correo)  # Iniciar sesión en la cuenta de correo
        servidor.send_message(mensaje)  # Enviar el mensaje
        servidor.quit()  # Cerrar la conexión con el servidor
    except smtplib.SMTPException as e:
        raise ValidationError(f"Error al enviar el correo electrónico: {e}")
