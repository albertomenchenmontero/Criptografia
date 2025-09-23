import re
from exceptions import ValidationError


# =====================
# FUNCIONES DE VALIDACIÓN DE DATOS
# =====================

def validar_nombre_usuario(nombre_usuario):
    """
    Valida el nombre de usuario para asegurarse de que cumple con los siguientes requisitos:

    - No debe contener caracteres especiales.
    - Debe tener entre 5 y 15 caracteres.

    Si no cumple con alguno de estos criterios, lanza una excepción de ValidationError.
    """
    if re.search(r"[\W]", nombre_usuario):
        raise ValidationError("El nombre de usuario no debe contener caracteres especiales.")
    if len(nombre_usuario) > 15:
        raise ValidationError("El nombre de usuario no debe tener más de 15 caracteres.")
    if len(nombre_usuario) < 5:
        raise ValidationError("El nombre de usuario no debe tener menos de 5 caracteres.")
    return True


def validar_contraseña(password):
    """
    Valida la contraseña para asegurarse de que cumple con los siguientes requisitos:

    - Debe tener entre 8 y 30 caracteres.
    - Debe contener al menos una letra, un número y un carácter especial.

    Si la contraseña no cumple con alguno de estos criterios, lanza una excepción de ValidationError.
    """
    if len(password) < 8:
        raise ValidationError("La contraseña debe tener al menos 8 caracteres.")
    if len(password) > 30:
        raise ValidationError("La contraseña no debe tener más de 30 caracteres.")
    if not re.search(r"^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[\W]).{8,30}$", password):
        raise ValidationError("La contraseña debe contener al menos una letra, un número y un carácter especial.")
    return True


def validar_email(email):
    """
    Valida que el correo electrónico pertenezca al dominio de Gmail (.com o .es) y tenga un formato correcto.

    Utiliza una expresión regular para comprobar que el correo electrónico es válido y pertenece al dominio requerido.
    Si no es válido, lanza una excepción de ValidationError.
    """
    patron = r'^[a-zA-Z0-9._%+-]+@gmail\.(com|es)$'
    if not bool(re.fullmatch(patron, email)):
        raise ValidationError(
            "El correo electrónico debe tener una forma válida y pertenecer al dominio de Gmail (.com o .es).")
    return True


def validar_telefono(telefono):
    """
    Valida que el número de teléfono sea válido bajo los siguientes criterios:

    - Debe tener 9 dígitos.
    - Debe comenzar con un 6 o 7.

    Si no cumple con estos criterios, lanza una excepción de ValidationError.
    """
    patron = r'^[6-7]\d{8}$'
    if not bool(re.fullmatch(patron, telefono)):
        raise ValidationError("El número de teléfono debe tener 9 dígitos y comenzar con 6 o 7.")
    return True
