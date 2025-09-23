# Criptograf-a
En este repositorio se encontrará todo el material utilizado para la implementación del GESTOR DE CONTRASEÑAS con cifrado RSA/AES y certificados digitales


# 🔐 Proyecto de Criptografía

Este proyecto fue desarrollado en la asignatura de **Criptografía** como parte del Grado en Ingeniería Informática en la UC3M.  
El objetivo era implementar una aplicación en **Python** que gestionara usuarios y sus credenciales de forma segura, incorporando:

- Cifrado simétrico y asimétrico
- Hash de contraseñas con `salt`
- Firmas digitales
- Validación y gestión de certificados
- Recuperación de contraseñas
- Validación de datos de usuario
- Interfaz gráfica básica para la interacción

---

## 📂 Contenido principal

- **`app.py`**  
  Script principal de la aplicación. Construye la interfaz, inicializa la ventana y conecta con las funciones de gestión de usuarios, cifrado y validación.

- **`certificate_management.py`**  
  Generación y gestión de certificados digitales (CA) y claves privadas, asegurando su cifrado con contraseña maestra.

- **`data_validation.py`**  
  Validación de nombres de usuario, contraseñas y correos para cumplir criterios de formato y seguridad.

- **`digital_signature.py`**  
  Implementación de creación y verificación de **firmas digitales** sobre datos serializables en JSON.

- **`encryption.py`**  
  Funciones de cifrado y descifrado. Uso de **PBKDF2-HMAC-SHA256** para derivación de claves y cifrado seguro.

- **`exceptions.py`**  
  Definición de excepciones personalizadas para manejo de errores de validación y de seguridad.

- **`json_management.py`**  
  Lectura y escritura segura de la base de datos de usuarios (`usuarios.json`).

- **`password_hashing.py`**  
  Hash de contraseñas con generación de `salt` aleatorio para evitar ataques de rainbow tables.

- **`password_restoration.py`**  
  Lógica de restauración de contraseñas y envío de correos de aviso al usuario.

- **`profile_management.py`**  
  Consulta y actualización de datos de perfil de usuario (correo, teléfono, etc.), aplicando descifrado cuando corresponde.

- **`register_login.py`**  
  Registro de nuevos usuarios, validación de credenciales y control de login.

- **`usuarios.json`**  
  Base de datos de usuarios en formato JSON (simulada para la práctica). Contiene información encriptada/hasheada.

- **`ca_cert.pem`** / **`ca_key.json`**  
  Certificado raíz de la CA y clave privada asociada (cifrados).

- **`instrucciones.txt`**  
  Guía rápida de ejecución: se indica iniciar con `app.py` y tener instalado el paquete `cryptography`.

- **Memoria en PDF (`100495692_100495884.pdf`)**  
  Documento de memoria explicativa de la práctica.

- **`autores.txt`**  
  Integrantes del proyecto.

---

## ▶️ Ejecución

```bash
# Requisitos
Python 3.9+
pip install cryptography

# Lanzar la aplicación
python app.py
