# Sistema de Login Seguro

Este es un sistema de login seguro desarrollado en PHP con características avanzadas de seguridad y gestión de usuarios.

## Características

- Inicio de sesión seguro con protección contra ataques de fuerza bruta
- Panel de administración de usuarios (solo para usuario root)
- Gestión de cuentas de usuario
- Recuperación de contraseña
- Búsqueda avanzada de usuarios
- Protección CSRF
- Sanitización de entradas
- Sesiones seguras

## Requisitos

- PHP 7.4 o superior
- MySQL/MariaDB
- Servidor web (Apache/Nginx)
- Extensiones PHP requeridas:
  - PDO
  - PDO_MySQL
  - session

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/Javier-osw/sistema-login-seguro.git
   ```

2. Importar la base de datos:
   - Crear una base de datos llamada `proy_cursor`
   - Importar el archivo `database.sql`

3. Configurar la conexión:
   - Editar el archivo `config.php` con los datos de tu base de datos

4. Crear usuario root:
   - Ejecutar el script `crear_root.php`
   - Credenciales por defecto:
     - Usuario: root
     - Contraseña: root123

## Estructura del Proyecto

- `index.php` - Página de inicio de sesión
- `principal.php` - Página principal después del login
- `admin_usuarios.php` - Panel de administración de usuarios
- `mi_cuenta.php` - Gestión de cuenta de usuario
- `config.php` - Configuración y funciones de seguridad
- `plantilla_busqueda.php` - Sistema de búsqueda
- `reset_password.php` - Recuperación de contraseña

## Seguridad

El sistema implementa múltiples capas de seguridad:
- Protección contra inyección SQL usando PDO
- Hashing seguro de contraseñas
- Protección contra CSRF
- Límite de intentos de login
- Headers de seguridad
- Sanitización de entradas
- Manejo seguro de sesiones

## Autor

Desarrollado por [Tu Nombre]

## Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles. 