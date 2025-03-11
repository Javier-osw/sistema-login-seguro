<?php
session_start();
require_once 'config.php';

// Verificar si el usuario está logueado y es root
if (!isLoggedIn() || $_SESSION['username'] !== 'root') {
    header("Location: index.php");
    exit();
}

$mensaje = '';
$error = '';

// Procesar formularios
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $pdo = getDBConnection();
    
    // Crear nuevo usuario
    if (isset($_POST['crear'])) {
        $username = sanitizeInput($_POST['new_username']);
        $email = sanitizeInput($_POST['new_email']);
        $password = $_POST['new_password'];
        
        // Validar contraseña
        if (strlen($password) < 8) {
            $error = "La contraseña debe tener al menos 8 caracteres";
        } else if (!preg_match("/[A-Z]/", $password)) {
            $error = "La contraseña debe contener al menos una mayúscula";
        } else if (!preg_match("/[a-z]/", $password)) {
            $error = "La contraseña debe contener al menos una minúscula";
        } else if (!preg_match("/[0-9]/", $password)) {
            $error = "La contraseña debe contener al menos un número";
        } else {
            try {
                // Verificar si el usuario ya existe
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
                $stmt->execute([$username, $email]);
                if ($stmt->fetch()) {
                    $error = "El usuario o email ya existe";
                } else {
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
                    $stmt->execute([$username, $hashedPassword, $email]);
                    $mensaje = "Usuario creado exitosamente";
                }
            } catch(PDOException $e) {
                $error = "Error al crear usuario: " . $e->getMessage();
            }
        }
    }
    
    // Eliminar usuario
    if (isset($_POST['eliminar'])) {
        $id = filter_var($_POST['user_id'], FILTER_VALIDATE_INT);
        if ($id) {
            try {
                // No permitir eliminar al usuario root
                $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                $stmt->execute([$id]);
                $user = $stmt->fetch();
                
                if ($user['username'] === 'root') {
                    $error = "No se puede eliminar al usuario root";
                } else {
                    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
                    $stmt->execute([$id]);
                    $mensaje = "Usuario eliminado exitosamente";
                }
            } catch(PDOException $e) {
                $error = "Error al eliminar usuario: " . $e->getMessage();
            }
        }
    }
    
    // Cambiar contraseña
    if (isset($_POST['cambiar_password'])) {
        $id = filter_var($_POST['user_id'], FILTER_VALIDATE_INT);
        $newPassword = $_POST['new_password'];
        
        // Validar contraseña
        if (strlen($newPassword) < 8) {
            $error = "La contraseña debe tener al menos 8 caracteres";
        } else if (!preg_match("/[A-Z]/", $newPassword)) {
            $error = "La contraseña debe contener al menos una mayúscula";
        } else if (!preg_match("/[a-z]/", $newPassword)) {
            $error = "La contraseña debe contener al menos una minúscula";
        } else if (!preg_match("/[0-9]/", $newPassword)) {
            $error = "La contraseña debe contener al menos un número";
        } else {
            try {
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                $stmt->execute([$hashedPassword, $id]);
                $mensaje = "Contraseña actualizada exitosamente";
            } catch(PDOException $e) {
                $error = "Error al actualizar contraseña: " . $e->getMessage();
            }
        }
    }
}

// Obtener lista de usuarios
try {
    $pdo = getDBConnection();
    $stmt = $pdo->query("SELECT id, username, email, created_at, last_login FROM users ORDER BY id");
    $usuarios = $stmt->fetchAll();
} catch(PDOException $e) {
    $error = "Error al obtener usuarios: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administración de Usuarios</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .password-container {
            position: relative;
        }
        .toggle-password {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6c757d;
            background: none;
            border: none;
            padding: 0;
        }
        .toggle-password:hover {
            color: #0d6efd;
        }
        .generate-password {
            position: absolute;
            right: 40px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6c757d;
            background: none;
            border: none;
            padding: 0;
        }
        .generate-password:hover {
            color: #0d6efd;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="#">Panel de Administración</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="principal.php">Volver al Inicio</a>
                <a class="nav-link" href="logout.php">Cerrar Sesión</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if ($mensaje): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($mensaje); ?></div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <!-- Crear nuevo usuario -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">Crear Nuevo Usuario</h5>
            </div>
            <div class="card-body">
                <form method="POST" class="row g-3">
                    <div class="col-md-4">
                        <label for="new_username" class="form-label">Usuario</label>
                        <input type="text" class="form-control" id="new_username" name="new_username" required>
                    </div>
                    <div class="col-md-4">
                        <label for="new_email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="new_email" name="new_email" required>
                    </div>
                    <div class="col-md-4">
                        <label for="new_password" class="form-label">Contraseña</label>
                        <div class="password-container">
                            <input type="password" class="form-control" id="new_password" name="new_password" required>
                            <button type="button" class="generate-password" onclick="generatePassword('new_password')" title="Generar contraseña segura">
                                <i class="bi bi-magic"></i>
                            </button>
                            <button type="button" class="toggle-password" onclick="togglePassword('new_password')">
                                <i class="bi bi-eye"></i>
                            </button>
                        </div>
                        <small class="form-text text-muted">
                            Mínimo 8 caracteres, una mayúscula, una minúscula y un número
                        </small>
                    </div>
                    <div class="col-12">
                        <button type="submit" name="crear" class="btn btn-primary">Crear Usuario</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Lista de usuarios -->
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Usuarios del Sistema</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Usuario</th>
                                <th>Email</th>
                                <th>Fecha Creación</th>
                                <th>Último Login</th>
                                <th>Acciones</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($usuarios as $usuario): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($usuario['id']); ?></td>
                                <td><?php echo htmlspecialchars($usuario['username']); ?></td>
                                <td><?php echo htmlspecialchars($usuario['email']); ?></td>
                                <td><?php echo htmlspecialchars($usuario['created_at']); ?></td>
                                <td><?php echo $usuario['last_login'] ? htmlspecialchars($usuario['last_login']) : 'Nunca'; ?></td>
                                <td>
                                    <!-- Botón cambiar contraseña -->
                                    <button type="button" class="btn btn-warning btn-sm" data-bs-toggle="modal" 
                                            data-bs-target="#cambiarPassword<?php echo $usuario['id']; ?>">
                                        <i class="bi bi-key"></i>
                                    </button>
                                    
                                    <!-- Botón eliminar (deshabilitado para root) -->
                                    <?php if ($usuario['username'] !== 'root'): ?>
                                    <form method="POST" class="d-inline" onsubmit="return confirm('¿Estás seguro de eliminar este usuario?');">
                                        <input type="hidden" name="user_id" value="<?php echo $usuario['id']; ?>">
                                        <button type="submit" name="eliminar" class="btn btn-danger btn-sm">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            
                            <!-- Modal Cambiar Contraseña -->
                            <div class="modal fade" id="cambiarPassword<?php echo $usuario['id']; ?>" tabindex="-1">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Cambiar Contraseña - <?php echo htmlspecialchars($usuario['username']); ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                        </div>
                                        <form method="POST">
                                            <div class="modal-body">
                                                <input type="hidden" name="user_id" value="<?php echo $usuario['id']; ?>">
                                                <div class="mb-3">
                                                    <label for="new_password<?php echo $usuario['id']; ?>" class="form-label">Nueva Contraseña</label>
                                                    <div class="password-container">
                                                        <input type="password" class="form-control" id="new_password<?php echo $usuario['id']; ?>" 
                                                               name="new_password" required>
                                                        <button type="button" class="generate-password" onclick="generatePassword('new_password<?php echo $usuario['id']; ?>')" title="Generar contraseña segura">
                                                            <i class="bi bi-magic"></i>
                                                        </button>
                                                        <button type="button" class="toggle-password" onclick="togglePassword('new_password<?php echo $usuario['id']; ?>')">
                                                            <i class="bi bi-eye"></i>
                                                        </button>
                                                    </div>
                                                    <small class="form-text text-muted">
                                                        Mínimo 8 caracteres, una mayúscula, una minúscula y un número
                                                    </small>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                                                <button type="submit" name="cambiar_password" class="btn btn-primary">Guardar Cambios</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Diccionario de palabras comunes en español
        const palabras = [
            'gato', 'perro', 'casa', 'luna', 'sol', 'mar', 'cielo', 'tierra', 
            'fuego', 'agua', 'aire', 'luz', 'noche', 'dia', 'amor', 'vida',
            'paz', 'rey', 'flor', 'arbol', 'rio', 'monte', 'lago', 'bosque',
            'playa', 'viento', 'lluvia', 'nube', 'rayo', 'estrella', 'dragon'
        ];

        // Diccionario de sustituciones haxor
        const sustituciones = {
            'a': '4',
            'e': '3',
            'i': '1',
            'o': '0',
            's': '5',
            't': '7',
            'b': '8',
            'g': '9',
            'z': '2'
        };

        function generarPalabraHaxor(palabra) {
            let resultado = '';
            for (let letra of palabra) {
                if (Math.random() < 0.7 && sustituciones[letra]) { // 70% de probabilidad de sustituir
                    resultado += sustituciones[letra];
                } else {
                    resultado += letra;
                }
            }
            return resultado;
        }

        function generatePassword(inputId) {
            // Seleccionar dos palabras aleatorias
            const palabra1 = palabras[Math.floor(Math.random() * palabras.length)];
            const palabra2 = palabras[Math.floor(Math.random() * palabras.length)];
            
            // Convertir a haxor
            const haxor1 = generarPalabraHaxor(palabra1);
            const haxor2 = generarPalabraHaxor(palabra2);
            
            // Agregar números aleatorios
            const numeros = Math.floor(Math.random() * 100);
            
            // Asegurar que haya al menos una mayúscula
            const password = haxor1.charAt(0).toUpperCase() + haxor1.slice(1) + 
                           haxor2 + numeros;
            
            // Asignar la contraseña al input
            const input = document.getElementById(inputId);
            input.value = password;
            input.type = 'text';
            
            // Actualizar el icono del ojo
            const toggleButton = input.nextElementSibling.nextElementSibling;
            const icon = toggleButton.querySelector('i');
            icon.classList.remove('bi-eye');
            icon.classList.add('bi-eye-slash');
            
            // Mostrar la contraseña por 3 segundos y luego ocultarla
            setTimeout(() => {
                input.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }, 3000);
        }

        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling.nextElementSibling;
            const icon = button.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
            }
        }
    </script>
</body>
</html> 