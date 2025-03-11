<?php
session_start();
require_once 'config.php';

// Inicializar variables
$error = '';
$mensaje = '';
$token_valido = false;
$token = '';

// Verificar si se proporcionó un token
if (isset($_GET['token'])) {
    $token = $_GET['token'];
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("SELECT id, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        
        if ($user) {
            $token_valido = true;
        } else {
            $error = "El enlace de recuperación ha expirado o no es válido";
        }
    } catch(PDOException $e) {
        $error = "Error al verificar el token: " . $e->getMessage();
    }
} else {
    $error = "No se proporcionó un token válido";
}

// Procesar el formulario de cambio de contraseña
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['nueva_password'])) {
    $password = $_POST['nueva_password'];
    $confirm_password = $_POST['confirmar_password'];
    
    // Validar contraseña
    if (strlen($password) < 8) {
        $error = "La contraseña debe tener al menos 8 caracteres";
    } else if (!preg_match("/[A-Z]/", $password)) {
        $error = "La contraseña debe contener al menos una mayúscula";
    } else if (!preg_match("/[a-z]/", $password)) {
        $error = "La contraseña debe contener al menos una minúscula";
    } else if (!preg_match("/[0-9]/", $password)) {
        $error = "La contraseña debe contener al menos un número";
    } else if ($password !== $confirm_password) {
        $error = "Las contraseñas no coinciden";
    } else {
        try {
            $pdo = getDBConnection();
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Actualizar contraseña y limpiar token
            $stmt = $pdo->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = ?");
            $stmt->execute([$hashedPassword, $token]);
            
            if ($stmt->rowCount() > 0) {
                $mensaje = "Tu contraseña ha sido actualizada exitosamente. Ya puedes <a href='index.php'>iniciar sesión</a>";
                $token_valido = false; // Ocultar el formulario
            } else {
                $error = "Error al actualizar la contraseña";
            }
        } catch(PDOException $e) {
            $error = "Error al actualizar la contraseña: " . $e->getMessage();
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Restablecer Contraseña</title>
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
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-body">
                        <h2 class="text-center mb-4">Restablecer Contraseña</h2>
                        
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>
                        
                        <?php if ($mensaje): ?>
                            <div class="alert alert-success"><?php echo $mensaje; ?></div>
                        <?php endif; ?>

                        <?php if ($token_valido): ?>
                            <form method="POST" action="">
                                <div class="mb-3">
                                    <label for="nueva_password" class="form-label">Nueva Contraseña</label>
                                    <div class="password-container">
                                        <input type="password" class="form-control" id="nueva_password" name="nueva_password" required>
                                        <button type="button" class="generate-password" onclick="generatePassword('nueva_password')" title="Generar contraseña segura">
                                            <i class="bi bi-magic"></i>
                                        </button>
                                        <button type="button" class="toggle-password" onclick="togglePassword('nueva_password')">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                    </div>
                                    <small class="form-text text-muted">
                                        Mínimo 8 caracteres, una mayúscula, una minúscula y un número
                                    </small>
                                </div>
                                <div class="mb-3">
                                    <label for="confirmar_password" class="form-label">Confirmar Contraseña</label>
                                    <div class="password-container">
                                        <input type="password" class="form-control" id="confirmar_password" name="confirmar_password" required>
                                        <button type="button" class="toggle-password" onclick="togglePassword('confirmar_password')">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="d-grid">
                                    <button type="submit" class="btn btn-primary">Cambiar Contraseña</button>
                                </div>
                            </form>
                        <?php else: ?>
                            <?php if (!$mensaje): ?>
                                <div class="text-center">
                                    <p>El enlace de recuperación no es válido o ha expirado.</p>
                                    <a href="index.php" class="btn btn-primary">Volver al Inicio</a>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
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
                if (Math.random() < 0.7 && sustituciones[letra]) {
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
            const button = input.nextElementSibling;
            if (inputId === 'nueva_password') {
                button = input.nextElementSibling.nextElementSibling;
            }
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