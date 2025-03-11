<?php
require_once 'config.php';
require_once 'mail_config.php';

// Iniciar sesión con configuración segura
initSession();

// Configurar headers de seguridad
setSecurityHeaders();

// Inicializar variables
$error = '';
$mensaje = '';

// Procesar formulario de recuperación de contraseña
if (isset($_POST['recuperar_password'])) {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error = "Error de validación del formulario";
    } else {
        $email = sanitizeInput($_POST['email_recuperacion']);
        
        try {
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("SELECT id, username FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if ($user) {
                // Generar token único
                $token = bin2hex(random_bytes(32));
                $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));
                
                // Guardar token en la base de datos
                $stmt = $pdo->prepare("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
                $stmt->execute([$token, $expiry, $user['id']]);
                
                // Crear el enlace de recuperación
                $resetLink = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/reset_password.php?token=" . $token;
                
                // Preparar el mensaje del correo
                $mensajeCorreo = "
                    <html>
                    <head>
                        <title>Recuperación de Contraseña</title>
                    </head>
                    <body>
                        <h2>Recuperación de Contraseña</h2>
                        <p>Hola {$user['username']},</p>
                        <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
                        <p><a href='{$resetLink}'>{$resetLink}</a></p>
                        <p>Este enlace expirará en 1 hora.</p>
                        <p>Si no solicitaste este cambio, por favor ignora este correo.</p>
                        <p>Saludos,<br>Sistema de Login</p>
                    </body>
                    </html>
                ";
                
                // Por ahora, mostrar el link (en producción, enviar por correo)
                $mensaje = "Se ha enviado un enlace de recuperación a tu correo electrónico. " .
                          "<br><small>Link temporal: <a href='$resetLink'>$resetLink</a></small>";
            } else {
                $error = "No se encontró ninguna cuenta con ese correo electrónico";
            }
        } catch(Exception $e) {
            error_log("Error en recuperación de contraseña: " . $e->getMessage());
            $error = "Error al procesar la solicitud";
        }
    }
}

// Procesar el formulario de login
if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['recuperar_password'])) {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        $error = "Error de validación del formulario";
    } else {
        if (isset($_POST['username']) && isset($_POST['password'])) {
            $userOrEmail = sanitizeInput($_POST['username']);
            $password = $_POST['password'];
            
            if (!empty($userOrEmail) && !empty($password)) {
                try {
                    // Verificar intentos de login
                    checkLoginAttempts($userOrEmail);
                    
                    $pdo = getDBConnection();
                    $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ? OR email = ?");
                    $stmt->execute([$userOrEmail, $userOrEmail]);
                    $user = $stmt->fetch();
                    
                    if ($user && password_verify($password, $user['password'])) {
                        // Login exitoso
                        session_regenerate_id(true);
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['last_activity'] = time();
                        
                        // Reiniciar intentos de login
                        resetLoginAttempts($userOrEmail);
                        
                        // Actualizar último login
                        $stmt = $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
                        $stmt->execute([$user['id']]);
                        
                        header("Location: principal.php");
                        exit();
                    } else {
                        // Login fallido
                        incrementLoginAttempts($userOrEmail);
                        $error = "Credenciales incorrectas";
                    }
                } catch(Exception $e) {
                    $error = $e->getMessage();
                }
            } else {
                $error = "Por favor, complete todos los campos";
            }
        }
    }
}

// Generar nuevo token CSRF
$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6 col-lg-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h2 class="text-center mb-4">Iniciar Sesión</h2>
                        
                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>

                        <?php if ($mensaje): ?>
                            <div class="alert alert-success"><?php echo $mensaje; ?></div>
                        <?php endif; ?>

                        <form method="POST" action="">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <div class="mb-3">
                                <label for="username" class="form-label">Usuario o Correo Electrónico</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Contraseña</label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="password" name="password" required>
                                    <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('password')">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
                            </div>
                        </form>

                        <div class="text-center mt-3">
                            <a href="#" data-bs-toggle="modal" data-bs-target="#recuperarPasswordModal">
                                ¿Olvidaste tu contraseña?
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal Recuperar Contraseña -->
    <div class="modal fade" id="recuperarPasswordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Recuperar Contraseña</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="mb-3">
                            <label for="email_recuperacion" class="form-label">Correo Electrónico</label>
                            <input type="email" class="form-control" id="email_recuperacion" name="email_recuperacion" required>
                        </div>
                        <div class="d-grid">
                            <button type="submit" name="recuperar_password" class="btn btn-primary">
                                Enviar Link de Recuperación
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
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