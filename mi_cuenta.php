<?php
session_start();
require_once 'config.php';
require_once 'funciones.php';

// Verificar si el usuario está logueado
requireLogin();

$username = $_SESSION['username'];
$isRoot = ($username === 'root');

// Inicializar variables
$mensaje = '';
$error = '';
$usuario = null;

try {
    $pdo = getDBConnection();
    
    // Obtener datos del usuario
    $stmt = $pdo->prepare("SELECT id, username, email, last_login FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $usuario = $stmt->fetch();
    
    // Procesar actualización de datos
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (isset($_POST['actualizar_datos'])) {
            $nuevoUsername = sanitizeInput($_POST['username']);
            $nuevoEmail = sanitizeInput($_POST['email']);
            
            // Verificar si el nuevo username ya existe
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
            $stmt->execute([$nuevoUsername, $_SESSION['user_id']]);
            if ($stmt->fetch()) {
                $error = "El nombre de usuario ya está en uso";
            } else {
                // Verificar si el nuevo email ya existe
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                $stmt->execute([$nuevoEmail, $_SESSION['user_id']]);
                if ($stmt->fetch()) {
                    $error = "El correo electrónico ya está en uso";
                } else {
                    // Actualizar datos
                    $stmt = $pdo->prepare("UPDATE users SET username = ?, email = ? WHERE id = ?");
                    $stmt->execute([$nuevoUsername, $nuevoEmail, $_SESSION['user_id']]);
                    $mensaje = "Datos actualizados correctamente";
                    $_SESSION['username'] = $nuevoUsername;
                }
            }
        }
        
        if (isset($_POST['cambiar_password'])) {
            $passwordActual = $_POST['password_actual'];
            $nuevaPassword = $_POST['nueva_password'];
            $confirmarPassword = $_POST['confirmar_password'];
            
            // Verificar contraseña actual
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
            
            if (password_verify($passwordActual, $user['password'])) {
                if ($nuevaPassword === $confirmarPassword) {
                    // Validar requisitos de la contraseña
                    if (strlen($nuevaPassword) >= 8 && 
                        preg_match('/[A-Z]/', $nuevaPassword) && 
                        preg_match('/[a-z]/', $nuevaPassword) && 
                        preg_match('/[0-9]/', $nuevaPassword)) {
                        
                        $passwordHash = password_hash($nuevaPassword, PASSWORD_DEFAULT);
                        $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                        $stmt->execute([$passwordHash, $_SESSION['user_id']]);
                        $mensaje = "Contraseña actualizada correctamente";
                    } else {
                        $error = "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número";
                    }
                } else {
                    $error = "Las contraseñas no coinciden";
                }
            } else {
                $error = "La contraseña actual es incorrecta";
            }
        }
    }
} catch(PDOException $e) {
    $error = "Error: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mi Cuenta</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body >
<?php renderizarMenu($username, $isRoot); ?>
   
    <div class="container mt-4">
        <div class="row">
            <div class="col-md-8 mx-auto">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">Mi Cuenta</h4>
                    </div>
                    <div class="card-body">
                        <?php if ($mensaje): ?>
                            <div class="alert alert-success"><?php echo $mensaje; ?></div>
                        <?php endif; ?>

                        <?php if ($error): ?>
                            <div class="alert alert-danger"><?php echo $error; ?></div>
                        <?php endif; ?>

                        <?php if ($usuario): ?>
                            <div class="mb-4">
                                <h5>Último acceso</h5>
                                <p class="text-muted">
                                    <?php echo $usuario['last_login'] ? date('d/m/Y H:i:s', strtotime($usuario['last_login'])) : 'Nunca'; ?>
                                </p>
                            </div>

                            <form method="POST" action="" class="mb-4">
                                <h5>Actualizar Datos Personales</h5>
                                <div class="mb-3">
                                    <label for="username" class="form-label">Nombre de Usuario</label>
                                    <input type="text" class="form-control" id="username" name="username" 
                                           value="<?php echo htmlspecialchars($usuario['username']); ?>" required>
                                </div>
                                <div class="mb-3">
                                    <label for="email" class="form-label">Correo Electrónico</label>
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($usuario['email']); ?>" required>
                                </div>
                                <button type="submit" name="actualizar_datos" class="btn btn-primary">
                                    Actualizar Datos
                                </button>
                            </form>

                            <form method="POST" action="">
                                <h5>Cambiar Contraseña</h5>
                                <div class="mb-3">
                                    <label for="password_actual" class="form-label">Contraseña Actual</label>
                                    <div class="input-group">
                                        <input type="password" class="form-control" id="password_actual" name="password_actual" required>
                                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('password_actual')">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="nueva_password" class="form-label">Nueva Contraseña</label>
                                    <div class="input-group">
                                        <input type="password" class="form-control" id="nueva_password" name="nueva_password" required>
                                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('nueva_password')">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                    </div>
                                    <div class="form-text">
                                        La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="confirmar_password" class="form-label">Confirmar Nueva Contraseña</label>
                                    <div class="input-group">
                                        <input type="password" class="form-control" id="confirmar_password" name="confirmar_password" required>
                                        <button class="btn btn-outline-secondary" type="button" onclick="togglePassword('confirmar_password')">
                                            <i class="bi bi-eye"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <button type="button" class="btn btn-info" onclick="generarContraseña()">
                                        <i class="bi bi-magic"></i> Generar Contraseña Segura
                                    </button>
                                </div>
                                <button type="submit" name="cambiar_password" class="btn btn-primary">
                                    Cambiar Contraseña
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
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

        function leetSpeak(word) {
            const leetMap = {
                'a': '4',
                'e': '3',
                'i': '1',
                'o': '0',
                's': '5',
                't': '7',
                'b': '8',
                'g': '9',
                'l': '1',
                'z': '2',
                'A': '4',
                'E': '3',
                'I': '1',
                'O': '0',
                'S': '5',
                'T': '7',
                'B': '8',
                'G': '9',
                'Z': '2'
            };
            return word.split('').map(char => leetMap[char] || char).join('');
        }

        function generarContraseña() {
            const palabrasBasicas = [
                // Tecnología
                'Hacker', 'Admin', 'Root', 'System', 'Code', 'Cyber', 'Data', 'Tech',
                'Server', 'Secure', 'Matrix', 'Binary', 'Crypto', 'Network', 'Program',
                // Fantasía
                'Dragon', 'Phoenix', 'Wizard', 'Magic', 'Shadow', 'Crystal', 'Legend',
                'Master', 'Power', 'Force', 'Spirit', 'Mystic', 'Divine', 'Sacred',
                // Naturaleza
                'Thunder', 'Storm', 'Lightning', 'Flame', 'Frost', 'Wind', 'Earth',
                'Ocean', 'Mountain', 'Forest', 'River', 'Solar', 'Lunar', 'Star',
                // Guerreros
                'Ninja', 'Samurai', 'Warrior', 'Knight', 'Hunter', 'Ranger', 'Guard',
                'Shield', 'Sword', 'Battle', 'Combat', 'Strike', 'Attack', 'Defense'
            ];

            const mayusculas = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const numeros = '0123456789';
            const caracteres = '!@#$%^&*()_+-=[]{}|;:,.<>?';

            // Seleccionar dos palabras base aleatorias
            const palabra1 = palabrasBasicas[Math.floor(Math.random() * palabrasBasicas.length)];
            const palabra2 = palabrasBasicas[Math.floor(Math.random() * palabrasBasicas.length)];
            
            // Convertir a leet speak
            const leet1 = leetSpeak(palabra1);
            const leet2 = leetSpeak(palabra2);
            
            // Agregar caracteres especiales y números
            const especial = caracteres[Math.floor(Math.random() * caracteres.length)];
            const numero = numeros[Math.floor(Math.random() * numeros.length)];
            const mayuscula = mayusculas[Math.floor(Math.random() * mayusculas.length)];
            
            // Combinar todo de manera legible
            let contraseña = leet1 + especial + leet2 + numero + mayuscula;
            
            // Asignar la contraseña generada
            document.getElementById('nueva_password').value = contraseña;
            document.getElementById('confirmar_password').value = contraseña;
            
            // Mostrar la traducción en un alert
            alert(`Contraseña generada:\n${contraseña}\n\nTraducción:\n${palabra1} + ${palabra2}`);
        }
    </script>
</body>
</html> 