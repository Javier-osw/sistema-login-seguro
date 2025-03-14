<?php
// Configuración de la base de datos
define('DB_HOST', 'localhost');     // Host de la base de datos
define('DB_NAME', 'database');      // Nombre de la base de datos
define('DB_USER', 'root');   // Usuario de la base de datos
define('DB_PASS', '');  // Contraseña de la base de datos

// Configuración de seguridad
define('MAX_LOGIN_ATTEMPTS', 5); // Máximo de intentos de login
define('LOCKOUT_TIME', 15 * 60); // Tiempo de bloqueo en segundos (15 minutos)
define('SESSION_LIFETIME', 3600); // Tiempo de vida de la sesión (1 hora)

// Iniciar o reanudar sesión con configuración segura
function initSession() {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Strict');
    
    session_start();
}

// Configurar headers de seguridad
function setSecurityHeaders() {
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Content-Security-Policy: default-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline';");
}

// Generar token CSRF
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Verificar token CSRF
function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
        error_log("CSRF token inválido");
        return false;
    }
    return true;
}

// Verificar intentos de login
function checkLoginAttempts($username) {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT login_attempts, last_attempt FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$username, $username]);
    $user = $stmt->fetch();
    
    if ($user) {
        if ($user['login_attempts'] >= MAX_LOGIN_ATTEMPTS && 
            time() - strtotime($user['last_attempt']) < LOCKOUT_TIME) {
            $tiempoRestante = LOCKOUT_TIME - (time() - strtotime($user['last_attempt']));
            throw new Exception("Cuenta bloqueada. Intente nuevamente en " . ceil($tiempoRestante / 60) . " minutos.");
        }
        
        if (time() - strtotime($user['last_attempt']) > LOCKOUT_TIME) {
            // Reiniciar intentos si ha pasado el tiempo de bloqueo
            $stmt = $pdo->prepare("UPDATE users SET login_attempts = 0 WHERE username = ? OR email = ?");
            $stmt->execute([$username, $username]);
        }
    }
    return true;
}

// Incrementar intentos de login fallidos
function incrementLoginAttempts($username) {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("UPDATE users SET login_attempts = login_attempts + 1, last_attempt = CURRENT_TIMESTAMP WHERE username = ? OR email = ?");
    $stmt->execute([$username, $username]);
}

// Reiniciar intentos de login
function resetLoginAttempts($username) {
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("UPDATE users SET login_attempts = 0, last_attempt = NULL WHERE username = ? OR email = ?");
    $stmt->execute([$username, $username]);
}

// Conexión a la base de datos
function getDBConnection() {
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false
            ]
        );
        return $pdo;
    } catch(PDOException $e) {
        error_log("Error de conexión: " . $e->getMessage());
        throw new Exception("Error de conexión a la base de datos");
    }
}

// Sanitizar input
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Verificar si el usuario está logueado
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Requerir login para acceder a una página
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: index.php");
        exit();
    }
    
    // Verificar tiempo de inactividad
    if (isset($_SESSION['last_activity']) && 
        time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
        session_unset();
        session_destroy();
        header("Location: index.php?mensaje=" . urlencode("Su sesión ha expirado por inactividad."));
        exit();
    }
    
    $_SESSION['last_activity'] = time();
}
?> 