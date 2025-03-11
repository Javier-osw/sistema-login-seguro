<?php
// Iniciar la sesión
session_start();
require_once 'config.php';

// Actualizar último login en la base de datos si el usuario está logueado
if (isLoggedIn()) {
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
    } catch(PDOException $e) {
        // Si hay error, continuamos con el logout de todos modos
        error_log("Error al actualizar último login: " . $e->getMessage());
    }
}

// Destruir todas las variables de sesión
$_SESSION = array();

// Destruir la cookie de sesión si existe
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time()-42000, '/');
}

// Destruir la sesión
session_destroy();

// Redirigir al login
header("Location: index.php");
exit(); 