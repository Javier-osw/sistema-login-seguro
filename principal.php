<?php
session_start();
require_once 'config.php';
require_once 'funciones.php';

// Verificar si el usuario está logueado
requireLogin();

$username = $_SESSION['username'];
$isRoot = ($username === 'root');
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Página Principal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <?php renderizarMenu($username, $isRoot); ?>

    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-body">
                        <h1 class="card-title">Bienvenido a la página principal</h1>
                        <p class="card-text">Has iniciado sesión correctamente.</p>
                        
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <div class="d-grid gap-2">
                                    <a href="plantilla_busqueda.php" class="btn btn-primary">
                                        <i class="bi bi-search"></i> 
                                        Ir a la Página de Búsqueda
                                    </a>
                                </div>
                            </div>
                            <?php if ($isRoot): ?>
                            <div class="col-md-6">
                                <div class="d-grid gap-2">
                                    <a href="admin_usuarios.php" class="btn btn-primary">
                                        <i class="bi bi-people-fill"></i> 
                                        Ir al Panel de Administración de Usuarios
                                    </a>
                                </div>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 