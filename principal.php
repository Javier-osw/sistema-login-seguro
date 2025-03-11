<?php
session_start();
require_once 'config.php';

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
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="#">Mi Aplicación</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <?php if ($isRoot): ?>
                    <li class="nav-item">
                        <a class="nav-link" href="admin_usuarios.php">
                            <i class="bi bi-people-fill"></i> Administrar Usuarios
                        </a>
                    </li>
                    <?php endif; ?>
                    <li class="nav-item">
                        <a class="nav-link" href="plantilla_busqueda.php">
                            <i class="bi bi-search"></i> Búsqueda
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="mi_cuenta.php">Mi Cuenta</a>
                    </li>
                    <li class="nav-item">
                        <span class="nav-link">
                            <i class="bi bi-person-circle"></i> 
                            Bienvenido, <?php echo htmlspecialchars($username); ?>
                        </span>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="logout.php">
                            <i class="bi bi-box-arrow-right"></i> 
                            Cerrar Sesión
                        </a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

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