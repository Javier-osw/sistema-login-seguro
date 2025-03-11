<?php
session_start();
require_once 'config.php';

// Verificar si el usuario está logueado
requireLogin();

// Inicializar variables
$resultados = [];
$error = '';
$mensaje = '';

// Procesar el formulario de búsqueda
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $pdo = getDBConnection();
        
        // Ejemplo de búsqueda simple
        if (isset($_POST['buscar_simple'])) {
            $termino = sanitizeInput($_POST['termino_busqueda']);
            
            // Consulta preparada para prevenir SQL injection
            $stmt = $pdo->prepare("
                SELECT id, username, email, created_at, last_login 
                FROM users 
                WHERE username LIKE ? OR email LIKE ?
                ORDER BY created_at DESC
            ");
            
            // Usar comodines para búsqueda parcial
            $termino = "%$termino%";
            $stmt->execute([$termino, $termino]);
            $resultados = $stmt->fetchAll();
            
            if (empty($resultados)) {
                $mensaje = "No se encontraron resultados";
            }
        }
        
        // Ejemplo de búsqueda avanzada
        if (isset($_POST['buscar_avanzada'])) {
            $username = sanitizeInput($_POST['username'] ?? '');
            $email = sanitizeInput($_POST['email'] ?? '');
            $fecha_desde = sanitizeInput($_POST['fecha_desde'] ?? '');
            $fecha_hasta = sanitizeInput($_POST['fecha_hasta'] ?? '');
            
            // Construir la consulta dinámicamente
            $sql = "SELECT id, username, email, created_at, last_login FROM users WHERE 1=1";
            $params = [];
            
            if (!empty($username)) {
                $sql .= " AND username LIKE ?";
                $params[] = "%$username%";
            }
            
            if (!empty($email)) {
                $sql .= " AND email LIKE ?";
                $params[] = "%$email%";
            }
            
            if (!empty($fecha_desde)) {
                $sql .= " AND created_at >= ?";
                $params[] = $fecha_desde;
            }
            
            if (!empty($fecha_hasta)) {
                $sql .= " AND created_at <= ?";
                $params[] = $fecha_hasta;
            }
            
            $sql .= " ORDER BY created_at DESC";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $resultados = $stmt->fetchAll();
            
            if (empty($resultados)) {
                $mensaje = "No se encontraron resultados";
            }
        }
        
    } catch(PDOException $e) {
        $error = "Error en la búsqueda: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plantilla de Búsqueda</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="principal.php">Volver al Inicio</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link" href="mi_cuenta.php">Mi Cuenta</a>
                <a class="nav-link" href="logout.php">Cerrar Sesión</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if ($mensaje): ?>
            <div class="alert alert-info"><?php echo htmlspecialchars($mensaje); ?></div>
        <?php endif; ?>

        <!-- Búsqueda Simple -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">Búsqueda Simple</h5>
            </div>
            <div class="card-body">
                <form method="POST" class="row g-3">
                    <div class="col-md-8">
                        <label for="termino_busqueda" class="form-label">Buscar por usuario o email</label>
                        <input type="text" class="form-control" id="termino_busqueda" name="termino_busqueda" 
                               value="<?php echo isset($_POST['termino_busqueda']) ? htmlspecialchars($_POST['termino_busqueda']) : ''; ?>">
                    </div>
                    <div class="col-md-4 d-flex align-items-end">
                        <button type="submit" name="buscar_simple" class="btn btn-primary w-100">
                            <i class="bi bi-search"></i> Buscar
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Búsqueda Avanzada -->
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0">Búsqueda Avanzada</h5>
            </div>
            <div class="card-body">
                <form method="POST" class="row g-3">
                    <div class="col-md-6">
                        <label for="username" class="form-label">Usuario</label>
                        <input type="text" class="form-control" id="username" name="username" 
                               value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
                    </div>
                    <div class="col-md-6">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email" name="email" 
                               value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>">
                    </div>
                    <div class="col-md-6">
                        <label for="fecha_desde" class="form-label">Fecha Desde</label>
                        <input type="date" class="form-control" id="fecha_desde" name="fecha_desde" 
                               value="<?php echo isset($_POST['fecha_desde']) ? htmlspecialchars($_POST['fecha_desde']) : ''; ?>">
                    </div>
                    <div class="col-md-6">
                        <label for="fecha_hasta" class="form-label">Fecha Hasta</label>
                        <input type="date" class="form-control" id="fecha_hasta" name="fecha_hasta" 
                               value="<?php echo isset($_POST['fecha_hasta']) ? htmlspecialchars($_POST['fecha_hasta']) : ''; ?>">
                    </div>
                    <div class="col-12">
                        <button type="submit" name="buscar_avanzada" class="btn btn-primary">
                            <i class="bi bi-search"></i> Buscar Avanzada
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Resultados -->
        <?php if (!empty($resultados)): ?>
        <div class="card">
            <div class="card-header">
                <h5 class="mb-0">Resultados de la Búsqueda</h5>
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
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($resultados as $resultado): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($resultado['id']); ?></td>
                                <td><?php echo htmlspecialchars($resultado['username']); ?></td>
                                <td><?php echo htmlspecialchars($resultado['email']); ?></td>
                                <td><?php echo htmlspecialchars($resultado['created_at']); ?></td>
                                <td><?php echo $resultado['last_login'] ? htmlspecialchars($resultado['last_login']) : 'Nunca'; ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 