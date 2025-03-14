<?php
function renderizarMenu($username, $isRoot) {
    echo '<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="principal.php"> <i class="bi bi-house-door-fill"></i>
             Mi Aplicación</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">';
    if ($isRoot) {
        echo '<li class="nav-item">
                <a class="nav-link" href="admin_usuarios.php">
                    <i class="bi bi-people-fill"></i> Administrar Usuarios
                </a>
              </li>';
    }
    echo '<!--
            <li class="nav-item">
            <a class="nav-link" href="plantilla_busqueda.php">
                <i class="bi bi-search"></i> Búsqueda
            </a>
          </li> -->
          
          <li class="nav-item">
            <a class="nav-link" href="mi_cuenta.php">
                <i class="bi bi-person-circle"></i>  Mi Cuenta
            </a>
          </li>
          
          
          <li class="nav-item">
            <span class="nav-link">
                <i class="bi bi-house-door-fill"></i> 
                
                Bienvenido, ' . htmlspecialchars($username) . '
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
  </nav>';
}
?> 