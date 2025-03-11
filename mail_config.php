<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Función para enviar correos
function enviarCorreo($destinatario, $asunto, $mensaje) {
    try {
        // Crear una nueva instancia de PHPMailer
        $mail = new PHPMailer(true);

        // Configuración del servidor
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'tu_correo@gmail.com'; // Reemplaza con tu correo de Gmail
        $mail->Password   = 'tu_contraseña_de_aplicacion'; // Reemplaza con tu contraseña de aplicación de Gmail
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;
        $mail->CharSet    = 'UTF-8';

        // Remitente y destinatario
        $mail->setFrom('tu_correo@gmail.com', 'Sistema de Login'); // Reemplaza con tu correo
        $mail->addAddress($destinatario);

        // Contenido
        $mail->isHTML(true);
        $mail->Subject = $asunto;
        $mail->Body    = $mensaje;

        // Enviar el correo
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Error al enviar correo: {$mail->ErrorInfo}");
        return false;
    }
} 