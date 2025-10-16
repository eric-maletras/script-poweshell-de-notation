<?php

// logreceiver.php

error_log("Requête reçue - Fichier: " . $_GET['filename']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['filename'])) {

    // Récupère le contenu brut envoyé en UTF-8
    $log_content = file_get_contents('php://input');
    $log_content = mb_convert_encoding($log_content, 'UTF-8', 'auto');

    // Sécurise le nom du fichier
    $filename = basename($_GET['filename']);
    $extension = pathinfo($filename, PATHINFO_EXTENSION);
    $name = pathinfo($filename, PATHINFO_FILENAME); // Sans extension

    // Détermine le dossier de destination
    if ($extension === 'json') {
        $directory = 'json_files/'; // Dossier pour JSON
    } else {
        $directory = ''; // Même répertoire que logreceiver.php
    }

    // Créer le dossier si nécessaire
    if (!empty($directory) && !is_dir($directory)) {
        mkdir($directory, 0777, true);
    }

    // Générer un nom unique si le fichier existe déjà
    $filepath = $directory . $filename;
    $counter = 1;

    while (file_exists($filepath)) {
        $filepath = $directory . $name . "_" . str_pad($counter, 2, '0', STR_PAD_LEFT) . "." . $extension;
        $counter++;
    }

    // Ajoute une date au contenu du log
    $log_content = "Reçu le : " . date('Y-m-d H:i:s') . PHP_EOL . $log_content;

    // Écrit le fichier
    file_put_contents($filepath, $log_content);

    // Confirme la réception
    http_response_code(200);
    echo "Fichier enregistré sous : " . basename($filepath);

} else {
    http_response_code(400);
    echo "Erreur de réception : paramètre filename manquant.";
}
?>
