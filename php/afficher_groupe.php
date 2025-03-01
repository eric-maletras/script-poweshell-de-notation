<?php
$directory = __DIR__ . "/json_files"; // Dossier contenant les fichiers JSON
$files = glob("$directory/*.json"); // Récupérer tous les fichiers JSON

$groups = []; // Stocker les groupes détectés
$data = [];   // Stocker les données JSON

// Lire les fichiers et organiser les données
foreach ($files as $file) {
    $filename = basename($file, ".json");
    $parts = explode("-", $filename);
    
    if (count($parts) >= 3) {
        
        $group = $parts[0]; // Premier mot du fichier
        $nom = $parts[1];    // Nom de famille
        $prenom = $parts[2]; // Prénom

        // Charger le contenu JSON
        // Lire le contenu du fichier JSON
	$log_content = file_get_contents($file);

	// Extraire uniquement la partie JSON
	$json_start = strpos($log_content, "{");
	if ($json_start === false) {
	    echo "<p style='color: red;'>❌ Erreur : Format du fichier invalide ($file).</p>";
	    continue;
	}

	// Isoler uniquement la partie JSON du contenu du fichier
	$json_data = substr($log_content, $json_start);
	$jsonContent = json_decode($json_data, true);

	// Vérifier si `json_decode()` a réussi
	if ($jsonContent === null) {
	    echo "<p style='color: red;'>❌ Erreur : `json_decode()` a échoué sur $file.</p>";
	    echo "<p>🔍 Message d'erreur JSON : " . json_last_error_msg() . "</p>";
	    continue;
	}

        $note = isset($jsonContent['note']) ? $jsonContent['note'] : "N/A";

        $groups[$group][] = [
            "filename" => $filename,
            "nom" => $nom,
            "prenom" => $prenom,
            "note" => $note,
            "details" => $jsonContent
        ];
    }
}

// Vérifier si une sélection de groupe est faite
$selectedGroup = isset($_GET['group']) ? $_GET['group'] : "";
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Résultats GLPI</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .clickable { cursor: pointer; color: blue; text-decoration: underline; }
        .details { display: none; border: 1px solid black; padding: 10px; margin-top: 10px; background: #f9f9f9; }
    </style>
    <script>
        function showDetails(id) {
            var detailDiv = document.getElementById("details-" + id);
            detailDiv.style.display = detailDiv.style.display === "none" ? "block" : "none";
        }
    </script>
</head>
<body>

    <h1>Résultats des tests GLPI</h1>

    <!-- Formulaire de sélection du groupe -->
    <form method="GET">
        <label for="group">Sélectionnez un groupe :</label>
        <select name="group" id="group" onchange="this.form.submit()">
            <option value="">-- Choisissez --</option>
            <?php foreach ($groups as $group => $students): ?>
                <option value="<?= htmlspecialchars($group) ?>" <?= $selectedGroup === $group ? 'selected' : '' ?>>
                    <?= htmlspecialchars($group) ?>
                </option>
            <?php endforeach; ?>
        </select>
    </form>

    <?php if ($selectedGroup && isset($groups[$selectedGroup])): ?>
        <h2>Résultats pour le groupe : <?= htmlspecialchars($selectedGroup) ?></h2>
        <table>
            <thead>
                <tr>
                    <th>Nom</th>
                    <th>Prénom</th>
                    <th>Note</th>
                    <th>Détails</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($groups[$selectedGroup] as $index => $student): ?>
                    <tr>
                        <td><?= htmlspecialchars($student['nom']) ?></td>
                        <td><?= htmlspecialchars($student['prenom']) ?></td>
                        <td><?= htmlspecialchars($student['note']) ?></td>
                        <td><span class="clickable" onclick="showDetails(<?= $index ?>)">Voir</span></td>
                    </tr>
                    <tr id="details-<?= $index ?>" class="details">
                        <td colspan="4">
                          <pre><?= nl2br(htmlspecialchars($student['details']['commentaires'])) ?></pre>

                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

</body>
</html>
