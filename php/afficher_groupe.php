<?php
$directory = __DIR__ . "/json_files";
$files = glob("$directory/*.json");

$groups = [];
$data = [];

// Lire les fichiers et organiser les données
foreach ($files as $file) {
    $filename = basename($file, ".json");

    $parts = explode("-", $filename);

    if (count($parts) >= 3) {
        $group = $parts[0];
        $nom = $parts[1];

        // Regrouper tout le reste comme prénom
        $prenom_raw = implode("-", array_slice($parts, 2));

        // PUIS supprimer le suffixe _01, _02, etc. du prénom
        $prenom = preg_replace('/_\d+$/', '', $prenom_raw);

        // Lire le contenu du fichier JSON
        $log_content = file_get_contents($file);
        $json_start = strpos($log_content, "{");

        if ($json_start === false) {
            echo "<p style='color: red;'>⚠ Erreur : Format du fichier invalide ($file).</p>";
            continue;
        }

        $json_data = substr($log_content, $json_start);
        $jsonContent = json_decode($json_data, true);

        if ($jsonContent === null) {
            echo "<p style='color: red;'>⚠ Erreur : json_decode() a échoué sur $file.</p>";
            echo "<p>📄 Message d'erreur JSON : " . json_last_error_msg() . "</p>";
            continue;
        }

        $note = isset($jsonContent['note']) ? $jsonContent['note'] : "N/A";

        // Extraire la date de réception (première ligne du fichier)
        $first_line = strtok($log_content, "\n");
        preg_match('/Reçu le : (.+)/', $first_line, $matches);
        $timestamp = isset($matches[1]) ? $matches[1] : date('Y-m-d H:i:s', filemtime($file));

        // Clé unique par étudiant (groupe + nom + prénom)
        $key = $group . "_" . $nom . "_" . $prenom;

        // Stocker toutes les tentatives
        if (!isset($groups[$group][$key])) {
            $groups[$group][$key] = [
                "nom" => $nom,
                "prenom" => $prenom,
                "tentatives" => []
            ];
        }

        $groups[$group][$key]['tentatives'][] = [
            "filename" => $filename,
            "note" => $note,
            "timestamp" => $timestamp,
            "details" => $jsonContent
        ];
    }
}

// Calculer les notes pondérées
$coefficients = [2, 1, 0.5]; // Pondération décroissante

foreach ($groups as $group => &$students) {
    foreach ($students as $key => &$student) {
        // Trier les tentatives par date
        usort($student['tentatives'], function($a, $b) {
            return strtotime($a['timestamp']) - strtotime($b['timestamp']);
        });

        // Calculer la note pondérée
        $somme_ponderee = 0;
        $somme_coeff = 0;

        foreach ($student['tentatives'] as $index => $tentative) {
            $coeff = $coefficients[$index] ?? 0.5; // 0.5 par défaut pour tentative 3+
            $somme_ponderee += $tentative['note'] * $coeff;
            $somme_coeff += $coeff;
        }

        $student['note_finale'] = round($somme_ponderee / $somme_coeff, 2);
        $student['nb_tentatives'] = count($student['tentatives']);
        $student['derniere_note'] = end($student['tentatives'])['note'];
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
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .clickable { cursor: pointer; color: #2196F3; text-decoration: underline; }
        .clickable:hover { color: #0b7dda; }
        .details { display: none; border: 1px solid #ddd; padding: 15px; margin: 10px 0; background: #f9f9f9; }
        .tentative { margin: 10px 0; padding: 10px; border-left: 3px solid #2196F3; background: #e3f2fd; }
        .note-finale { font-weight: bold; color: #4CAF50; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.85em; margin-left: 5px; }
        .badge-warning { background-color: #ff9800; color: white; }
        .badge-info { background-color: #2196F3; color: white; }
        form { margin: 20px 0; }
        select { padding: 8px; font-size: 1em; }
    </style>
    <script>
        function showDetails(id) {
            var detailDiv = document.getElementById("details-" + id);
            detailDiv.style.display = detailDiv.style.display === "none" ? "block" : "none";
        }
    </script>
</head>
<body>

    <h1>📊 Résultats des tests GLPI</h1>

    <!-- Formulaire de sélection du groupe -->
    <form method="GET">
        <label for="group">Sélectionnez un groupe :</label>
        <select name="group" id="group" onchange="this.form.submit()">
            <option value="">-- Choisissez --</option>
            <?php foreach ($groups as $group => $students): ?>
                <option value="<?= htmlspecialchars($group) ?>" <?= $selectedGroup === $group ? 'selected' : '' ?>>
                    <?= htmlspecialchars($group) ?> (<?= count($students) ?> étudiants)
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
                    <th>Tentatives</th>
                    <th>Dernière note</th>
                    <th>Note finale (pondérée)</th>
                    <th>Détails</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $index = 0;
                foreach ($groups[$selectedGroup] as $student):
                ?>
                    <tr>
                        <td><?= htmlspecialchars($student['nom']) ?></td>
                        <td><?= htmlspecialchars($student['prenom']) ?></td>
                        <td>
                            <?= $student['nb_tentatives'] ?>
                            <?php if ($student['nb_tentatives'] > 1): ?>
                                <span class="badge badge-warning">Multiple</span>
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars($student['derniere_note']) ?>/20</td>
                        <td class="note-finale"><?= $student['note_finale'] ?>/20</td>
                        <td>
                            <span class="clickable" onclick="showDetails(<?= $index ?>)">
                                👁️ Voir les détails
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="6">
                            <div id="details-<?= $index ?>" class="details">
                                <h3>📝 Détails des tentatives</h3>
                                <?php foreach ($student['tentatives'] as $num => $tentative): ?>
                                    <div class="tentative">
                                        <strong>Tentative <?= $num + 1 ?></strong>
                                        <span class="badge badge-info"><?= $tentative['timestamp'] ?></span>
                                        <br>
                                        <strong>Note :</strong> <?= $tentative['note'] ?>/20
                                        <br>
                                        <strong>Fichier :</strong> <?= htmlspecialchars($tentative['filename']) ?>.json
                                        <br><br>
                                        <strong>Commentaires :</strong>
                                        <pre><?= nl2br(htmlspecialchars($tentative['details']['commentaires'])) ?></pre>
                                    </div>
                                <?php endforeach; ?>
                                <div style="margin-top: 15px; padding: 10px; background: #e8f5e9; border-left: 3px solid #4CAF50;">
                                    <strong>📊 Calcul de la note finale :</strong><br>
                                    <?php
                                    $calcul = [];
                                    foreach ($student['tentatives'] as $num => $tentative) {
                                        $coeff = $coefficients[$num] ?? 0.5;
                                        $calcul[] = "{$tentative['note']} × $coeff";
                                    }
                                    $somme_coeff = 0;
                                    foreach ($student['tentatives'] as $num => $t) {
                                        $somme_coeff += $coefficients[$num] ?? 0.5;
                                    }
                                    ?>
                                    (<?= implode(" + ", $calcul) ?>) / <?= $somme_coeff ?> = <strong><?= $student['note_finale'] ?>>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php
                    $index++;
                endforeach;
                ?>
            </tbody>
        </table>
    <?php endif; ?>

</body>
</html>
