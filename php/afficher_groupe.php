<?php
// FORCER LE RECHARGEMENT - PAS DE CACHE
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

$directory = __DIR__ . "/json_files";
$files = glob("$directory/*.json");

$all_groups = [];

// ÉTAPE 1 : Organiser les fichiers par groupe
$files_by_group = [];

foreach ($files as $file) {
    $filename = basename($file, ".json");
    $parts = explode("-", $filename);
    
    if (count($parts) >= 3) {
        $group = $parts[0];
        
        if (!isset($files_by_group[$group])) {
            $files_by_group[$group] = [];
        }
        
        $files_by_group[$group][] = $file;
    }
}

// ÉTAPE 2 : Pour chaque groupe, traiter SES fichiers uniquement
foreach ($files_by_group as $group_name => $group_files) {
    
    $all_groups[$group_name] = [];
    
    foreach ($group_files as $file) {
        $filename = basename($file, ".json");
        $parts = explode("-", $filename);
        
        if (count($parts) < 3) {
            continue;
        }
        
        $group = $parts[0];
        $nom = $parts[1];
        
        $prenom_raw = implode("-", array_slice($parts, 2));
        $prenom = preg_replace('/_\d+$/', '', $prenom_raw);
        
        if ($group !== $group_name) {
            continue;
        }
        
        $log_content = file_get_contents($file);
        $json_start = strpos($log_content, "{");
        
        if ($json_start === false) {
            continue;
        }
        
        $json_data = substr($log_content, $json_start);
        $jsonContent = json_decode($json_data, true);
        
        if ($jsonContent === null) {
            continue;
        }
        
        $note = isset($jsonContent['note']) ? $jsonContent['note'] : "N/A";
        
        $first_line = strtok($log_content, "\n");
        preg_match('/Reçu le : (.+)/', $first_line, $matches);
        $timestamp = isset($matches[1]) ? $matches[1] : date('Y-m-d H:i:s', filemtime($file));
        
        $key = strtoupper($nom) . "_" . strtoupper($prenom);
        
        if (!isset($all_groups[$group_name][$key])) {
            $all_groups[$group_name][$key] = [
                "nom" => strtoupper($nom),
                "prenom" => ucfirst(strtolower($prenom)),
                "tentatives" => []
            ];
        }
        
        $all_groups[$group_name][$key]['tentatives'][] = [
            "filename" => $filename,
            "note" => $note,
            "timestamp" => $timestamp,
            "details" => $jsonContent
        ];
    }
}

// ÉTAPE 3 : Calculer les notes pondérées
$coefficients = [2, 1, 0.5];

foreach ($all_groups as $grp_name => $grp_students) {
    foreach ($grp_students as $student_key => $student_info) {
        usort($all_groups[$grp_name][$student_key]['tentatives'], function($a, $b) {
            return strtotime($a['timestamp']) - strtotime($b['timestamp']);
        });
        
        $somme_ponderee = 0;
        $somme_coeff = 0;
        
        foreach ($all_groups[$grp_name][$student_key]['tentatives'] as $index => $tentative) {
            $coeff = $coefficients[$index] ?? 0.5;
            $somme_ponderee += $tentative['note'] * $coeff;
            $somme_coeff += $coeff;
        }
        
        $all_groups[$grp_name][$student_key]['note_finale'] = round($somme_ponderee / $somme_coeff, 2);
        $all_groups[$grp_name][$student_key]['nb_tentatives'] = count($all_groups[$grp_name][$student_key]['tentatives']);
        $all_groups[$grp_name][$student_key]['derniere_note'] = end($all_groups[$grp_name][$student_key]['tentatives'])['note'];
    }
}

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

    <form method="GET" action="">
        <label for="group">Sélectionnez un groupe :</label>
        <select name="group" id="group" onchange="this.form.submit()">
            <option value="">-- Choisissez --</option>
            <?php foreach ($all_groups as $g_name => $g_data): ?>
                <option value="<?= htmlspecialchars($g_name) ?>"
                        <?= ($selectedGroup === $g_name) ? 'selected' : '' ?>>
                    <?= htmlspecialchars($g_name) ?> (<?= count($g_data) ?> étudiants)
                </option>
            <?php endforeach; ?>
        </select>
    </form>

    <?php if ($selectedGroup && isset($all_groups[$selectedGroup])): ?>
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
                $display_index = 0;
                foreach ($all_groups[$selectedGroup] as $stu_key => $stu_info):
                ?>
                    <tr>
                        <td><?= htmlspecialchars($stu_info['nom']) ?></td>
                        <td><?= htmlspecialchars($stu_info['prenom']) ?></td>
                        <td>
                            <?= $stu_info['nb_tentatives'] ?>
                            <?php if ($stu_info['nb_tentatives'] > 1): ?>
                                <span class="badge badge-warning">Multiple</span>
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars($stu_info['derniere_note']) ?>/20</td>
                        <td class="note-finale"><?= $stu_info['note_finale'] ?>/20</td>
                        <td>
                            <span class="clickable" onclick="showDetails(<?= $display_index ?>)">
                                👁️ Voir les détails
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td colspan="6">
                            <div id="details-<?= $display_index ?>" class="details">
                                <h3>📝 Détails des tentatives pour <?= htmlspecialchars($stu_info['prenom']) ?> <?= htmlspecialchars($stu_info['nom']) ?></h3>
                                <?php foreach ($stu_info['tentatives'] as $t_num => $t_data): ?>
                                    <div class="tentative">
                                        <strong>Tentative <?= $t_num + 1 ?></strong>
                                        <span class="badge badge-info"><?= $t_data['timestamp'] ?></span>
                                        <br>
                                        <strong>Note :</strong> <?= $t_data['note'] ?>/20
                                        <br>
                                        <strong>Fichier :</strong> <?= htmlspecialchars($t_data['filename']) ?>.json
                                        <br><br>
                                        <strong>Commentaires :</strong>
                                        <pre><?= nl2br(htmlspecialchars($t_data['details']['commentaires'])) ?></pre>
                                    </div>
                                <?php endforeach; ?>

                                <div style="margin-top: 15px; padding: 10px; background: #e8f5e9; border-left: 3px solid #4CAF50;">
                                    <strong>📊 Calcul de la note finale :</strong><br>
                                    <?php
                                    $calc_parts = [];
                                    $calc_coeff = 0;
                                    foreach ($stu_info['tentatives'] as $t_idx => $t_tent) {
                                        $c = $coefficients[$t_idx] ?? 0.5;
                                        $calc_parts[] = "{$t_tent['note']} × $c";
                                        $calc_coeff += $c;
                                    }
                                    ?>
                                    (<?= implode(" + ", $calc_parts) ?>) / <?= number_format($calc_coeff, 1) ?> = <strong><?= $stu_info['note_finale'] ?>/20</strong>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php
                    $display_index++;
                endforeach;
                ?>
            </tbody>
        </table>
    <?php elseif ($selectedGroup): ?>
        <p style="color: red;">⚠ Aucun étudiant trouvé pour le groupe sélectionné.</p>
    <?php endif; ?>

</body>
</html>
