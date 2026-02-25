# Script PowerShell de Notation

## Description du projet

Dépôt de scripts de correction et vérification automatisée pour les TP de BTS SIO SISR.
Ces scripts sont exécutés par les étudiants pour évaluer automatiquement leurs travaux pratiques
(Active Directory, GPO, NTFS, DFS, DNS, GLPI, Zabbix).

Auteur : Eric MALETRAS - BTS SIO SISR

## Structure du projet

```
├── check_ad_conf.ps1           # Vérification configuration Active Directory + DNS
├── GPO_TP1.ps1                 # Correction TP1 GPO Sécurité (PSRemoting depuis client)
├── check_GPO_TP2.ps1           # Correction TP2 GPO
├── DFS_TP1.ps1                 # Correction TP1 DFS (droits admin requis)
├── NTFS_Ex1-RH                 # Correction exercice NTFS - Service RH
├── NTFS_Ex2-Compta             # Correction exercice NTFS - Comptabilité
├── RAID_TP1_Windows            # Correction TP RAID Windows
├── Devoir01_AD_GPO_DFS         # Correction devoir AD + GPO + DFS
├── check_install_winServ2019.ps1  # Vérification installation Windows Server 2019
├── check_win_dns_conf.ps1      # Vérification configuration DNS Windows
├── check_glpi_data.py          # Vérification données GLPI (Python, sur serveur Linux)
├── check_install_glpi.py       # Vérification installation GLPI (Python, sur serveur Linux)
├── CreateTP/
│   └── GPO_TP2_create          # Script de préparation TP2 GPO (crée des bugs volontaires)
├── linux/
│   └── check_install_zabbix.py # Vérification installation Zabbix 7.0 sur Debian 12
└── php/
    ├── logreceiver.php         # Réception des logs envoyés par les scripts (POST)
    └── afficher_groupe.php     # Affichage des résultats par groupe (lecture JSON)
```

## Architecture commune des scripts

### Pattern de notation (PowerShell)

Tous les scripts PowerShell suivent le même pattern :

1. **En-tête / Inputs** : `Read-Host` pour Nom, Prénom, Domaine FQDN, lettre de disque, etc.
2. **Normalisation du domaine** : validation FQDN, construction du DN (`DC=...`)
3. **Système de scoring** : variables `$note` et `$totalPoints`, fonction `Write-Log`
4. **Vérifications séquentielles** : chaque point du TP est vérifié avec attribution de points
5. **Résumé final** : affichage de la note `$note / $totalPoints`
6. **Envoi des résultats** : POST vers `logreceiver.php` (logs texte + JSON)

### Pattern de notation (Python)

Les scripts Python (`check_glpi_data.py`, `check_install_glpi.py`, `check_install_zabbix.py`) :

1. Installation automatique des dépendances (`apt`)
2. Vérifications via subprocess, API, ou requêtes HTTP
3. Système de scoring similaire
4. Envoi des résultats vers le serveur web

### Serveur de résultats (PHP)

- `logreceiver.php` reçoit les logs en POST et les stocke (fichiers texte + JSON)
- `afficher_groupe.php` affiche les résultats agrégés par groupe d'étudiants

## Conventions de code

- **Langue** : commentaires et messages en français
- **Encodage** : UTF-8
- **PowerShell** : variables en PascalCase (`$DomainDns`, `$NomServeurWeb`)
- **Couleurs console** : Cyan (titres), Green (succès), Red (échec), Yellow (avertissements)
- **Logs** : format horodaté `yyyy-MM-dd HH:mm:ss - Message`
- **Scoring** : chaque vérification ajoute à `$totalPoints` et incrémente `$note` si réussi

## Environnement cible

- **Scripts PowerShell** : Windows Server 2019+, postes clients Windows joints au domaine
- **Scripts Python** : Debian 12 / serveurs Linux
- **PHP** : serveur web Apache avec PHP
- Les scripts sont conçus pour être exécutés par les étudiants sur leurs machines de TP
