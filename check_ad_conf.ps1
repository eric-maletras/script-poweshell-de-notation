# Demande des informations à l'utilisateur
$nom = Read-Host "Entrez votre nom"
$prenom = Read-Host "Entrez votre prénom"
$domaine = Read-Host "Entrez le nom du domaine"
$nomServeurWeb = Read-Host "Entrez le nom du serveur web (ex: srv-web)"
$ipServeurWeb = Read-Host "Entrez l'IP du serveur web (ex: 192.168.62.3)"
$nomSiteWeb = Read-Host "Entrez le nom du site web (ex: glpi)"

# Initialisation du fichier de log
$jsonFile = "C:\AD-$($nom)-$($prenom).json"

# Initialisation d'un tableau pour stocker les logs
$logMessages = @()

function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"

    # Ajouter chaque entrée au tableau des logs
    $global:logMessages += $logEntry

    # Également afficher la ligne dans la console (utile pour debug)
    Write-Output $logEntry
}



# Vérification des points demandés
$note = 0
$totalPoints = 0

Write-Log "Début des vérifications pour le domaine: $domaine"

# 1. Vérifier si le rôle DNS est installé
$totalPoints++
$dnsInstalled = Get-WindowsFeature -Name "DNS" | Select-Object -ExpandProperty Installed
if ($dnsInstalled) {
    Write-Log "[OK] Le rôle DNS est installé."
    $note++
} else {
    Write-Log "[ERREUR] Le rôle DNS n'est pas installé."
}

# 2. Vérifier si une ZRD principale au nom du domaine existe
$totalPoints++
$zrdExist = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $domaine -and $_.ZoneType -eq 'Primary' }
if ($zrdExist) {
    Write-Log "[OK] La zone de recherche directe (ZRD) '$domaine' est créée en principale."
    $note++
} else {
    Write-Log "[ERREUR] La zone de recherche directe (ZRD) '$domaine' est absente."
}

# 3. Vérifier si une ZRI est créée
$totalPoints++
$zriExist = Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -eq $true }
if ($zriExist) {
    Write-Log "[OK] Une zone de recherche inverse (ZRI) est créée."
    $note++
} else {
    Write-Log "[ERREUR] Aucune zone de recherche inverse (ZRI) n'est configurée."
}

# 4. Vérifier si le DNS de la carte réseau est bien configuré
$totalPoints++
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }).IPAddress
$dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
if ($dnsConfig -contains '127.0.0.1' -or $dnsConfig -contains $localIP) {
    Write-Log "[OK] Le serveur DNS est bien configuré sur 127.0.0.1 ou l'IP du serveur."
    $note++
} else {
    Write-Log "[ERREUR] Le serveur DNS n'est pas configuré correctement."
}

# Vérifier uniquement si la ZRD existe avant d'interroger les records
$totalPoints++
$totalPoints++
if ($zrdExist) {
    # 5. Vérifier la présence exacte d'un enregistrement A pour le serveur web
    $recordA = Get-DnsServerResourceRecord -ZoneName $domaine -Name $nomServeurWeb -RRType 'A' -ErrorAction SilentlyContinue
    if ($recordA -and ($recordA.RecordData.IPv4Address.IPAddressToString -eq $ipServeurWeb)) {
        Write-Log "[OK] L'enregistrement A '$nomServeurWeb' ($ipServeurWeb) est présent."
        $note++
    } else {
        Write-Log "[ERREUR] L'enregistrement A '$nomServeurWeb' ($ipServeurWeb) est absent ou incorrect."
    }

    # 6. Vérifier la présence exacte d'un enregistrement CNAME pour le site web
    $recordCNAME = Get-DnsServerResourceRecord -ZoneName $domaine -Name $nomSiteWeb -RRType 'CNAME' -ErrorAction SilentlyContinue
    if ($recordCNAME -and ($recordCNAME.RecordData.HostNameAlias -eq "$nomServeurWeb.$domaine.")) {
        Write-Log "[OK] L'enregistrement CNAME '$nomSiteWeb' pointant sur '$nomServeurWeb' est présent."
        $note++
    } else {
        Write-Log "[ERREUR] L'enregistrement CNAME '$nomSiteWeb' pointant sur '$nomServeurWeb' est absent ou incorrect."
    }
} else {
    Write-Log "[ERREUR] Les vérifications des enregistrements DNS sont ignorées car la zone '$domaine' est absente."
}

# 7. Vérifier la présence d'un redirecteur (8.8.8.8)
$totalPoints++
$redirectors = (Get-DnsServerForwarder).IPAddress.IPAddressToString
if ($redirectors -contains '8.8.8.8') {
    Write-Log "[OK] Le redirecteur vers 8.8.8.8 est configuré."
    $note++
} else {
    Write-Log "[ERREUR] Le redirecteur vers 8.8.8.8 est absent."
}

# 8. Vérifier que l'IP est configurée en statique
$totalPoints++
$ipConfig = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
if ($ipConfig.Dhcp -eq "Disabled") {
    Write-Log "[OK] L'IP du serveur est configurée en statique."
    $note++
} else {
    Write-Log "[ERREUR] L'IP du serveur n'est pas configurée en statique."
}


# 9. Vérifier que le suffixe DNS principal correspond au domaine
$totalPoints++
$suffixDNS = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
if ($suffixDNS -eq $domaine) {
    Write-Log "[OK] Le suffixe DNS principal correspond au domaine '$domaine'."
    $note++
} else {
    Write-Log "[ERREUR] Le suffixe DNS principal '$suffixDNS' ne correspond pas au domaine '$domaine'."
}

$totalPoints = $totalPoints + 11
# 10 - Vérification de l'installation du rôle AD DS
# Write-Host "Vérification de la présence du rôle Active Directory Domain Services..."
$adRole = Get-WindowsFeature -Name AD-Domain-Services

if ($adRole.Installed) {
    Write-Log "[OK] Le rôle AD DS est installé." -ForegroundColor Green
    $note++

    # Vérification si la machine est un contrôleur de domaine (DC)
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($domainRole -eq 5) {
        Write-Log "[OK] Le serveur est promu en contrôleur de domaine." -ForegroundColor Green
        $note++

        # 11 - Vérification du service AD DS
        Write-Host "Vérification du service NTDS..."
        if ((Get-Service -Name NTDS -ErrorAction SilentlyContinue).Status -eq "Running") {
            Write-Log "[OK] Le service NTDS est actif." -ForegroundColor Green
            $note++
        } else {
            Write-Log "[ERREUR] Le service NTDS n'est PAS actif !" -ForegroundColor Red
        }

        # 12 - Vérification du contrôleur de domaine
        Write-Host "Vérification de la présence d'un contrôleur de domaine..."
        if (Get-ADDomainController -Discover -ErrorAction SilentlyContinue) {
            Write-Log "[OK] Un contrôleur de domaine a été détecté." -ForegroundColor Green
            $note++
        } else {
            Write-Log "[ERREUR] Aucun contrôleur de domaine trouvé !" -ForegroundColor Red
        }

        # 13 - Vérification du domaine AD
        Write-Host "Vérification du domaine AD..."
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            Write-Log "[OK] Domaine détecté : $($domain.DNSRoot)" -ForegroundColor Green
            $note++
        } catch {
            Write-Log "[ERREUR] Aucun domaine AD trouvé !" -ForegroundColor Red
        }

        # 14 - Vérification de la forêt AD
        Write-Host "Vérification de la forêt AD..."
        try {
            $forest = Get-ADForest -ErrorAction Stop
            Write-log "[OK] Forêt détectée : $($forest.Name)" -ForegroundColor Green
            $note++
        } catch {
            Write-Log "[ERREUR] Aucune forêt AD trouvée !" -ForegroundColor Red
        }

        # 15 - Vérification des rôles FSMO
        Write-Host "Vérification des rôles FSMO..."
        try {
            $fsmoRoles = netdom query fsmo 2>$null | ForEach-Object { $_ -replace "\s+", " " }  # Supprime les espaces multiples
            if ($fsmoRoles) {
                Write-Log "[OK] Tous les rôles FSMO sont bien attribués." -ForegroundColor Green
                $note++
            } else {
                Write-Log "[ERREUR] Impossible de récupérer les rôles FSMO !" -ForegroundColor Red
            }
        } catch {
            Write-log "Erreur lors de la récupération des rôles FSMO !" -ForegroundColor Red
        }


        # 16 - Vérification de la résolution DNS du domaine
        Write-Host "Vérification de la résolution DNS..."
        try {
            $domainName = (Get-ADDomain).DNSRoot
            if ($domainName -and (Resolve-DnsName -Name $domainName -Server 127.0.0.1 -ErrorAction SilentlyContinue)) {
                Write-Log "[OK] La résolution DNS du domaine '$domainName' est correcte." -ForegroundColor Green
                $note++
            } else {
                Write-Log "[ERREUR] Problème de résolution DNS pour $domainName !" -ForegroundColor Red
            }
        } catch {
            Write-Log "[ERREUR] Impossible de récupérer le DNS du domaine." -ForegroundColor Red
        }


        # 17 - Vérification de la réplication AD
        Write-Host "Vérification de la réplication AD..."
        try {
            $replicationStatus = repadmin /showrepl 2>$null | Select-String "successfully"  # Filtrer uniquement les lignes pertinentes
            if ($replicationStatus) {
                Write-log "[OK] La réplication AD est fonctionnelle." -ForegroundColor Green
                $note++
            } else {
                Write-log "[ERREUR] Attention : La réplication AD ne semble pas totalement fonctionnelle." -ForegroundColor Yellow
            }
        } catch {
            Write-log "[ERREUR] Impossible d'exécuter 'repadmin', l'outil n'est peut-être pas disponible." -ForegroundColor Red
        }

        # 18 - Vérification de l'OU racine correspondant au domaine
        Write-Host "Vérification de l'OU racine du domaine..."
        $domainDN = (Get-ADDomain).DistinguishedName
        $ouRoot = "OU=@labo.lan,$domainDN"

        if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRoot'" -ErrorAction SilentlyContinue) {
            Write-log "[OK] L'OU racine '$ouRoot' existe bien." -ForegroundColor Green
            $note++
        } else {
            Write-log "[ERREUR] L'OU racine n'existe pas !" -ForegroundColor Red
        }

        # 19 - Vérification de l'OU "Utilisateurs" sous l'OU racine
        Write-Host "Vérification de l'OU 'Utilisateurs' sous l'OU racine..."
        $ouUsers = "OU=utilisateurs,$ouRoot"
        
        if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouUsers'" -ErrorAction SilentlyContinue) {
            Write-Log "[OK] L'OU 'Utilisateurs' existe : $ouUsers" -ForegroundColor Green
            $note++
        } else {
            Write-Log "[ERREUR] L'OU 'Utilisateurs' n'existe pas !" -ForegroundColor Red
        }

        # 20 - Vérification de la présence d'au moins un utilisateur dans l'OU "Utilisateurs"
        Write-Host "Vérification de la présence d'au moins un utilisateur dans l'OU 'Utilisateurs'..."
        $usersCount = (Get-ADUser -Filter * -SearchBase "$ouUsers" -ErrorAction SilentlyContinue | Measure-Object).Count

        if ($usersCount -gt 0) {
            Write-log "[OK] Nombre d'utilisateurs trouvés dans l'OU 'Utilisateurs' : $usersCount" -ForegroundColor Green
            $note++
        } else {
            Write-log "[ERREUR] Aucun utilisateur trouvé dans l'OU 'Utilisateurs' !" -ForegroundColor Red
        }

    } else {
        Write-Log "[ERREUR] Le rôle AD DS est installé mais la machine n'est PAS promue en contrôleur de domaine. Aucun test AD ne sera effectué." -ForegroundColor Yellow
    }

} else {
    Write-Log "[ERREUR] Le rôle Active Directory Domain Services n'est PAS installé. Aucun test AD ne sera effectué." -ForegroundColor Red
}



# Calcul de la note
#$finalNote = [math]::Round(($note / $totalPoints) * 20, 1)

# Calcul de la note sur 20
$scoreSur20 = if ($totalPoints -gt 0) { [math]::Round(($note / $totalPoints) * 20, 2) } else { 0 }

# Transformation de la liste en une seule chaîne avec sauts de ligne
$logDetails = $logMessages -join "`n"

# Génération du JSON
$jsonData = @{
    "status"    = "OK"
    "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "nom"       = $nom
    "prenom"    = $prenom
    "score"     = $note
    "total"     = $totalPoints
    "note"      = if ($totalPoints -gt 0) { [math]::Round(($note / $totalPoints) * 20, 2) } else { 0 }
    "commentaires"   = $logDetails  # ✅ Ici, on force le format avec des \n
} | ConvertTo-Json -Depth 3


# Sauvegarde du fichier JSON
$jsonData | Set-Content -Path $jsonFile -Encoding UTF8

Write-Output "✅ Fichier JSON généré : $jsonFile"

# ---- Envoi du fichier JSON vers logreceiver.php ----

# URL du serveur PHP qui reçoit les données
$serverUrl = "http://www.imcalternance.com/logsapi/logreceiver.php?filename=AD-$($nom)-$($prenom).json"

# Envoi via une requête POST
try {
    Invoke-RestMethod -Uri $serverUrl -Method Post -Body $jsonData -ContentType "application/json; charset=utf-8"
    Write-Output "✅ Fichier JSON envoyé avec succès !"
} catch {
    Write-Output "❌ Erreur lors de l'envoi du fichier JSON : $_"
}


# Attendre avant de fermer
Read-Host -Prompt "Appuyez sur Entrée pour quitter"
