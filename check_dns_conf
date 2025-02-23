# Demande des informations à l'utilisateur
$nom = Read-Host "Entrez votre nom"
$prenom = Read-Host "Entrez votre prénom"
$domaine = Read-Host "Entrez le nom du domaine"
$nomServeurWeb = Read-Host "Entrez le nom du serveur web (ex: srv-web)"
$ipServeurWeb = Read-Host "Entrez l'IP du serveur web (ex: 192.168.62.3)"
$nomSiteWeb = Read-Host "Entrez le nom du site web (ex: glpi)"

# Initialisation du fichier de log
$logFile = "C:\$($nom)-$($prenom).txt"

# Fonction pour écrire dans le log
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -Append -FilePath $logFile -Encoding UTF8
}

# Vérification des points demandés
$note = 0
$totalPoints = 9

Write-Log "Début des vérifications pour le domaine: $domaine"

# 1. Vérifier si le rôle DNS est installé
$dnsInstalled = Get-WindowsFeature -Name "DNS" | Select-Object -ExpandProperty Installed
if ($dnsInstalled) {
    Write-Log "[OK] Le rôle DNS est installé."
    $note++
} else {
    Write-Log "[ERREUR] Le rôle DNS n'est pas installé."
}

# 2. Vérifier si une ZRD principale au nom du domaine existe
$zrdExist = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $domaine -and $_.ZoneType -eq 'Primary' }
if ($zrdExist) {
    Write-Log "[OK] La zone de recherche directe (ZRD) '$domaine' est créée en principale."
    $note++
} else {
    Write-Log "[ERREUR] La zone de recherche directe (ZRD) '$domaine' est absente."
}

# 3. Vérifier si une ZRI est créée
$zriExist = Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -eq $true }
if ($zriExist) {
    Write-Log "[OK] Une zone de recherche inverse (ZRI) est créée."
    $note++
} else {
    Write-Log "[ERREUR] Aucune zone de recherche inverse (ZRI) n'est configurée."
}

# 4. Vérifier si le DNS de la carte réseau est bien configuré
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }).IPAddress
$dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
if ($dnsConfig -contains '127.0.0.1' -or $dnsConfig -contains $localIP) {
    Write-Log "[OK] Le serveur DNS est bien configuré sur 127.0.0.1 ou l'IP du serveur."
    $note++
} else {
    Write-Log "[ERREUR] Le serveur DNS n'est pas configuré correctement."
}

# Vérifier uniquement si la ZRD existe avant d'interroger les records
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
$redirectors = (Get-DnsServerForwarder).IPAddress.IPAddressToString
if ($redirectors -contains '8.8.8.8') {
    Write-Log "[OK] Le redirecteur vers 8.8.8.8 est configuré."
    $note++
} else {
    Write-Log "[ERREUR] Le redirecteur vers 8.8.8.8 est absent."
}

# 8. Vérifier que l'IP est configurée en statique
$ipConfig = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
if ($ipConfig.Dhcp -eq "Disabled") {
    Write-Log "[OK] L'IP du serveur est configurée en statique."
    $note++
} else {
    Write-Log "[ERREUR] L'IP du serveur n'est pas configurée en statique."
}


# 9. Vérifier que le suffixe DNS principal correspond au domaine
$suffixDNS = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
if ($suffixDNS -eq $domaine) {
    Write-Log "[OK] Le suffixe DNS principal correspond au domaine '$domaine'."
    $note++
} else {
    Write-Log "[ERREUR] Le suffixe DNS principal '$suffixDNS' ne correspond pas au domaine '$domaine'."
}


# Calcul de la note
$finalNote = [math]::Round(($note / $totalPoints) * 20, 1)
Write-Log "Vérifications terminées. Note obtenue: $finalNote / 20"

Write-Host "Le rapport de vérification a été généré: $logFile"
Write-Host "Note finale: $finalNote / 20"

# Envoi du log sur le site externe
$logContent = Get-Content -Path $logFile -Raw
Invoke-RestMethod -Uri "http://www.imcalternance.com/logsapi/logreceiver.php?filename=$nom-$prenom.txt" `
                  -Method Post `
                  -Body $logContent `
                  -ContentType "text/plain; charset=utf-8"

# Attendre avant de fermer
Read-Host -Prompt "Appuyez sur Entrée pour quitter"
