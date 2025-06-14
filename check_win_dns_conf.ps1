# Variables de configuration
$LogFolder = "C:\Logs"
if (!(Test-Path $LogFolder)) { 
    New-Item -ItemType Directory -Path $LogFolder | Out-Null 
}
$LogFile = "$LogFolder\DNS_Check.log"

$nom = Read-Host "Entrez votre nom"
$prenom = Read-Host "Entrez votre prénom"
$nomVM = Read-Host "Entrez le nom du serveur DNS (VM)"
$domaine = Read-Host "Entrez le nom du domaine (eg: votrePrenom.lan)"
$ipRange = Read-Host "Entrez le nom du rÃ©seau (eg:192.168.62.0)"
$ipMasque = Read-Host "Entrez le masque de sous-rÃ©seau (eg: 255.255.255.0)"
$nomServeurWeb = Read-Host "Entrez le nom du serveur web (eg: srv-web)"
$ipServeurWeb = Read-Host "Entrez l'IP du serveur web (eg: 192.168.62.3)"
$nomSiteWeb = Read-Host "Entrez le nom du site web (eg: glpi)"

Write-Host "`n===== RECAPITULATIF ====="
Write-Host "Nom                          : $nom"
Write-Host "Prénom                       : $prenom"
Write-Host "Nom de la VM                 : $nomVM"
Write-Host "Domaine                      : $domaine"
Write-Host "Réseau IP                    : $ipRange / $ipMasque"
write-Host "Nom du serveur WEB (Record A): $nomServeurWeb"
write-Host "Nom de l'alias (CNAME)       : $nomSiteWeb"

$confirmation = Read-Host "`nLes informations sont-elles correctes ? (O/N)"
if ($confirmation.ToUpper() -ne "O") {
    Write-Host "`n Script interrompu. Veuillez relancer avec les bonnes informations." -ForegroundColor Red
    exit
}

$JsonFile = "$LogFolder\DNS_Check-$nom-$prenom.json"

# Initialisation des logs et des compteurs
$global:logMessages = @()
$global:score = 0
$global:totalPoints = 0

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    $global:logMessages += $logEntry
    Write-Output $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

function Check-InternetAccess {
    $global:totalPoints++
    if (Test-NetConnection -ComputerName "google.com" -InformationLevel Quiet) {
        Write-Log "[OK] Accés à  Internet disponible."
        $global:score++
    } else {
        Write-Log "[ERREUR] Pas d'accés à  Internet."
    }
}

function Check-IEESC {
    $global:totalPoints++
    $adminKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
    $userKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
    
    $adminESC = (Get-ItemProperty -Path $adminKey -Name "IEHarden" -ErrorAction SilentlyContinue).IEHarden
    $userESC = (Get-ItemProperty -Path $userKey -Name "IEHarden" -ErrorAction SilentlyContinue).IEHarden

    if (($adminESC -eq $null -or $adminESC -eq 0) -and ($userESC -eq $null -or $userESC -eq 0)) {
        Write-Log "[OK] Sécurité IE désactivée pour les administrateurs et les utilisateurs."
        $global:score++
    } else {
        Write-Log "[ERREUR] Sécurité IE activée."
    }
}



function Check-PingFirewall {
# Vérifier si la règle pare-feu ICMPv4 est activée en entrée
$global:totalPoints++
$ruleInbound = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "ICMPv4" -and $_.Direction -eq "Inbound" }
if ($ruleInbound -and $ruleInbound.Enabled -eq "True") {
    Write-Log "[OK] La règle pare-feu ICMPv4 entrante est activée."
    $global:score++
} else {
    Write-Log "[ERREUR] Aucune règle pare-feu ICMPv4 entrante activée détectée."
}

# Vérifier si la règle pare-feu ICMPv4 est activée en sortie
$global:totalPoints++
$ruleOutbound = Get-NetFirewallRule | Where-Object { $_.DisplayName -match "ICMPv4" -and $_.Direction -eq "Outbound" }
if ($ruleOutbound -and $ruleOutbound.Enabled -eq "True") {
    Write-Log "[OK] La règle pare-feu ICMPv4 sortante est activée."
    $global:score++
} else {
    Write-Log "[ERREUR] Aucune règle pare-feu ICMPv4 sortante activée détectée."
}

}

function Check-RDP {
    $global:totalPoints++
    $rdpStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
    if ($rdpStatus -eq 0) {
        Write-Log "[OK] Bureau Ã  Distance activé."
        $global:score++
    } else {
        Write-Log "[ERREUR] Bureau Ã  Distance désactivé."
    }
}

function Check-Hostname {
    $global:totalPoints++
    $hostname = (Get-ComputerInfo).CsName
    if ($hostname -eq $NomVM) {
        Write-Log "[OK] Nom de la VM correct."
        $global:score++
    } else {
        Write-Log "[ERREUR] Nom de la VM incorrect."
    }
}

function Check-InstalledSoftware {
    param ([string]$SoftwareName)
    
    $global:totalPoints++
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $found = $false
    foreach ($path in $paths) {
        $installed = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$SoftwareName*" }
        if ($installed) {
            $found = $true
            break
        }
    }
    
    if ($found) {
        Write-Log "[OK] Le logiciel '$SoftwareName' est installé."
        $global:score++
    } else {
        Write-Log "[ERREUR] Le logiciel '$SoftwareName' n'est pas installé."
    }
}


# Test 1 : Vérifier si le rôle DNS est installé
function Check-DNSRole {
    $global:totalPoints++
    if ((Get-WindowsFeature -Name "DNS").Installed) {
        Write-Log "[OK] Le rôle DNS est installé."
        $global:score++
    } else {
        Write-Log "[ERREUR] Le rôle DNS n'est pas installé."
    }
}

# Test 2 : Vérifier la présence d'une zone de recherche directe (ZRD) principale pour le domaine
function Check-ZRD {
    $global:totalPoints++
    $zrdExist = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $domaine -and $_.ZoneType -eq 'Primary' }
    if ($zrdExist) {
        Write-Log "[OK] La zone de recherche directe '$domaine' est créée en principale."
        $global:score++
    } else {
        Write-Log "[ERREUR] La zone de recherche directe '$domaine' est absente."
    }
}

# Test 3 : Vérifier la présence d'une zone de recherche inverse (ZRI)
function Check-ZRI {
    $global:totalPoints++
    $zriExist = Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -eq $true }
    if ($zriExist) {
        Write-Log "[OK] Une zone de recherche inverse est configurée."
        $global:score++
    } else {
        Write-Log "[ERREUR] Aucune zone de recherche inverse n'est configurée."
    }
}

# Test 4 : Vérifier la configuration DNS de la carte réseau (adresse 127.0.0.1 ou IP locale)
function Check-DNSClientConfig {
    $global:totalPoints++
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }).IPAddress
    $dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
    if ($dnsConfig -contains '127.0.0.1' -or $dnsConfig -contains $localIP) {
        Write-Log "[OK] Le serveur DNS est configuré sur 127.0.0.1 ou sur l'IP du serveur ($localIP)."
        $global:score++
    } else {
        Write-Log "[ERREUR] Le serveur DNS n'est pas configuré correctement."
    }
}

# Test 5 : Vérifier l'enregistrement A pour le serveur web (redirection des erreurs)
function Check-RecordA {
    $global:totalPoints++
    $recordA = Get-DnsServerResourceRecord -ZoneName $domaine -Name $nomServeurWeb -RRType 'A' -ErrorAction SilentlyContinue 2>$null
    if ($recordA -and ($recordA.RecordData.IPv4Address.IPAddressToString -eq $ipServeurWeb)) {
        Write-Log "[OK] L'enregistrement A '$nomServeurWeb' ($ipServeurWeb) est présent."
        $global:score++
    } else {
        Write-Log "[ERREUR] L'enregistrement A '$nomServeurWeb' ($ipServeurWeb) est absent ou incorrect."
    }
}

# Test 6 : Vérifier l'enregistrement CNAME pour le site web (redirection des erreurs)
function Check-RecordCNAME {
    $global:totalPoints++
    $recordCNAME = Get-DnsServerResourceRecord -ZoneName $domaine -Name $nomSiteWeb -RRType 'CNAME' -ErrorAction SilentlyContinue 2>$null
    $expectedCNAME = "$nomServeurWeb.$domaine."
    if ($recordCNAME -and ($recordCNAME.RecordData.HostNameAlias -eq $expectedCNAME)) {
        Write-Log "[OK] L'enregistrement CNAME '$nomSiteWeb' pointant sur '$expectedCNAME' est présent."
        $global:score++
    } else {
        Write-Log "[ERREUR] L'enregistrement CNAME '$nomSiteWeb' pointant sur '$expectedCNAME' est absent ou incorrect."
    }
}

# Test 7 : Vérifier la présence d'un redirecteur (8.8.8.8)
function Check-Redirector {
    $global:totalPoints++
    $redirectors = (Get-DnsServerForwarder).IPAddress.IPAddressToString
    if ($redirectors -contains '8.8.8.8') {
        Write-Log "[OK] Le redirecteur vers 8.8.8.8 est configuré."
        $global:score++
    } else {
        Write-Log "[ERREUR] Le redirecteur vers 8.8.8.8 est absent."
    }
}

# Test 8 : Vérifier que l'IP du serveur est configurée en statique
function Check-StaticIP {
    $global:totalPoints++
    $ipConfig = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
    if ($ipConfig.Dhcp -eq "Disabled") {
        Write-Log "[OK] L'IP du serveur est configurée en statique."
        $global:score++
    } else {
        Write-Log "[ERREUR] L'IP du serveur n'est pas configurée en statique."
    }
}

# Test 9 : Vérifier que le suffixe DNS principal correspond au domaine
function Check-DNSSuffix {
    $global:totalPoints++
    $suffixDNS = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
    if ($suffixDNS -eq $domaine) {
        Write-Log "[OK] Le suffixe DNS principal correspond au domaine '$domaine'."
        $global:score++
    } else {
        Write-Log "[ERREUR] Le suffixe DNS principal ('$suffixDNS') ne correspond pas au domaine '$domaine'."
    }
}

# Test 10 : Vérifier le temps écoulé depuis le premier boot de la journée et attribuer un score sur 8
function Check-ElapsedTimeScore {
    param(
        [int]$DefinedTime = 30  # Temps de référence en minutes
    )
    
    # Récupérer le premier événement 6005 (démarrage) depuis le début de la journée
    $startOfDay = (Get-Date).Date
    $firstBootEvent = Get-WinEvent -FilterHashtable @{LogName="System"; ID=6005; StartTime=$startOfDay} |
                      Sort-Object TimeCreated | Select-Object -First 1
                      
    # Ajout des 8 points au total pour ce test
    $global:totalPoints += 8

    if ($firstBootEvent) {
        $firstBootTime = $firstBootEvent.TimeCreated
        Write-Log "Premier boot de la journée enregistré le : $firstBootTime"
        
        $now = Get-Date
        $elapsed = $now - $firstBootTime
        Write-Log "Temps écoulé depuis le premier boot de la journée : $elapsed"
        
        # Convertir le temps écoulé en minutes
        $elapsedMinutes = $elapsed.TotalMinutes
        Write-Log "Temps écoulé en minutes : $elapsedMinutes"
        
        # Attribution du score sur 8 points
        if ($elapsedMinutes -le $DefinedTime) {
            $score = 8
            Write-Log "Délai optimal (<= $DefinedTime minutes). Score = $score / 8"
        }
        elseif ($elapsedMinutes -ge (2 * $DefinedTime)) {
            $score = 0
            Write-Log "Délai trop long (>= {0} minutes). Score = $score / 8" -f (2 * $DefinedTime)
        }
        else {
            # Découpage de la tranche (entre $DefinedTime et 2*$DefinedTime) en 5 intervalles
            $slice = $DefinedTime / 5.0
            $n = [math]::Ceiling(($elapsedMinutes - $DefinedTime) / $slice)
            $score = 8 - ($n * (8 / 5))
            if ($score -lt 0) { 
                $score = 0 
            }
            Write-Log "Délai intermédiaire. (n = $n, tranche = $slice minutes). Score calculé = $score / 8"
        }
        # Mise à jour du score global
        $global:score += $score
    }
    else {
        Write-Log "Aucun événement de démarrage trouvé pour aujourd'hui." "ERROR"
        # En l'absence d'événement, aucun point n'est attribué (mais on a quand même ajouté les 7 points au total)
    }
}

# Exécution des tests
Check-InternetAccess
Check-IEESC
Check-PingFirewall
Check-RDP
Check-Hostname

$softwares = @("VMWare Tools", "Mozilla Firefox", "Google Chrome", "PuTTY", "WinSCP", "FileZilla", "7-Zip")
foreach ($software in $softwares) {
    Check-InstalledSoftware -SoftwareName $software
}
Check-DNSRole
Check-ZRD
Check-ZRI
Check-DNSClientConfig
Check-RecordA
Check-RecordCNAME
Check-Redirector
Check-StaticIP
Check-DNSSuffix
Check-ElapsedTimeScore

# Calcul de la note finale
$finalScore = if ($global:totalPoints -gt 0) { 
    [math]::Round(($global:score / $global:totalPoints) * 20, 2) 
} else { 
    0 
}
Write-Log "Note finale : $finalScore / 20"

# Génération du JSON
$jsonData = @{
    status       = "OK"
    timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    nom          = $nom
    prenom       = $prenom
    score        = $global:score
    total        = $global:totalPoints
    note         = $finalScore
    commentaires = $global:logMessages -join "`n"
} | ConvertTo-Json -Depth 3

# Sauvegarde du fichier JSON
$jsonData | Set-Content -Path $JsonFile -Encoding UTF8
Write-Log "… Fichier JSON généré : $JsonFile"

# Envoi du fichier JSON vers le serveur
$serverUrl = "http://www.imcalternance.com/logsapi/logreceiver.php?filename=DNSWin_Check-$nom-$prenom.json"
try {
    Invoke-RestMethod -Uri $serverUrl -Method Post -Body $jsonData -ContentType "application/json; charset=utf-8"
    Write-Log "… Fichier JSON envoyé avec succès !"
} catch {
    Write-Log "Erreur lors de l'envoi du fichier JSON : $_"
}

Read-Host -Prompt "Appuyez sur Entrée pour quitter"
