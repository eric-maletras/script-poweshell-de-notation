# Variables de configuration
$NomVM = "srv-2019"
$SuffixeDNS = "labo.lan"
$LogFolder = "C:\Logs"
$LogFile = "$LogFolder\VM_Check.log"
$JsonFile = "$LogFolder\CheckVM2019-$nom-$prenom.json"

# Création du dossier Logs s'il n'existe pas
if (!(Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}

# Demande des informations à l'utilisateur
$nom = Read-Host "Entrez votre nom"
$prenom = Read-Host "Entrez votre prénom"
$NomVM = Read-Host "Entrez le Nom de la VM"
$SuffixeDNS = Read-Host "Entrez le nom du suffixe DNS (votre_prenom.lan)"

# Initialisation des logs
$logMessages = @()

function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    $global:logMessages += $logEntry
    Write-Output $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

# Vérifications
function Check-InternetAccess {
    $global:totalPoints++
    if (Test-NetConnection -ComputerName "google.com" -InformationLevel Quiet) {
        Write-Log "[OK] Accès à Internet disponible."
        $global:score++
    } else {
        Write-Log "[ERREUR] Pas d'accès à Internet."
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
    $global:totalPoints++
    $pingIn = Get-NetFirewallRule -DisplayName "Partage de fichiers et d’imprimantes (Demande d’écho - Trafic entrant ICMPv4)" -ErrorAction SilentlyContinue
    $pingOut = Get-NetFirewallRule -DisplayName "Partage de fichiers et d’imprimantes (Demande d’écho - Trafic sortant ICMPv4)" -ErrorAction SilentlyContinue
    if ($pingIn.Enabled -eq $true -and $pingOut.Enabled -eq $true) {
        Write-Log "[OK] Ping autorisé en entrée et en sortie."
        $global:score++
    } else {
        Write-Log "[ERREUR] Ping non entièrement autorisé."
    }
}

function Check-RDP {
    $global:totalPoints++
    $rdpStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections").fDenyTSConnections
    if ($rdpStatus -eq 0) {
        Write-Log "[OK] Bureau à Distance activé."
        $global:score++
    } else {
        Write-Log "[ERREUR] Bureau à Distance désactivé."
    }
}

function Check-StaticIP {
    $global:totalPoints++
    $networkAdapters = Get-NetIPInterface | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.ConnectionState -eq "Connected" }
    $isStatic = $true

    foreach ($adapter in $networkAdapters) {
        $dhcpStatus = $adapter.Dhcp
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex

        if ($dhcpStatus -eq "Enabled") {
            Write-Log "[ERREUR] Interface $($adapter.InterfaceAlias) est en DHCP (IP: $($ipConfig.IPv4Address.IPAddress))"
            $isStatic = $false
        } else {
            Write-Log "[OK] Interface $($adapter.InterfaceAlias) utilise une IP statique (IP: $($ipConfig.IPv4Address.IPAddress))"
        }
    }

    if ($isStatic) {
        Write-Log "[OK] Toutes les interfaces utilisent une IP statique."
        $global:score++
    } else {
        Write-Log "[ERREUR] Au moins une interface est encore en DHCP."
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

    $installed = Get-WmiObject -Query "SELECT Name FROM Win32_Product WHERE Name LIKE '%$SoftwareName%'" -ErrorAction SilentlyContinue
    if ($installed) {
        Write-Log "[OK] Le logiciel '$SoftwareName' est installé."
    } else {
        Write-Log "[ERREUR] Le logiciel '$SoftwareName' n'est pas installé."
    }
}

# Exécution des tests
$global:score = 0
$global:totalPoints = 0

Check-InternetAccess
Check-IEESC
Check-PingFirewall
Check-RDP
Check-StaticIP
Check-Hostname

$softwares = @("VMWare Tools", "Mozilla Firefox", "Google Chrome", "PuTTY", "WinSCP", "FileZilla", "7-Zip")
foreach ($software in $softwares) {
    Check-InstalledSoftware -SoftwareName $software
}

# Calcul de la note finale
$finalScore = if ($global:totalPoints -gt 0) { [math]::Round(($global:score / $global:totalPoints) * 20, 2) } else { 0 }

# Génération du JSON
$jsonData = @{
    "status"    = "OK"
    "timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "nom"       = $nom
    "prenom"    = $prenom
    "score"     = $global:score
    "total"     = $global:totalPoints
    "note"      = $finalScore
    "commentaires" = ($logMessages -join "`n")
} | ConvertTo-Json -Depth 3

# Sauvegarde du fichier JSON
$jsonData | Set-Content -Path $JsonFile -Encoding UTF8
Write-Log "✅ Fichier JSON généré : $JsonFile"

# Envoi du fichier JSON vers le serveur
$serverUrl = "http://www.imcalternance.com/logsapi/logreceiver.php?filename=VM_Check-$nom-$prenom.json"
try {
    Invoke-RestMethod -Uri $serverUrl -Method Post -Body $jsonData -ContentType "application/json; charset=utf-8"
    Write-Log "✅ Fichier JSON envoyé avec succès !"
} catch {
    Write-Log "❌ Erreur lors de l'envoi du fichier JSON : $_"
}

Read-Host -Prompt "Appuyez sur Entrée pour quitter"
