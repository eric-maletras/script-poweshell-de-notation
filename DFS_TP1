cls
# =========================
# VÉRIFICATION PRÉALABLE : Droits administrateur
# =========================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  ⚠️  AVERTISSEMENT : Droits administrateur requis" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "Ce script nécessite des droits administrateur pour :" -ForegroundColor Yellow
    Write-Host "  • Configurer TrustedHosts (si connexion par IP)" -ForegroundColor White
    Write-Host "  • Établir des sessions PSRemoting" -ForegroundColor White
    Write-Host ""
    Write-Host "Veuillez relancer PowerShell en tant qu'administrateur" -ForegroundColor Yellow
    Write-Host "(Clic droit > Exécuter en tant qu'administrateur)" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

# =========================
# Script de correction - TP1 : DFS (Distributed File System)
# Exécution depuis un poste CLIENT Windows joint au domaine
# VERSION AVEC PSREMOTING MULTI-SERVEURS
# =========================

# =========================
# En-tête / Inputs
# =========================
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Script de vérification TP1 - DFS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$Nom            = Read-Host "Entrez votre nom"
$Prenom         = Read-Host "Entrez votre prénom"
$Domain         = Read-Host "Entrez le nom du domaine (FQDN ex: prenom.lan)"

# Normalisation domaine
$DomainDns = ([string]$Domain).Trim().TrimEnd('.')
if ([string]::IsNullOrWhiteSpace($DomainDns) -or ($DomainDns -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')) {
    Write-Host ""
    Write-Host "❌ ERREUR : Le domaine saisi '$Domain' n'est pas un FQDN valide (ex: prenom.lan)." -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}
$DomainDN = ($DomainDns -split '\.' | ForEach-Object { "DC=$_" }) -join ','
$DomainNetBios = ($DomainDns -split '\.')[0].ToUpper()

# =========================
# Noms des serveurs
# =========================
Write-Host ""
Write-Host "─────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host "Noms des serveurs" -ForegroundColor Yellow
Write-Host "─────────────────────────────────────────────────" -ForegroundColor Yellow
Write-Host ""

$inputServeurAD = Read-Host "Nom du contrôleur de domaine (ex: srv-ad)"
if ([string]::IsNullOrWhiteSpace($inputServeurAD)) {
    Write-Host "❌ ERREUR : Le nom du contrôleur de domaine est obligatoire" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}
$NomServeurAD = $inputServeurAD

$inputSRV1 = Read-Host "Nom du premier serveur de fichiers (défaut: SRV-FICHIERS1)"
if ([string]::IsNullOrWhiteSpace($inputSRV1)) { 
    $NomServeurSRV1 = "SRV-FICHIERS1" 
} else { 
    $NomServeurSRV1 = $inputSRV1 
}

$inputSRV2 = Read-Host "Nom du second serveur de fichiers (défaut: SRV-FICHIERS2)"
if ([string]::IsNullOrWhiteSpace($inputSRV2)) { 
    $NomServeurSRV2 = "SRV-FICHIERS2" 
} else { 
    $NomServeurSRV2 = $inputSRV2 
}

Write-Host ""
$inputDataDrive = Read-Host "Lettre du disque de données sur les serveurs de fichiers (défaut: E:)"
if ([string]::IsNullOrWhiteSpace($inputDataDrive)) { 
    $DataDrive = "E:" 
} else { 
    $DataDrive = $inputDataDrive.Trim().TrimEnd(':') + ":"
}

# =========================
# AFFICHAGE DE CONFIRMATION
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  RÉCAPITULATIF DES INFORMATIONS SAISIES" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""
Write-Host "Étudiant :" -ForegroundColor Cyan
Write-Host "  • Nom         : $Nom" -ForegroundColor White
Write-Host "  • Prénom      : $Prenom" -ForegroundColor White
Write-Host ""
Write-Host "Infrastructure :" -ForegroundColor Cyan
Write-Host "  • Domaine     : $DomainDns" -ForegroundColor White
Write-Host "  • NetBIOS     : $DomainNetBios" -ForegroundColor White
Write-Host ""
Write-Host "Serveurs :" -ForegroundColor Cyan
Write-Host "  • DC          : $NomServeurAD" -ForegroundColor White
Write-Host "  • Fichiers 1  : $NomServeurSRV1" -ForegroundColor White
Write-Host "  • Fichiers 2  : $NomServeurSRV2" -ForegroundColor White
Write-Host ""
Write-Host "Configuration :" -ForegroundColor Cyan
Write-Host "  • Disque      : $DataDrive" -ForegroundColor White
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""

$confirmation = Read-Host "Les informations sont-elles correctes ? (O/N)"
if ($confirmation -notmatch '^[OoYy]') {
    Write-Host ""
    Write-Host "❌ Test annulé. Relancez le script pour corriger les informations." -ForegroundColor Yellow
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 0
}

Write-Host ""
Write-Host "✅ Informations confirmées. Démarrage des tests..." -ForegroundColor Green
Start-Sleep -Seconds 2

# Construction des FQDN si nécessaire
if ($NomServeurAD -notmatch '\.') { $NomServeurAD = "$NomServeurAD.$DomainDns" }
if ($NomServeurSRV1 -notmatch '\.') { $NomServeurSRV1 = "$NomServeurSRV1.$DomainDns" }
if ($NomServeurSRV2 -notmatch '\.') { $NomServeurSRV2 = "$NomServeurSRV2.$DomainDns" }

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Résolution DNS des serveurs" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Fonction de résolution DNS
function Resolve-ServerIP {
    param(
        [string]$ServerFQDN,
        [string]$ServerLabel
    )
    
    Write-Host "Résolution DNS de $ServerLabel ($ServerFQDN)..." -ForegroundColor Gray
    
    try {
        $dnsResult = Resolve-DnsName -Name $ServerFQDN -Type A -ErrorAction Stop
        $ip = $dnsResult | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1 -ExpandProperty IPAddress
        
        if ($ip) {
            Write-Host "  ✓ $ServerLabel : $ip" -ForegroundColor Green
            return $ip
        } else {
            Write-Host "  ✗ Aucune adresse IP trouvée pour $ServerFQDN" -ForegroundColor Red
            return $null
        }
    } catch {
        Write-Host "  ✗ ERREUR : Impossible de résoudre $ServerFQDN" -ForegroundColor Red
        Write-Host "    Détails : $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# Résolution des IPs
$IpServeurAD   = Resolve-ServerIP -ServerFQDN $NomServeurAD -ServerLabel "Contrôleur de domaine"
$IpServeurSRV1 = Resolve-ServerIP -ServerFQDN $NomServeurSRV1 -ServerLabel "SRV-FICHIERS1"
$IpServeurSRV2 = Resolve-ServerIP -ServerFQDN $NomServeurSRV2 -ServerLabel "SRV-FICHIERS2"

# Vérification que toutes les résolutions ont réussi
$resolutionFailed = $false
if (-not $IpServeurAD) {
    Write-Host ""
    Write-Host "❌ Impossible de résoudre l'IP du contrôleur de domaine ($NomServeurAD)" -ForegroundColor Red
    $resolutionFailed = $true
}
if (-not $IpServeurSRV1) {
    Write-Host ""
    Write-Host "❌ Impossible de résoudre l'IP de SRV-FICHIERS1 ($NomServeurSRV1)" -ForegroundColor Red
    $resolutionFailed = $true
}
if (-not $IpServeurSRV2) {
    Write-Host ""
    Write-Host "❌ Impossible de résoudre l'IP de SRV-FICHIERS2 ($NomServeurSRV2)" -ForegroundColor Red
    $resolutionFailed = $true
}

if ($resolutionFailed) {
    Write-Host ""
    Write-Host "Vérifications à effectuer :" -ForegroundColor Yellow
    Write-Host "  • Les noms de serveurs sont correctement orthographiés" -ForegroundColor White
    Write-Host "  • Les enregistrements DNS A existent dans la zone $DomainDns" -ForegroundColor White
    Write-Host "  • Le client DNS pointe vers le bon serveur DNS" -ForegroundColor White
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

Write-Host ""
Write-Host "✅ Résolution DNS réussie pour tous les serveurs !" -ForegroundColor Green

# =========================
# Configuration préventive de TrustedHosts
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Configuration PSRemoting" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "Vérification de TrustedHosts..." -ForegroundColor Gray

try {
    $currentTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
    
    $needsUpdate = $false
    $ipsToAdd = @()
    
    foreach ($ip in @($IpServeurAD, $IpServeurSRV1, $IpServeurSRV2)) {
        if ([string]::IsNullOrWhiteSpace($currentTrustedHosts) -or $currentTrustedHosts -notlike "*$ip*") {
            $needsUpdate = $true
            $ipsToAdd += $ip
        }
    }
    
    if ($needsUpdate) {
        Write-Host "  → Ajout des serveurs à TrustedHosts..." -ForegroundColor Gray
        
        if ([string]::IsNullOrWhiteSpace($currentTrustedHosts)) {
            $newValue = ($ipsToAdd -join ',')
        } else {
            $newValue = "$currentTrustedHosts," + ($ipsToAdd -join ',')
        }
        
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force -ErrorAction Stop
        Write-Host "  ✓ TrustedHosts configuré avec : $($ipsToAdd -join ', ')" -ForegroundColor Green
    } else {
        Write-Host "  ✓ TrustedHosts déjà configuré" -ForegroundColor Green
    }
} catch {
    Write-Host "  ⚠ AVERTISSEMENT : Impossible de configurer TrustedHosts" -ForegroundColor Yellow
    Write-Host "    Les connexions par FQDN seront privilégiées" -ForegroundColor Gray
}

# =========================
# Demande des credentials administrateur
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  Authentification administrateur du domaine" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "Ces identifiants seront utilisés pour se connecter aux serveurs via PSRemoting" -ForegroundColor Gray
Write-Host ""

$inputAdminUser = Read-Host "Login administrateur (défaut: Administrateur)"
if ([string]::IsNullOrWhiteSpace($inputAdminUser)) { 
    $AdminUser = "Administrateur" 
} else { 
    $AdminUser = $inputAdminUser 
}

$AdminPassword = Read-Host "Mot de passe" -AsSecureString

# Construction du credential avec préfixe domaine si nécessaire
if ($AdminUser -notmatch '\\|@') {
    $AdminUser = "$DomainNetBios\$AdminUser"
}

$Credential = New-Object System.Management.Automation.PSCredential($AdminUser, $AdminPassword)

# =========================
# Fonction de test de connexion PSRemoting
# =========================
function Test-PSRemotingConnection {
    param(
        [string]$ServerName,
        [string]$ServerIP,
        [string]$ServerFQDN,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Connexion à $ServerName" -ForegroundColor Cyan
    Write-Host "  FQDN: $ServerFQDN | IP: $ServerIP" -ForegroundColor DarkGray
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Test 1 : Ping
    Write-Host "[1/3] Test de connectivité réseau (ping)..." -ForegroundColor Gray
    if (-not (Test-Connection -ComputerName $ServerIP -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Host "❌ ERREUR : Le serveur $ServerName ($ServerIP) ne répond pas au ping" -ForegroundColor Red
        Write-Host ""
        Write-Host "Vérifications :" -ForegroundColor Yellow
        Write-Host "  • Le serveur est allumé" -ForegroundColor White
        Write-Host "  • L'adresse IP DNS est correcte" -ForegroundColor White
        Write-Host "  • Le réseau fonctionne" -ForegroundColor White
        return $null
    }
    Write-Host "      ✓ Le serveur répond au ping" -ForegroundColor Green
    
    # Test 2 : Port WinRM (5985)
    Write-Host "[2/3] Test du port WinRM (5985)..." -ForegroundColor Gray
    $portTest = Test-NetConnection -ComputerName $ServerIP -Port 5985 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
    if (-not $portTest) {
        Write-Host "❌ ERREUR : Le port WinRM (5985) n'est pas accessible sur $ServerName" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "  SOLUTION : Activer PSRemoting sur $ServerName" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Sur le serveur $ServerName, ouvrez PowerShell en administrateur et exécutez :" -ForegroundColor White
        Write-Host ""
        Write-Host "    Enable-PSRemoting -Force" -ForegroundColor Cyan
        Write-Host ""
        return $null
    }
    Write-Host "      ✓ Port WinRM accessible" -ForegroundColor Green
    
    # Test 3 : Authentification et création de session
    Write-Host "[3/3] Test d'authentification et création de session..." -ForegroundColor Gray
    
    # Tentative 1 : FQDN
    try {
        $Session = New-PSSession -ComputerName $ServerFQDN -Credential $Cred -ErrorAction Stop
        Write-Host "      ✓ Session PSRemoting établie avec succès (FQDN)" -ForegroundColor Green
        Write-Host "        SessionID: $($Session.Id) | État: $($Session.State)" -ForegroundColor DarkGray
        return $Session
    } catch {
        Write-Host "      ⚠ Échec par FQDN, tentative par IP..." -ForegroundColor Yellow
    }
    
    # Tentative 2 : IP (TrustedHosts déjà configuré en amont)
    try {
        $Session = New-PSSession -ComputerName $ServerIP -Credential $Cred -ErrorAction Stop
        Write-Host "      ✓ Session PSRemoting établie par IP" -ForegroundColor Green
        Write-Host "        SessionID: $($Session.Id) | État: $($Session.State)" -ForegroundColor DarkGray
        return $Session
    } catch {
        Write-Host "❌ ERREUR : Impossible d'établir une session PSRemoting" -ForegroundColor Red
        Write-Host ""
        Write-Host "Détails de l'erreur :" -ForegroundColor Yellow
        Write-Host "  $($_.Exception.Message)" -ForegroundColor White
        Write-Host ""
        
        if ($_.Exception.Message -like "*Access is denied*" -or $_.Exception.Message -like "*Accès refusé*") {
            Write-Host "Cause probable : Identifiants incorrects" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Vérifications :" -ForegroundColor Yellow
            Write-Host "  • Le login est correct ($($Cred.UserName))" -ForegroundColor White
            Write-Host "  • Le mot de passe est correct" -ForegroundColor White
            Write-Host "  • Le compte a les droits d'administrateur" -ForegroundColor White
        }
        
        return $null
    }
}

# =========================
# Connexion aux trois serveurs
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  PHASE 1 : Établissement des connexions" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta

# Connexion au serveur AD
$SessionAD = Test-PSRemotingConnection -ServerName "Contrôleur de domaine" -ServerIP $IpServeurAD -ServerFQDN $NomServeurAD -Cred $Credential
if (-not $SessionAD) {
    Write-Host ""
    Write-Host "❌ ÉCHEC : Impossible de se connecter au contrôleur de domaine" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

# Connexion à SRV-FICHIERS1
$SessionSRV1 = Test-PSRemotingConnection -ServerName "SRV-FICHIERS1" -ServerIP $IpServeurSRV1 -ServerFQDN $NomServeurSRV1 -Cred $Credential
if (-not $SessionSRV1) {
    Write-Host ""
    Write-Host "❌ ÉCHEC : Impossible de se connecter à SRV-FICHIERS1" -ForegroundColor Red
    if ($SessionAD) { Remove-PSSession -Session $SessionAD }
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

# Connexion à SRV-FICHIERS2
$SessionSRV2 = Test-PSRemotingConnection -ServerName "SRV-FICHIERS2" -ServerIP $IpServeurSRV2 -ServerFQDN $NomServeurSRV2 -Cred $Credential
if (-not $SessionSRV2) {
    Write-Host ""
    Write-Host "❌ ÉCHEC : Impossible de se connecter à SRV-FICHIERS2" -ForegroundColor Red
    if ($SessionAD) { Remove-PSSession -Session $SessionAD }
    if ($SessionSRV1) { Remove-PSSession -Session $SessionSRV1 }
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

# Stockage dans la portée globale
Set-Variable -Name "SessionAD" -Value $SessionAD -Scope Global -Force
Set-Variable -Name "SessionSRV1" -Value $SessionSRV1 -Scope Global -Force
Set-Variable -Name "SessionSRV2" -Value $SessionSRV2 -Scope Global -Force

Write-Host ""
Write-Host "✅ SUCCÈS : Toutes les connexions PSRemoting sont établies !" -ForegroundColor Green
Write-Host ""
Write-Host "Sessions actives :" -ForegroundColor Cyan
Write-Host "  • Contrôleur AD  : Session $($SessionAD.Id) → $NomServeurAD" -ForegroundColor White
Write-Host "  • SRV-FICHIERS1  : Session $($SessionSRV1.Id) → $NomServeurSRV1" -ForegroundColor White
Write-Host "  • SRV-FICHIERS2  : Session $($SessionSRV2.Id) → $NomServeurSRV2" -ForegroundColor White

Start-Sleep -Seconds 2
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  PHASE 2 : Démarrage des vérifications du TP" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host ""

# Logs / Score
$logMessages = @()
$note = 0
$totalPoints = 0

function Write-Log([string]$Message,[string]$Color="Gray"){
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    $global:logMessages += $line
    Write-Host $line -ForegroundColor $Color
}

Write-Log "═══════════════════════════════════════════════════" "Cyan"
Write-Log "Correction TP1 : DFS (Distributed File System)" "Cyan"
Write-Log "Domaine: $DomainDns" "Cyan"
Write-Log "Étudiant: $Prenom $Nom" "Cyan"
Write-Log "═══════════════════════════════════════════════════" "Cyan"

# =========================
# FONCTIONS DE TEST REMOTE (reprises du fichier GPO)
# =========================

function Test-RemoteStaticIP {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test IP statique sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            $ipCfg = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
            $ok = ($ipCfg.Dhcp -eq "Disabled")
            return @{ IsStatic = $ok; InterfaceAlias = $ipCfg.InterfaceAlias }
        }
        
        if ($result.IsStatic) {
            Write-Log "[OK] L'IP est configurée en statique sur $ServerName" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] L'IP n'est pas configurée en statique sur $ServerName" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'IP statique sur $ServerName : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteInternetAccess {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test accès Internet sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            $pingOk = Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet -ErrorAction SilentlyContinue
            return @{ PingOK = $pingOk }
        }
        
        if ($result.PingOK) {
            Write-Log "[OK] Accès Internet fonctionnel sur $ServerName" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Pas d'accès Internet sur $ServerName" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'accès Internet sur $ServerName : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemotePingFirewall {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test pare-feu ping sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            # Vérifier les règles de pare-feu ICMPv4
            $icmpRules = Get-NetFirewallRule | Where-Object {
                $_.Enabled -eq $true -and
                $_.Direction -eq "Inbound" -and
                ($_.DisplayName -like "*ICMP*" -or $_.DisplayName -like "*Partage*" -or $_.DisplayName -like "*echo*")
            }
            return @{ IcmpEnabled = [bool]$icmpRules }
        }
        
        if ($result.IcmpEnabled) {
            Write-Log "[OK] Pare-feu Windows autorise le ping ICMP sur $ServerName" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Pare-feu Windows bloque le ping ICMP sur $ServerName" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les règles pare-feu ICMP sur $ServerName : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteRDP {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test RDP sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            # Vérifier si RDP est activé dans le registre
            $rdpEnabled = $null
            try {
                $rdpEnabled = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
            } catch {}
            
            # Vérifier si le service TermService est en cours d'exécution
            $termService = Get-Service -Name TermService -ErrorAction SilentlyContinue
            
            # Vérifier les règles de pare-feu pour RDP
            $firewallRule = Get-NetFirewallRule -DisplayGroup "Bureau à distance" -Enabled True -ErrorAction SilentlyContinue
            
            return @{
                RdpEnabled = ($rdpEnabled -and $rdpEnabled.fDenyTSConnections -eq 0)
                ServiceRunning = ($termService -and $termService.Status -eq "Running")
                FirewallOK = [bool]$firewallRule
            }
        }
        
        $allOK = $result.RdpEnabled -and $result.ServiceRunning -and $result.FirewallOK
        
        if ($allOK) {
            Write-Log "[OK] RDP activé et configuré sur $ServerName" "Green"
            return $true
        } else {
            $issues = @()
            if (-not $result.RdpEnabled) { $issues += "RDP désactivé" }
            if (-not $result.ServiceRunning) { $issues += "Service TermService arrêté" }
            if (-not $result.FirewallOK) { $issues += "Règles pare-feu RDP désactivées" }
            
            Write-Log "[ERREUR] RDP non configuré sur $ServerName : $($issues -join ', ')" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier RDP sur $ServerName : $($_.Exception.Message)" "Red"
        return $false
    }
}

# =========================
# FONCTIONS DE TEST DFS - RÔLES ET FONCTIONNALITÉS
# =========================

function Test-RemoteDFSRolesInstalled {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test rôles DFS sur $ServerName" "Red"
        return @{ NamespaceOK = $false; ReplicationOK = $false; Score = 0 }
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            # Vérifier les rôles DFS
            $dfsNamespace = Get-WindowsFeature -Name "FS-DFS-Namespace" -ErrorAction SilentlyContinue
            $dfsReplication = Get-WindowsFeature -Name "FS-DFS-Replication" -ErrorAction SilentlyContinue
            
            return @{
                NamespaceInstalled = ($dfsNamespace -and $dfsNamespace.Installed)
                ReplicationInstalled = ($dfsReplication -and $dfsReplication.Installed)
            }
        }
        
        $score = 0
        
        if ($result.NamespaceInstalled) {
            Write-Log "[OK] Rôle 'DFS Namespaces' installé sur $ServerName" "Green"
            $score++
        } else {
            Write-Log "[ERREUR] Rôle 'DFS Namespaces' absent sur $ServerName" "Red"
        }
        
        if ($result.ReplicationInstalled) {
            Write-Log "[OK] Rôle 'DFS Replication' installé sur $ServerName" "Green"
            $score++
        } else {
            Write-Log "[ERREUR] Rôle 'DFS Replication' absent sur $ServerName" "Red"
        }
        
        return @{
            NamespaceOK = $result.NamespaceInstalled
            ReplicationOK = $result.ReplicationInstalled
            Score = $score
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les rôles DFS sur $ServerName : $($_.Exception.Message)" "Red"
        return @{ NamespaceOK = $false; ReplicationOK = $false; Score = 0 }
    }
}

function Test-RemoteDFSManagementToolsInstalled {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test outils DFS sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            # Vérifier les outils d'administration DFS
            $dfsTools = Get-WindowsFeature -Name "RSAT-DFS-Mgmt-Con" -ErrorAction SilentlyContinue
            
            return @{
                ToolsInstalled = ($dfsTools -and $dfsTools.Installed)
            }
        }
        
        if ($result.ToolsInstalled) {
            Write-Log "[OK] Outils d'administration DFS installés sur $ServerName" "Green"
            return $true
        } else {
            Write-Log "[WARNING] Outils d'administration DFS non installés sur $ServerName (optionnel)" "Yellow"
            return $false
        }
        
    } catch {
        Write-Log "[WARNING] Impossible de vérifier les outils DFS sur $ServerName" "Yellow"
        return $false
    }
}

# =========================
# FONCTIONS DE TEST DFS - DOSSIERS PARTAGÉS
# =========================

function Test-RemoteDataDriveExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$DriveLetter
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test disque sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($drive)
            
            # Vérifier que le disque existe
            $driveInfo = Get-PSDrive -Name $drive.TrimEnd(':') -ErrorAction SilentlyContinue
            
            return @{
                DriveExists = [bool]$driveInfo
                DriveType = if ($driveInfo) { $driveInfo.Provider.Name } else { $null }
            }
        } -ArgumentList $DriveLetter
        
        if ($result.DriveExists) {
            Write-Log "[OK] Disque '$DriveLetter' existe sur $ServerName" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Disque '$DriveLetter' absent sur $ServerName" "Red"
            return $false
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le disque sur $ServerName : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteSharedFolder {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$FolderPath,
        [string]$ShareName,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test dossier sur $ServerName" "Red"
        return @{ FolderExists = $false; ShareExists = $false; Score = 0 }
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($path, $share)
            
            # Test 1 : Existence du dossier physique
            $folderExists = Test-Path -Path $path -PathType Container
            
            # Test 2 : Existence du partage SMB
            $smbShare = Get-SmbShare -Name $share -ErrorAction SilentlyContinue
            $shareExists = [bool]$smbShare
            
            # Test 3 : Vérifier que le partage pointe vers le bon chemin
            $pathMatches = $false
            if ($smbShare) {
                $pathMatches = ($smbShare.Path -eq $path)
            }
            
            return @{
                FolderExists = $folderExists
                ShareExists = $shareExists
                SharePath = if ($smbShare) { $smbShare.Path } else { $null }
                PathMatches = $pathMatches
            }
        } -ArgumentList $FolderPath, $ShareName
        
        $score = 0
        
        # Vérification existence du dossier
        if ($result.FolderExists) {
            Write-Log "[OK] Dossier '$FolderPath' existe sur $ServerName ($Description)" "Green"
            $score++
        } else {
            Write-Log "[ERREUR] Dossier '$FolderPath' absent sur $ServerName ($Description)" "Red"
        }
        
        # Vérification existence du partage
        if ($result.ShareExists) {
            if ($result.PathMatches) {
                Write-Log "[OK] Partage '$ShareName' configuré correctement sur $ServerName → $FolderPath" "Green"
                $score++
            } else {
                Write-Log "[ERREUR] Partage '$ShareName' pointe vers '$($result.SharePath)' au lieu de '$FolderPath'" "Red"
            }
        } else {
            Write-Log "[ERREUR] Partage SMB '$ShareName' absent sur $ServerName" "Red"
        }
        
        return @{
            FolderExists = $result.FolderExists
            ShareExists = $result.ShareExists
            PathMatches = $result.PathMatches
            Score = $score
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le dossier partagé sur $ServerName : $($_.Exception.Message)" "Red"
        return @{ FolderExists = $false; ShareExists = $false; Score = 0 }
    }
}

function Test-RemoteAllSharedFolders {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$DataDrive,
        [hashtable[]]$ExpectedShares
    )
    
    Write-Log "`n──── Dossiers partagés sur $ServerName ────" "Yellow"
    
    # Test préalable : vérifier l'existence du disque de données
    $script:totalPoints += 1
    if (Test-RemoteDataDriveExists -Session $Session -ServerName $ServerName -DriveLetter $DataDrive) {
        $script:note += 1
    }
    
    $totalScore = 0
    $maxScore = 0
    
    foreach ($share in $ExpectedShares) {
        $maxScore += 2  # 1 point pour le dossier, 1 point pour le partage
        
        $result = Test-RemoteSharedFolder `
            -Session $Session `
            -ServerName $ServerName `
            -FolderPath $share.Path `
            -ShareName $share.Name `
            -Description $share.Description
        
        $totalScore += $result.Score
    }
    
    return @{
        Score = $totalScore
        MaxScore = $maxScore
    }
}

# =========================
# FONCTIONS DE TEST - UTILISATEURS ET GROUPES AD
# =========================

function Test-RemoteADOUExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$OUPath,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test OU sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($path)
            Import-Module ActiveDirectory -ErrorAction Stop
            $ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$path'" -ErrorAction SilentlyContinue
            return [bool]$ou
        } -ArgumentList $OUPath
        
        if ($result) {
            Write-Log "[OK] OU '$Description' existe : $OUPath" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] OU '$Description' absente : $OUPath" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'OU '$Description' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteADGroupExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$GroupName,
        [string]$OUPath,
        [string]$ExpectedScope,
        [string]$ExpectedType
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test groupe sur $ServerName" "Red"
        return @{ Exists = $false; ScopeOK = $false; TypeOK = $false; Score = 0 }
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($name, $ou, $scope, $type)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $group = Get-ADGroup -Filter "Name -eq '$name'" -SearchBase $ou -ErrorAction SilentlyContinue
            
            if ($group) {
                # Convertir les valeurs en strings
                $scopeStr = $group.GroupScope.ToString()
                $typeStr = $group.GroupCategory.ToString()
                
                return @{
                    Exists = $true
                    Scope = $scopeStr
                    Type = $typeStr
                }
            }
            return @{ Exists = $false }
        } -ArgumentList $GroupName, $OUPath, $ExpectedScope, $ExpectedType
        
        $score = 0
        
        if ($result.Exists) {
            Write-Log "[OK] Groupe '$GroupName' existe dans l'OU" "Green"
            $score++
            
            # Vérification de l'étendue (Global/DomainLocal)
            if ($result.Scope -eq $ExpectedScope) {
                Write-Log "[OK] Groupe '$GroupName' a l'étendue correcte : $ExpectedScope" "Green"
            } else {
                Write-Log "[ERREUR] Groupe '$GroupName' a l'étendue '$($result.Scope)' au lieu de '$ExpectedScope'" "Red"
            }
            
            # Vérification du type (Security/Distribution)
            if ($result.Type -eq $ExpectedType) {
                Write-Log "[OK] Groupe '$GroupName' a le type correct : $ExpectedType" "Green"
            } else {
                Write-Log "[ERREUR] Groupe '$GroupName' a le type '$($result.Type)' au lieu de '$ExpectedType'" "Red"
            }
        } else {
            Write-Log "[ERREUR] Groupe '$GroupName' absent de l'OU" "Red"
        }
        
        return @{
            Exists = $result.Exists
            ScopeOK = ($result.Scope -eq $ExpectedScope)
            TypeOK = ($result.Type -eq $ExpectedType)
            Score = $score
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le groupe '$GroupName' : $($_.Exception.Message)" "Red"
        return @{ Exists = $false; ScopeOK = $false; TypeOK = $false; Score = 0 }
    }
}

function Test-RemoteADUserExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$Username,
        [string]$OUPath
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test utilisateur sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($login, $ou)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $user = Get-ADUser -Filter "SamAccountName -eq '$login'" -SearchBase $ou -ErrorAction SilentlyContinue
            
            if ($user) {
                return @{
                    Exists = $true
                    Name = $user.Name
                    Enabled = $user.Enabled
                }
            }
            return @{ Exists = $false }
        } -ArgumentList $Username, $OUPath
        
        if ($result.Exists) {
            if ($result.Enabled) {
                Write-Log "[OK] Utilisateur '$Username' ($($result.Name)) existe et est activé" "Green"
                return $true
            } else {
                Write-Log "[ERREUR] Utilisateur '$Username' existe mais est DÉSACTIVÉ" "Red"
                return $false
            }
        } else {
            Write-Log "[ERREUR] Utilisateur '$Username' absent de l'OU" "Red"
            return $false
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'utilisateur '$Username' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteADGroupMembership {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$ParentGroupName,
        [string]$MemberGroupName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test appartenance groupe sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($parent, $member)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $parentGroup = Get-ADGroup -Filter "Name -eq '$parent'" -ErrorAction SilentlyContinue
            if (-not $parentGroup) {
                return @{ IsMember = $false; Error = "Groupe parent inexistant" }
            }
            
            $members = Get-ADGroupMember -Identity $parent -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            $isMember = $members -contains $member
            
            return @{
                IsMember = $isMember
                Members = $members
            }
        } -ArgumentList $ParentGroupName, $MemberGroupName
        
        if ($result.Error) {
            Write-Log "[ERREUR] Test appartenance : $($result.Error)" "Red"
            return $false
        }
        
        if ($result.IsMember) {
            Write-Log "[OK] Groupe '$MemberGroupName' est membre de '$ParentGroupName' (AGDLP)" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Groupe '$MemberGroupName' n'est PAS membre de '$ParentGroupName'" "Red"
            return $false
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'appartenance : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteADUserGroupMembership {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$Username,
        [string]$GroupName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test appartenance utilisateur sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($user, $group)
            Import-Module ActiveDirectory -ErrorAction Stop
            
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue
            if (-not $adUser) {
                return @{ IsMember = $false; Error = "Utilisateur inexistant" }
            }
            
            $groups = Get-ADUser -Identity $user -Properties MemberOf | Select-Object -ExpandProperty MemberOf
            $isMember = $groups | Where-Object { $_ -like "*CN=$group,*" }
            
            return @{
                IsMember = [bool]$isMember
            }
        } -ArgumentList $Username, $GroupName
        
        if ($result.Error) {
            Write-Log "[ERREUR] Test appartenance utilisateur : $($result.Error)" "Red"
            return $false
        }
        
        if ($result.IsMember) {
            Write-Log "[OK] Utilisateur '$Username' est membre du groupe '$GroupName'" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Utilisateur '$Username' n'est PAS membre du groupe '$GroupName'" "Red"
            return $false
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'appartenance utilisateur : $($_.Exception.Message)" "Red"
        return $false
    }
}

# =========================
# FONCTIONS DE TEST - PERMISSIONS NTFS
# =========================

function Test-RemoteNTFSPermissions {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ServerName,
        [string]$FolderPath,
        [string]$GroupName,
        [string]$ExpectedRight,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test NTFS sur $ServerName" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($path, $group, $right)
            
            if (-not (Test-Path $path)) {
                return @{ HasPermission = $false; Error = "Dossier inexistant"; Group = $group }
            }
            
            $acl = Get-Acl -Path $path
            
            # Chercher le groupe dans les permissions (support multi-formats)
            # Liste de tous les identifiants possibles pour debug
            $allIdentities = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
            
            $permissions = $acl.Access | Where-Object { 
                $identity = $_.IdentityReference.Value
                # Recherche flexible
                $identity -like "*$group*" -or 
                $identity -like "*$group" -or
                $identity -eq $group -or
                # Pour les groupes built-in en français/anglais
                ($group -eq "Authenticated Users" -and ($identity -like "*Utilisateurs authentifiés*" -or $identity -like "*Authenticated Users*")) -or
                ($group -eq "Utilisateurs authentifiés" -and ($identity -like "*Utilisateurs authentifiés*" -or $identity -like "*Authenticated Users*"))
            }
            
            if (-not $permissions) {
                return @{ 
                    HasPermission = $false
                    Error = "Groupe '$group' n'a aucune permission"
                    Group = $group
                    AllIdentities = ($allIdentities -join ", ")
                }
            }
            
            # Vérifier le droit attendu
            $hasRight = $false
            foreach ($perm in $permissions) {
                $rightsStr = $perm.FileSystemRights.ToString()
                if ($rightsStr -like "*$right*" -or $right -eq "Any") {
                    $hasRight = $true
                    break
                }
            }
            
            return @{
                HasPermission = $hasRight
                ActualRights = ($permissions | ForEach-Object { $_.FileSystemRights.ToString() }) -join ", "
                Group = $group
            }
        } -ArgumentList $FolderPath, $GroupName, $ExpectedRight
        
        if ($result.Error) {
            Write-Log "[ERREUR] Permissions NTFS '$Description' : $($result.Error)" "Red"
            if ($result.AllIdentities) {
                Write-Log "[INFO] Groupes trouvés dans les ACL : $($result.AllIdentities)" "Gray"
            }
            return $false
        }
        
        if ($result.HasPermission) {
            Write-Log "[OK] Groupe '$GroupName' a les permissions '$ExpectedRight' sur '$Description'" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Groupe '$GroupName' n'a PAS les permissions '$ExpectedRight' sur '$Description' (droits actuels : $($result.ActualRights))" "Red"
            return $false
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les permissions NTFS pour '$GroupName' : $($_.Exception.Message)" "Red"
        return $false
    }
}

# =========================
# TESTS - PHASE 2 : Configuration réseau de base
# =========================

Write-Log "`n──── Configuration réseau sur Contrôleur de domaine ────" "Yellow"

$totalPoints += 1
if (Test-RemoteStaticIP -Session $global:SessionAD -ServerName "Contrôleur de domaine") { $note += 1 }

$totalPoints += 1
if (Test-RemoteInternetAccess -Session $global:SessionAD -ServerName "Contrôleur de domaine") { $note += 1 }

$totalPoints += 1
if (Test-RemotePingFirewall -Session $global:SessionAD -ServerName "Contrôleur de domaine") { $note += 1 }

$totalPoints += 1
if (Test-RemoteRDP -Session $global:SessionAD -ServerName "Contrôleur de domaine") { $note += 1 }

Write-Log "`n──── Configuration réseau sur SRV-FICHIERS1 ────" "Yellow"

$totalPoints += 1
if (Test-RemoteStaticIP -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1") { $note += 1 }

$totalPoints += 1
if (Test-RemoteInternetAccess -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1") { $note += 1 }

$totalPoints += 1
if (Test-RemotePingFirewall -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1") { $note += 1 }

$totalPoints += 1
if (Test-RemoteRDP -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1") { $note += 1 }

Write-Log "`n──── Configuration réseau sur SRV-FICHIERS2 ────" "Yellow"

$totalPoints += 1
if (Test-RemoteStaticIP -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2") { $note += 1 }

$totalPoints += 1
if (Test-RemoteInternetAccess -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2") { $note += 1 }

$totalPoints += 1
if (Test-RemotePingFirewall -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2") { $note += 1 }

$totalPoints += 1
if (Test-RemoteRDP -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2") { $note += 1 }

# =========================
# TESTS - PHASE 3 : Rôles DFS
# =========================

Write-Log "`n──── Rôles DFS sur SRV-FICHIERS1 ────" "Yellow"

$totalPoints += 2
$resultSRV1Roles = Test-RemoteDFSRolesInstalled -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1"
$note += $resultSRV1Roles.Score

# Bonus pour les outils (non obligatoire, pas de points)
Test-RemoteDFSManagementToolsInstalled -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" | Out-Null

Write-Log "`n──── Rôles DFS sur SRV-FICHIERS2 ────" "Yellow"

$totalPoints += 2
$resultSRV2Roles = Test-RemoteDFSRolesInstalled -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2"
$note += $resultSRV2Roles.Score

# Bonus pour les outils (non obligatoire, pas de points)
Test-RemoteDFSManagementToolsInstalled -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" | Out-Null

# =========================
# TESTS - PHASE 4 : Vérification des dossiers partagés
# =========================

# Définition des dossiers attendus selon le TP
# Chemin de base : E:\DFS-Data (ou autre disque selon saisie utilisateur)

$basePath = "$DataDrive\DFS-Data"

# Sur SRV-FICHIERS1
$expectedSharesSRV1 = @(
    @{ Path = "$basePath\Ligues"; Name = "Ligues$"; Description = "Dossier Ligues" },
    @{ Path = "$basePath\Ligues\Football"; Name = "Football$"; Description = "Dossier Football" },
    @{ Path = "$basePath\Ligues\Basketball"; Name = "Basketball$"; Description = "Dossier Basketball" },
    @{ Path = "$basePath\Ligues\Tennis"; Name = "Tennis$"; Description = "Dossier Tennis" },
    @{ Path = "$basePath\Commun"; Name = "Commun$"; Description = "Dossier Commun" },
    @{ Path = "$basePath\Administration"; Name = "Administration$"; Description = "Dossier Administration" }
)

$resultSRV1Shares = Test-RemoteAllSharedFolders `
    -Session $global:SessionSRV1 `
    -ServerName "SRV-FICHIERS1" `
    -DataDrive $DataDrive `
    -ExpectedShares $expectedSharesSRV1

$totalPoints += $resultSRV1Shares.MaxScore
$note += $resultSRV1Shares.Score

# Sur SRV-FICHIERS2
$expectedSharesSRV2 = @(
    @{ Path = "$basePath\Ligues"; Name = "Ligues$"; Description = "Dossier Ligues (répliqué)" },
    @{ Path = "$basePath\Ligues\Football"; Name = "Football$"; Description = "Dossier Football (répliqué)" },
    @{ Path = "$basePath\Ligues\Basketball"; Name = "Basketball$"; Description = "Dossier Basketball (répliqué)" },
    @{ Path = "$basePath\Ligues\Tennis"; Name = "Tennis$"; Description = "Dossier Tennis (répliqué)" },
    @{ Path = "$basePath\Commun"; Name = "Commun$"; Description = "Dossier Commun (répliqué)" },
    @{ Path = "$basePath\Administration"; Name = "Administration$"; Description = "Dossier Administration (répliqué)" }
)

$resultSRV2Shares = Test-RemoteAllSharedFolders `
    -Session $global:SessionSRV2 `
    -ServerName "SRV-FICHIERS2" `
    -DataDrive $DataDrive `
    -ExpectedShares $expectedSharesSRV2

$totalPoints += $resultSRV2Shares.MaxScore
$note += $resultSRV2Shares.Score

# =========================
# TESTS - PHASE 5 : Vérification Active Directory (OUs, Groupes, Utilisateurs)
# =========================

Write-Log "`n──── Structure Active Directory ────" "Yellow"

# OUs
$OURacine = "OU=@$DomainDns,$DomainDN"
$OUUtilisateurs = "OU=Utilisateurs,$OURacine"
$OUGroupes = "OU=Groupes,$OURacine"
$OUOrdinateurs = "OU=Ordinateurs,$OURacine"

$totalPoints += 1
if (Test-RemoteADOUExists -Session $global:SessionAD -ServerName "DC" -OUPath $OURacine -Description "OU Racine @$DomainDns") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADOUExists -Session $global:SessionAD -ServerName "DC" -OUPath $OUUtilisateurs -Description "OU Utilisateurs") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADOUExists -Session $global:SessionAD -ServerName "DC" -OUPath $OUGroupes -Description "OU Groupes") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADOUExists -Session $global:SessionAD -ServerName "DC" -OUPath $OUOrdinateurs -Description "OU Ordinateurs") { $note += 1 }

Write-Log "`n──── Groupes de sécurité AD ────" "Yellow"

# Groupes Globaux (GG)
$totalPoints += 1
$resGG1 = Test-RemoteADGroupExists -Session $global:SessionAD -ServerName "DC" -GroupName "GG-Ligues-Admins" -OUPath $OUGroupes -ExpectedScope "Global" -ExpectedType "Security"
$note += $resGG1.Score

$totalPoints += 1
$resGG2 = Test-RemoteADGroupExists -Session $global:SessionAD -ServerName "DC" -GroupName "GG-Ligues-Utilisateurs" -OUPath $OUGroupes -ExpectedScope "Global" -ExpectedType "Security"
$note += $resGG2.Score

# Groupes Domaine Local (DL)
$totalPoints += 1
$resDL1 = Test-RemoteADGroupExists -Session $global:SessionAD -ServerName "DC" -GroupName "DL-Ligues-Full" -OUPath $OUGroupes -ExpectedScope "DomainLocal" -ExpectedType "Security"
$note += $resDL1.Score

$totalPoints += 1
$resDL2 = Test-RemoteADGroupExists -Session $global:SessionAD -ServerName "DC" -GroupName "DL-Ligues-Read" -OUPath $OUGroupes -ExpectedScope "DomainLocal" -ExpectedType "Security"
$note += $resDL2.Score

$totalPoints += 1
$resDL3 = Test-RemoteADGroupExists -Session $global:SessionAD -ServerName "DC" -GroupName "DL-Administration-Full" -OUPath $OUGroupes -ExpectedScope "DomainLocal" -ExpectedType "Security"
$note += $resDL3.Score

Write-Log "`n──── Modèle AGDLP (GG → DL) ────" "Yellow"

# Vérifier que les groupes globaux sont dans les groupes domaine local
$totalPoints += 1
if (Test-RemoteADGroupMembership -Session $global:SessionAD -ServerName "DC" -ParentGroupName "DL-Ligues-Full" -MemberGroupName "GG-Ligues-Admins") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADGroupMembership -Session $global:SessionAD -ServerName "DC" -ParentGroupName "DL-Ligues-Read" -MemberGroupName "GG-Ligues-Utilisateurs") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADGroupMembership -Session $global:SessionAD -ServerName "DC" -ParentGroupName "DL-Administration-Full" -MemberGroupName "GG-Ligues-Admins") { $note += 1 }

Write-Log "`n──── Utilisateurs de test ────" "Yellow"

# Utilisateurs
$expectedUsers = @("admin.football", "admin.basket", "user.football", "user.basket")

foreach ($user in $expectedUsers) {
    $totalPoints += 1
    if (Test-RemoteADUserExists -Session $global:SessionAD -ServerName "DC" -Username $user -OUPath $OUUtilisateurs) { $note += 1 }
}

Write-Log "`n──── Appartenance utilisateurs aux groupes ────" "Yellow"

# Vérifier que les admins sont dans GG-Ligues-Admins
$totalPoints += 1
if (Test-RemoteADUserGroupMembership -Session $global:SessionAD -ServerName "DC" -Username "admin.football" -GroupName "GG-Ligues-Admins") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADUserGroupMembership -Session $global:SessionAD -ServerName "DC" -Username "admin.basket" -GroupName "GG-Ligues-Admins") { $note += 1 }

# Vérifier que les users sont dans GG-Ligues-Utilisateurs
$totalPoints += 1
if (Test-RemoteADUserGroupMembership -Session $global:SessionAD -ServerName "DC" -Username "user.football" -GroupName "GG-Ligues-Utilisateurs") { $note += 1 }

$totalPoints += 1
if (Test-RemoteADUserGroupMembership -Session $global:SessionAD -ServerName "DC" -Username "user.basket" -GroupName "GG-Ligues-Utilisateurs") { $note += 1 }

# =========================
# TESTS - PHASE 6 : Vérification des permissions NTFS
# =========================

Write-Log "`n──── Permissions NTFS sur SRV-FICHIERS1 ────" "Yellow"

# Permissions sur Ligues
$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" -FolderPath "$basePath\Ligues" -GroupName "DL-Ligues-Full" -ExpectedRight "FullControl" -Description "Ligues") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" -FolderPath "$basePath\Ligues" -GroupName "DL-Ligues-Read" -ExpectedRight "Read" -Description "Ligues") { $note += 1 }

# Permissions sur Administration
$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" -FolderPath "$basePath\Administration" -GroupName "DL-Administration-Full" -ExpectedRight "FullControl" -Description "Administration") { $note += 1 }

# Permissions sur Commun (DL-Ligues-Full en contrôle total + Utilisateurs authentifiés en lecture/exécution)
$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" -FolderPath "$basePath\Commun" -GroupName "DL-Ligues-Full" -ExpectedRight "FullControl" -Description "Commun") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV1 -ServerName "SRV-FICHIERS1" -FolderPath "$basePath\Commun" -GroupName "Authenticated Users" -ExpectedRight "ReadAndExecute" -Description "Commun") { $note += 1 }

Write-Log "`n──── Permissions NTFS sur SRV-FICHIERS2 ────" "Yellow"

# Même chose sur SRV-FICHIERS2
$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" -FolderPath "$basePath\Ligues" -GroupName "DL-Ligues-Full" -ExpectedRight "FullControl" -Description "Ligues") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" -FolderPath "$basePath\Ligues" -GroupName "DL-Ligues-Read" -ExpectedRight "Read" -Description "Ligues") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" -FolderPath "$basePath\Administration" -GroupName "DL-Administration-Full" -ExpectedRight "FullControl" -Description "Administration") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" -FolderPath "$basePath\Commun" -GroupName "DL-Ligues-Full" -ExpectedRight "FullControl" -Description "Commun") { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTFSPermissions -Session $global:SessionSRV2 -ServerName "SRV-FICHIERS2" -FolderPath "$basePath\Commun" -GroupName "Authenticated Users" -ExpectedRight "ReadAndExecute" -Description "Commun") { $note += 1 }

# =========================
# Calcul / JSON / Affichage / Envoi
# =========================
function Show-And-Send-Result {
    param(
        [string]$Nom,
        [string]$Prenom,
        [double]$Note,
        [int]$Total,
        [array]$Logs,
        [string]$DomainDns
    )
    
    $scoreSur20 = if ($Total -gt 0) { [math]::Round(($Note / $Total) * 20, 2) } else { 0 }
    $pourcentage = if ($Total -gt 0) { [math]::Round(100 * $Note / $Total, 1) } else { 0 }
    
    # Chemin vers le bureau de l'utilisateur
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $jsonFile = Join-Path $desktopPath "DFS_TP1-$Nom-$Prenom.json"
    $payload = [ordered]@{
        status       = "OK"
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        nom          = $Nom
        prenom       = $Prenom
        tp           = "TP Guidé 1 - DFS"
        domaine      = $DomainDns
        score        = $Note
        total        = $Total
        note         = $scoreSur20
        commentaires = ($Logs -join "`n")
    } | ConvertTo-Json -Depth 4
    
    $payload | Set-Content -Path $jsonFile -Encoding UTF8
    Write-Host ""
    Write-Host "✅ Fichier JSON généré : $jsonFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           RÉSULTAT FINAL" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ("TP         : TP Guidé 1 - DFS") -ForegroundColor White
    Write-Host ("Étudiant   : $Prenom $Nom") -ForegroundColor White
    Write-Host ("Domaine    : $DomainDns") -ForegroundColor White
    Write-Host ("Points     : {0} / {1}" -f $Note, $Total) -ForegroundColor Cyan
    Write-Host ("Note       : {0} / 20" -f $scoreSur20) -ForegroundColor Cyan
    Write-Host ("Pourcentage: {0}%" -f $pourcentage) -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════" -ForegroundColor Cyan
    
    # Envoi optionnel
    $serverUrl = "http://www.ericm.fr/logsapi/logreceiver.php?filename=DFS_TP1-$Nom-$Prenom.json"
    try {
        Invoke-RestMethod -Uri $serverUrl -Method Post -Body $payload -ContentType "application/json; charset=utf-8"
        Write-Host "✅ Fichier JSON envoyé avec succès au serveur !" -ForegroundColor Green
    } catch {
        Write-Host "❌ Erreur lors de l'envoi du JSON : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Show-And-Send-Result -Nom $Nom -Prenom $Prenom -Note $note -Total $totalPoints -Logs $logMessages -DomainDns $DomainDns

# =========================
# Nettoyage : Fermeture des sessions PSRemoting
# =========================
Write-Host ""
Write-Host "Fermeture des sessions PSRemoting..." -ForegroundColor Gray
if ($global:SessionAD) { Remove-PSSession -Session $global:SessionAD }
if ($global:SessionSRV1) { Remove-PSSession -Session $global:SessionSRV1 }
if ($global:SessionSRV2) { Remove-PSSession -Session $global:SessionSRV2 }
Write-Log "[OK] Sessions fermées" "Green"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "RAPPEL - Points de vérification :" -ForegroundColor Yellow
Write-Host "  ✓ Configuration réseau (IP statique, Internet, Pare-feu, RDP)" -ForegroundColor White
Write-Host "  ✓ Rôles DFS installés sur les deux serveurs" -ForegroundColor White
Write-Host "  ✓ Disque de données présent" -ForegroundColor White
Write-Host "  ✓ Dossiers partagés créés et configurés" -ForegroundColor White
Write-Host "  ✓ Structure AD (OUs, Groupes, Utilisateurs)" -ForegroundColor White
Write-Host "  ✓ Modèle AGDLP respecté" -ForegroundColor White
Write-Host "  ✓ Permissions NTFS configurées" -ForegroundColor White
Write-Host "  ✓ Espace de noms DFS configuré (non testé)" -ForegroundColor White
Write-Host "  ✓ Réplication DFS active entre les serveurs (non testé)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nAppuyez sur Entrée pour quitter..." -ForegroundColor Gray
Read-Host
