# =========================
# Script de correction - TP1 : GPO Sécurité et Verrouillage
# Exécution depuis un poste CLIENT Windows joint au domaine
# VERSION AVEC PSREMOTING
# =========================

# =========================
# En-tête / Inputs
# =========================
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Script de vérification TP1 - GPO Sécurité" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$Nom            = Read-Host "Entrez votre nom"
$Prenom         = Read-Host "Entrez votre prénom"
$Domain         = Read-Host "Entrez le nom du domaine (FQDN ex: prenom.lan)"
$ServeurDC      = Read-Host "Entrez le nom ou l'IP du contrôleur de domaine (ex: SRV2019)"
$LettreDisqueSup= Read-Host "Entrez la lettre du disque supplémentaire (E: par défaut)"
if (-not $LettreDisqueSup) { $LettreDisqueSup = "E:" }

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
# Demande des credentials administrateur
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  Authentification administrateur du domaine" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""
Write-Host "Ces identifiants seront utilisés pour se connecter au DC via PSRemoting" -ForegroundColor Gray
Write-Host "Format accepté : Administrateur  OU  $DomainNetBios\Administrateur" -ForegroundColor Gray
Write-Host ""

$AdminUser = Read-Host "Login administrateur"
$AdminPassword = Read-Host "Mot de passe" -AsSecureString

# Construction du credential
if ($AdminUser -notmatch '\\|@') {
    $AdminUser = "$DomainNetBios\$AdminUser"
}

$Credential = New-Object System.Management.Automation.PSCredential($AdminUser, $AdminPassword)

# =========================
# Test IMMÉDIAT de connexion PSRemoting
# =========================
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Test de connexion PSRemoting vers $ServeurDC" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Test 1 : Ping
Write-Host "[1/3] Test de connectivité réseau (ping)..." -ForegroundColor Gray
if (-not (Test-Connection -ComputerName $ServeurDC -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
    Write-Host "❌ ERREUR : Le serveur $ServeurDC ne répond pas au ping" -ForegroundColor Red
    Write-Host ""
    Write-Host "Vérifications :" -ForegroundColor Yellow
    Write-Host "  • Le serveur DC est allumé" -ForegroundColor White
    Write-Host "  • Le nom/IP du DC est correct" -ForegroundColor White
    Write-Host "  • Le réseau fonctionne" -ForegroundColor White
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}
Write-Host "      ✓ Le serveur répond au ping" -ForegroundColor Green

# Test 2 : Port WinRM (5985)
Write-Host "[2/3] Test du port WinRM (5985)..." -ForegroundColor Gray
$portTest = Test-NetConnection -ComputerName $ServeurDC -Port 5985 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -InformationLevel Quiet
if (-not $portTest) {
    Write-Host "❌ ERREUR : Le port WinRM (5985) n'est pas accessible sur $ServeurDC" -ForegroundColor Red
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  SOLUTION : Activer PSRemoting sur le DC" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Sur le serveur DC ($ServeurDC), ouvrez PowerShell en administrateur et exécutez :" -ForegroundColor White
    Write-Host ""
    Write-Host "    Enable-PSRemoting -Force" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Cette commande va :" -ForegroundColor Gray
    Write-Host "  • Démarrer le service WinRM" -ForegroundColor Gray
    Write-Host "  • Configurer les règles de pare-feu" -ForegroundColor Gray
    Write-Host "  • Autoriser les connexions distantes" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Une fois fait, relancez ce script." -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}
Write-Host "      ✓ Port WinRM accessible" -ForegroundColor Green

# Test 3 : Authentification et création de session
Write-Host "[3/3] Test d'authentification et création de session..." -ForegroundColor Gray
try {
    $DCSession = New-PSSession -ComputerName $ServeurDC -Credential $Credential -ErrorAction Stop
    
    # Stockage FORCÉ dans la portée globale
    Set-Variable -Name "DCSession" -Value $DCSession -Scope Global -Force
    
    Write-Host "      ✓ Session PSRemoting établie avec succès" -ForegroundColor Green
    Write-Host "        SessionID: $($DCSession.Id) | État: $($DCSession.State)" -ForegroundColor DarkGray
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
        Write-Host "  • Le login est correct (ex: Administrateur ou $DomainNetBios\Administrateur)" -ForegroundColor White
        Write-Host "  • Le mot de passe est correct" -ForegroundColor White
        Write-Host "  • Le compte a les droits d'administrateur du domaine" -ForegroundColor White
    } elseif ($_.Exception.Message -like "*WinRM*") {
        Write-Host "Cause probable : Configuration WinRM incomplète" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Sur le DC, exécutez :" -ForegroundColor Yellow
        Write-Host "  Enable-PSRemoting -Force" -ForegroundColor Cyan
        Write-Host "  Set-Item WSMan:\localhost\Client\TrustedHosts * -Force" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

Write-Host ""
Write-Host "✅ Connexion PSRemoting réussie ! Démarrage des vérifications..." -ForegroundColor Green

# TEST IMMÉDIAT : vérifier que la variable est bien accessible
Write-Host ""
Write-Host "[DEBUG] Test de la variable globale..." -ForegroundColor DarkGray
$testSession = Get-Variable -Name "DCSession" -Scope Global -ErrorAction SilentlyContinue
if ($testSession -and $testSession.Value) {
    Write-Host "[DEBUG] ✓ Variable `$global:DCSession accessible (ID: $($testSession.Value.Id))" -ForegroundColor DarkGray
} else {
    Write-Host "[DEBUG] ✗ PROBLÈME : Variable `$global:DCSession est NULL !" -ForegroundColor Red
    Write-Host ""
    Write-Host "Tentative de correction..." -ForegroundColor Yellow
    Set-Variable -Name "DCSession" -Value $DCSession -Scope Global -Force
    $testSession = Get-Variable -Name "DCSession" -Scope Global -ErrorAction SilentlyContinue
    if ($testSession -and $testSession.Value) {
        Write-Host "✓ Variable corrigée" -ForegroundColor Green
    } else {
        Write-Host "✗ Impossible de corriger - Le script va échouer" -ForegroundColor Red
        Read-Host "Appuyez sur Entrée"
        exit 1
    }
}

Start-Sleep -Seconds 2
Write-Host ""

# Variables spécifiques au TP1
$OURacine = "OU=@$DomainDns,$DomainDN"
$OUUtilisateurs = "OU=Utilisateurs,$OURacine"
$OUEtudiants = "OU=Etudiants,$OUUtilisateurs"
$UserLogin = "jdupont"
$UserFullName = "Jean Dupont"
$GPOName = "GPO_Secu_Verrouillage"
$ShareName = "Wallpapers"
$WallpaperUNC = "\\$ServeurDC\$ShareName\wallpaper_m2l.jpg"

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
Write-Log "Correction TP1 : GPO Sécurité et Verrouillage" "Cyan"
Write-Log "Domaine: $DomainDns" "Cyan"
Write-Log "Étudiant: $Prenom $Nom" "Cyan"
Write-Log "Contrôleur de domaine: $ServeurDC" "Cyan"
Write-Log "═══════════════════════════════════════════════════" "Cyan"

# Vérification que la session PSRemoting est toujours active
if (-not $global:DCSession) {
    Write-Host ""
    Write-Host "❌ ERREUR CRITIQUE : La session PSRemoting n'est pas disponible !" -ForegroundColor Red
    Write-Host "La variable `$global:DCSession est NULL" -ForegroundColor Red
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

if ($global:DCSession.State -ne "Opened") {
    Write-Host ""
    Write-Host "❌ ERREUR CRITIQUE : La session PSRemoting n'est pas ouverte !" -ForegroundColor Red
    Write-Host "État de la session : $($global:DCSession.State)" -ForegroundColor Red
    Write-Host ""
    Read-Host "Appuyez sur Entrée pour quitter"
    exit 1
}

Write-Log "[INFO] Session PSRemoting active (ID: $($global:DCSession.Id))" "Gray"

# =========================
# Vérification préalable : Client joint au domaine
# =========================

function Test-ClientDomainJoined {
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $partOfDomain = $computerSystem.PartOfDomain
    $currentDomain = $computerSystem.Domain
    
    if (-not $partOfDomain) {
        Write-Log "[ERREUR] Ce poste n'est PAS joint à un domaine." "Red"
        return $false
    }
    
    if ($currentDomain -ine $DomainDns) {
        Write-Log "[WARNING] Ce poste est joint au domaine '$currentDomain' au lieu de '$DomainDns'." "Yellow"
    } else {
        Write-Log "[OK] Poste joint au domaine '$DomainDns'." "Green"
    }
    
    return $true
}

# =========================
# Fonctions de test REMOTE (sur le DC)
# =========================

function Test-RemoteOUExists {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$OUPath, 
        [string]$Description
    )
    
    try {
        $ou = Invoke-Command -Session $Session -ScriptBlock {
            param($OUPath)
            Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue
        } -ArgumentList $OUPath -ErrorAction Stop
        
        $ok = [bool]$ou
        if ($ok) { 
            Write-Log "[OK] OU '$Description' existe sur DC : $OUPath" "Green" 
        } else { 
            Write-Log "[ERREUR] OU '$Description' absente sur DC : $OUPath" "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'OU '$Description' sur DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteUserExists {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$Login, 
        [string]$FullName, 
        [string]$OUPath
    )
    
    try {
        $user = Invoke-Command -Session $Session -ScriptBlock {
            param($Login, $OUPath)
            Get-ADUser -Filter "SamAccountName -eq '$Login'" -SearchBase $OUPath -Properties DisplayName -ErrorAction SilentlyContinue
        } -ArgumentList $Login, $OUPath -ErrorAction Stop
        
        if (-not $user) {
            Write-Log "[ERREUR] Utilisateur '$Login' absent dans $OUPath sur DC" "Red"
            return $false
        }
        
        Write-Log "[OK] Utilisateur '$Login' ($($user.DisplayName)) existe dans $OUPath" "Green"
        return $true
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'utilisateur '$Login' sur DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteFolderExists {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$Path
    )
    
    try {
        $exists = Invoke-Command -Session $Session -ScriptBlock {
            param($Path)
            Test-Path -Path $Path -PathType Container
        } -ArgumentList $Path -ErrorAction Stop
        
        if ($exists) {
            Write-Log "[OK] Dossier existe sur DC : $Path" "Green"
        } else {
            Write-Log "[ERREUR] Dossier absent sur DC : $Path" "Red"
        }
        return $exists
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le dossier '$Path' sur DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteShareExists {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ShareName, 
        [string]$ExpectedPath
    )
    
    try {
        $share = Invoke-Command -Session $Session -ScriptBlock {
            param($ShareName)
            Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
        } -ArgumentList $ShareName -ErrorAction Stop
        
        if (-not $share) {
            Write-Log "[ERREUR] Partage '$ShareName' inexistant sur DC" "Red"
            return $false
        }
        
        if ($share.Path -ne $ExpectedPath) {
            Write-Log "[ERREUR] Partage '$ShareName' pointe vers '$($share.Path)' au lieu de '$ExpectedPath'" "Red"
            return $false
        }
        
        Write-Log "[OK] Partage '$ShareName' existe et pointe vers '$ExpectedPath'" "Green"
        return $true
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le partage '$ShareName' sur DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteSharePermission {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ShareName, 
        [string]$Identity, 
        [string]$AccessRight
    )
    
    try {
        $permissions = Invoke-Command -Session $Session -ScriptBlock {
            param($ShareName)
            Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue
        } -ArgumentList $ShareName -ErrorAction Stop
        
        # Recherche de la permission pour "Tout le monde" ou "Everyone"
        $permission = $permissions | Where-Object { 
            ($_.AccountName -eq "Everyone" -or $_.AccountName -eq "Tout le monde") -and 
            ($_.AccessRight -eq $AccessRight -or 
             ($AccessRight -eq "Full" -and $_.AccessRight -eq "Full"))
        }
        
        if ($permission) {
            Write-Log "[OK] Permission de partage '$AccessRight' pour 'Tout le monde' sur '$ShareName'" "Green"
            return $true
        } else {
            # Vérifier si "Tout le monde" a au moins des permissions
            $anyPermission = $permissions | Where-Object { 
                $_.AccountName -eq "Everyone" -or $_.AccountName -eq "Tout le monde"
            }
            if ($anyPermission) {
                Write-Log "[OK] Permission de partage '$($anyPermission.AccessRight)' pour 'Tout le monde' sur '$ShareName'" "Green"
                return $true
            } else {
                Write-Log "[ERREUR] Aucune permission de partage pour 'Tout le monde' sur '$ShareName'" "Red"
                return $false
            }
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les permissions du partage '$ShareName' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteNTFSPermission {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$Path,
        [string]$Identity = "Everyone",
        [string]$Rights = "Read"
    )
    
    try {
        $hasPermission = Invoke-Command -Session $Session -ScriptBlock {
            param($Path, $Identity, $Rights)
            
            if (-not (Test-Path $Path)) {
                return $false
            }
            
            $acl = Get-Acl -Path $Path
            
            # Recherche de la permission (héritée OU explicite)
            $permission = $acl.Access | Where-Object {
                ($_.IdentityReference -like "*Everyone*" -or 
                 $_.IdentityReference -like "*Tout le monde*" -or
                 $_.IdentityReference -like "*Utilisateurs*" -or
                 $_.IdentityReference -like "*Users*") -and
                $_.FileSystemRights -match $Rights -and
                $_.AccessControlType -eq "Allow"
                # SUPPRESSION du test IsInherited pour accepter héritées
            }
            
            return [bool]$permission
            
        } -ArgumentList $Path, $Identity, $Rights -ErrorAction Stop
        
        if ($hasPermission) {
            Write-Log "[OK] Permission NTFS '$Rights' pour 'Utilisateurs/Tout le monde' sur '$Path'" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] Permission NTFS '$Rights' pour 'Utilisateurs/Tout le monde' absente sur '$Path'" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les permissions NTFS sur '$Path' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOExists {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName
    )
    
    try {
        $gpo = Invoke-Command -Session $Session -ScriptBlock {
            param($GPOName)
            Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        } -ArgumentList $GPOName -ErrorAction Stop
        
        if ($gpo) {
            Write-Log "[OK] GPO '$GPOName' existe sur DC" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] GPO '$GPOName' inexistante sur DC" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la GPO '$GPOName' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOLinkedToOU {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName, 
        [string]$OUPath
    )
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($OUPath, $GPOName)
            
            $links = Get-GPInheritance -Target $OUPath -ErrorAction SilentlyContinue
            
            if (-not $links) {
                return @{
                    Found = $false
                    Error = "Impossible de récupérer les GPO liées"
                }
            }
            
            # Chercher la GPO dans les liens
            $isLinked = $links.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
            
            # Récupérer les noms de toutes les GPO liées pour diagnostic
            $allLinkedGPOs = $links.GpoLinks | Select-Object -ExpandProperty DisplayName
            
            return @{
                Found = [bool]$isLinked
                LinkedGPOs = $allLinkedGPOs
                LinkEnabled = if ($isLinked) { $isLinked.Enabled } else { $null }
                LinkEnforced = if ($isLinked) { $isLinked.Enforced } else { $null }
            }
            
        } -ArgumentList $OUPath, $GPOName -ErrorAction Stop
        
        if ($result.Found) {
            Write-Log "[OK] GPO '$GPOName' est liée à l'OU (Enabled: $($result.LinkEnabled), Enforced: $($result.LinkEnforced))" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] GPO '$GPOName' n'est PAS liée à l'OU '$OUPath'" "Red"
            if ($result.LinkedGPOs) {
                Write-Log "[INFO] GPO liées détectées : $($result.LinkedGPOs -join ', ')" "Yellow"
            } else {
                Write-Log "[INFO] Aucune GPO liée à cette OU" "Yellow"
            }
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le lien GPO → OU : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOSettings {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName
    )
    
    $settingsOk = 0
    $totalSettings = 4
    
    try {
        # Récupération du rapport XML de la GPO
        $gpoReport = Invoke-Command -Session $Session -ScriptBlock {
            param($GPOName)
            Get-GPOReport -Name $GPOName -ReportType Xml -ErrorAction Stop
        } -ArgumentList $GPOName -ErrorAction Stop
        
        [xml]$xmlReport = $gpoReport
        
        # Recherche des paramètres dans le XML
        $userConfig = $xmlReport.GPO.User.ExtensionData.Extension
        
        # 1. Activer l'écran de veille
        $screenSaverActive = $userConfig.Policy | Where-Object { 
            $_.Name -like "*écran de veille*" -or 
            $_.Name -like "*Enable screen saver*" -or
            $_.Name -like "*ScreenSaveActive*"
        }
        if ($screenSaverActive) {
            Write-Log "[OK] Paramètre 'Activer l'écran de veille' détecté" "Green"
            $settingsOk++
        } else {
            Write-Log "[ERREUR] Paramètre 'Activer l'écran de veille' non détecté" "Red"
        }
        
        # 2. Délai d'expiration (300 secondes)
        $screenSaverTimeout = $userConfig.Policy | Where-Object { 
            ($_.Name -like "*délai*" -or $_.Name -like "*timeout*" -or $_.Name -like "*ScreenSaveTimeOut*") -and
            ($_.State -eq "Enabled" -or $_.State -eq "Activé")
        }
        if ($screenSaverTimeout) {
            # Récupérer la valeur (plusieurs méthodes possibles selon la structure XML)
            $value = $null
            
            if ($screenSaverTimeout.Numeric.Value) {
                $value = $screenSaverTimeout.Numeric.Value
            }
            elseif ($screenSaverTimeout.EditText.Value) {
                $value = $screenSaverTimeout.EditText.Value
            }
            elseif ($screenSaverTimeout.DecimalTextBox.Value) {
                $value = $screenSaverTimeout.DecimalTextBox.Value
            }
            elseif ($screenSaverTimeout.Text) {
                $value = $screenSaverTimeout.Text
            }
            
            if ($value -eq "300") {
                Write-Log "[OK] Délai d'expiration écran de veille = 300 secondes" "Green"
                $settingsOk++
            } elseif ($value) {
                Write-Log "[ERREUR] Délai d'expiration = $value (attendu: 300)" "Red"
            } else {
                Write-Log "[ERREUR] Délai d'expiration non récupérable (attendu: 300)" "Red"
            }
        } else {
            Write-Log "[ERREUR] Paramètre 'Délai d'expiration écran de veille' non détecté" "Red"
        }
        
        # 3. Mot de passe protège l'écran de veille
        $screenSaverPassword = $userConfig.Policy | Where-Object { 
            $_.Name -like "*mot de passe*" -or 
            $_.Name -like "*password*" -or
            $_.Name -like "*ScreenSaverIsSecure*"
        }
        if ($screenSaverPassword) {
            Write-Log "[OK] Paramètre 'Mot de passe protège l'écran de veille' détecté" "Green"
            $settingsOk++
        } else {
            Write-Log "[ERREUR] Paramètre 'Mot de passe protège l'écran de veille' non détecté" "Red"
        }
        
        # 4. Papier peint du Bureau
        $wallpaper = $userConfig.Policy | Where-Object { 
            $_.Name -like "*papier peint*" -or 
            $_.Name -like "*wallpaper*" -or
            $_.Name -like "*Desktop Wallpaper*"
        }
        if ($wallpaper) {
            $wallpaperPath = $wallpaper.EditText.Value
            if ($wallpaperPath -like "*wallpaper_m2l.jpg*") {
                Write-Log "[OK] Papier peint configuré : $wallpaperPath" "Green"
                $settingsOk++
            } else {
                Write-Log "[WARNING] Papier peint = '$wallpaperPath' (attendu: wallpaper_m2l.jpg)" "Yellow"
                $settingsOk += 0.5
            }
        } else {
            Write-Log "[ERREUR] Paramètre 'Papier peint du Bureau' non détecté" "Red"
        }
        
    } catch {
        Write-Log "[ERREUR] Impossible d'analyser les paramètres de la GPO : $($_.Exception.Message)" "Red"
    }
    
    return $settingsOk
}

# =========================
# Fonctions de test REMOTE supplémentaires (DNS, AD, configuration système)
# =========================

function Test-RemoteDnsRoleInstalled {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            (Get-WindowsFeature -Name "DNS").Installed
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Le rôle DNS est installé." "Green" 
        } else { 
            Write-Log "[ERREUR] Le rôle DNS n'est pas installé." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le rôle DNS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemotePrimaryForwardZone {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ZoneName
    )
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            param($ZoneName)
            Get-DnsServerZone | Where-Object { $_.ZoneName -eq $ZoneName -and $_.ZoneType -eq 'Primary' }
        } -ArgumentList $ZoneName -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] La zone de recherche directe (ZRD) '$ZoneName' (principale) existe." "Green" 
        } else { 
            Write-Log "[ERREUR] La ZRD '$ZoneName' (principale) est absente." "Red" 
        }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la zone DNS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteReverseZoneExists {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -eq $true }
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Une zone de recherche inverse (ZRI) est configurée." "Green" 
        } else { 
            Write-Log "[ERREUR] Aucune ZRI configurée." "Red" 
        }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la zone inverse : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteNicDnsLoopbackOrLocalIP {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }).IPAddress
            $dnsCfg = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
            ($dnsCfg -contains '127.0.0.1' -or $dnsCfg -contains $localIP)
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Le DNS client du DC pointe sur 127.0.0.1 ou l'IP locale." "Green" 
        } else { 
            Write-Log "[ERREUR] Le DNS client du DC n'est pas correctement configuré." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la config DNS client : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteForwarder8888 {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $fwds = (Get-DnsServerForwarder).IPAddress.IPAddressToString
            ($fwds -contains '8.8.8.8')
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Redirecteur DNS 8.8.8.8 configuré." "Green" 
        } else { 
            Write-Log "[ERREUR] Redirecteur 8.8.8.8 absent." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les redirecteurs DNS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteStaticIP {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $ipCfg = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
            ($ipCfg.Dhcp -eq "Disabled")
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] L'IP du DC est configurée en statique." "Green" 
        } else { 
            Write-Log "[ERREUR] L'IP du DC n'est pas configurée en statique." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la config IP : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteSuffixMatches {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ExpectedSuffix
    )
    
    try {
        $suffix = Invoke-Command -Session $Session -ScriptBlock {
            (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
        } -ErrorAction Stop
        
        $ok = ($suffix -eq $ExpectedSuffix)
        if ($ok) { 
            Write-Log "[OK] Suffixe DNS principal du DC = '$ExpectedSuffix'." "Green" 
        } else { 
            Write-Log "[ERREUR] Suffixe DNS du DC '$suffix' ≠ '$ExpectedSuffix'." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le suffixe DNS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteAdRoleInstalled {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            (Get-WindowsFeature -Name AD-Domain-Services).Installed
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Rôle AD DS installé." "Green" 
        } else { 
            Write-Log "[ERREUR] Rôle AD DS non installé." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le rôle AD DS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteIsDomainController {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            ((Get-WmiObject Win32_ComputerSystem).DomainRole -eq 5)
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Le serveur est un contrôleur de domaine (DC)." "Green" 
        } else { 
            Write-Log "[ERREUR] Le serveur n'est pas promu en DC." "Yellow" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le rôle DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteNTDSRunning {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
            ($svc -and $svc.Status -eq "Running")
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Service NTDS actif." "Green" 
        } else { 
            Write-Log "[ERREUR] Service NTDS inactif." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le service NTDS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteDiscoverDC {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            [bool](Get-ADDomainController -Discover -ErrorAction SilentlyContinue)
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Un contrôleur de domaine est détecté." "Green" 
        } else { 
            Write-Log "[ERREUR] Aucun contrôleur de domaine détecté." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de découvrir le DC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteADMatchesInput {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$DomainDns
    )
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($DomainDns)
            try {
                $ad = Get-ADDomain -Server $DomainDns -ErrorAction Stop
                @{
                    Success = $true
                    DNSRoot = $ad.DNSRoot
                    Match = ($ad.DNSRoot -ieq $DomainDns)
                }
            } catch {
                @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        } -ArgumentList $DomainDns -ErrorAction Stop
        
        if ($result.Success) {
            if ($result.Match) { 
                Write-Log "[OK] Domaine AD conforme à l'input : $($result.DNSRoot)." "Green" 
                return $true
            } else { 
                Write-Log "[ERREUR] Domaine détecté '$($result.DNSRoot)' ≠ '$DomainDns'." "Red" 
                return $false
            }
        } else {
            Write-Log "[ERREUR] Interrogation du domaine '$DomainDns' : $($result.Error)" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le domaine AD : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteForest {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            try {
                $f = Get-ADForest -ErrorAction Stop
                @{ Success = $true; Name = $f.Name }
            } catch {
                @{ Success = $false }
            }
        } -ErrorAction Stop
        
        if ($result.Success) { 
            Write-Log "[OK] Forêt détectée : $($result.Name)." "Green" 
            return $true
        } else { 
            Write-Log "[ERREUR] Aucune forêt AD détectée." "Red" 
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la forêt : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteFSMO {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            try {
                $fsmo = netdom query fsmo 2>$null | ForEach-Object { $_ -replace "\s+", " " }
                [bool]$fsmo
            } catch {
                $false
            }
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Rôles FSMO attribués." "Green" 
        } else { 
            Write-Log "[ERREUR] Impossible de récupérer les rôles FSMO." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les rôles FSMO : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteDomainDnsResolution {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            try {
                $dn = (Get-ADDomain).DNSRoot
                $resolve = Resolve-DnsName -Name $dn -Server 127.0.0.1 -ErrorAction SilentlyContinue
                @{ Success = $true; DNSRoot = $dn; Resolved = [bool]$resolve }
            } catch {
                @{ Success = $false }
            }
        } -ErrorAction Stop
        
        if ($result.Success -and $result.Resolved) { 
            Write-Log "[OK] Résolution DNS du domaine '$($result.DNSRoot)' OK." "Green" 
            return $true
        } else { 
            Write-Log "[ERREUR] Problème de résolution DNS pour le domaine." "Red" 
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la résolution DNS : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteRootOU {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$DomainDns
    )
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            param($DomainDns)
            $domainDN = (Get-ADDomain).DistinguishedName
            $ouRoot = "OU=@$DomainDns,$domainDN"
            [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRoot'" -ErrorAction SilentlyContinue)
        } -ArgumentList $DomainDns -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] OU racine '@$DomainDns' existe." "Green" 
        } else { 
            Write-Log "[ERREUR] OU racine '@$DomainDns' absente." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'OU racine : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteNtdsSysvolOnDataDrive {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$DataDrive
    )
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($DataDrive)
            
            # Normalisation
            if (-not $DataDrive) { return @{ Success = $false; Message = "Lettre de lecteur non fournie" } }
            $drv = $DataDrive.Trim()
            if ($drv -notmatch '^[A-Za-z]:$') { return @{ Success = $false; Message = "Lettre invalide: $DataDrive" } }
            if ($drv -ieq 'C:') { return @{ Success = $false; Message = "Le lecteur supplémentaire ne peut pas être C:" } }
            
            # Récup des chemins NTDS et SYSVOL
            $ntdsPath = $null
            try {
                $ntdsReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
                $ntdsPath = $ntdsReg.'DSA Working Directory'
            } catch {}
            if (-not $ntdsPath) { $ntdsPath = (Join-Path ($drv + "\") 'Windows\NTDS') }
            
            $sysvolPath = $null
            try {
                $nl = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop
                $sysvolPath = $nl.'SysVol'
            } catch {}
            if (-not $sysvolPath) { $sysvolPath = (Join-Path ($drv + "\") 'Windows\SYSVOL') }
            
            # Fonction Get-Drive
            function Get-Drive([string]$p) { 
                try { return ([System.IO.Path]::GetPathRoot($p)).TrimEnd('\') } 
                catch { return $null } 
            }
            
            $ntdsDrive = Get-Drive $ntdsPath
            $sysvolDrive = Get-Drive $sysvolPath
            
            $okNtds = ($ntdsDrive -and ($ntdsDrive -ne 'C:') -and ($ntdsDrive -ieq $drv))
            $okSysvol = ($sysvolDrive -and ($sysvolDrive -ne 'C:') -and ($sysvolDrive -ieq $drv))
            
            @{
                Success = ($okNtds -and $okSysvol)
                NTDSPath = $ntdsPath
                SYSVOLPath = $sysvolPath
                NTDSDrive = $ntdsDrive
                SYSVOLDrive = $sysvolDrive
                OkNTDS = $okNtds
                OkSYSVOL = $okSysvol
            }
        } -ArgumentList $DataDrive -ErrorAction Stop
        
        if ($result.Success) {
            Write-Log "[OK] NTDS et SYSVOL sont sur $DataDrive (hors C:) : NTDS='$($result.NTDSPath)', SYSVOL='$($result.SYSVOLPath)'." "Green"
            return $true
        } else {
            if (-not $result.OkNTDS) { 
                Write-Log "[ERREUR] NTDS sur '$($result.NTDSPath)' (lecteur $($result.NTDSDrive)) – attendu sur $DataDrive (≠ C:)." "Red" 
            }
            if (-not $result.OkSYSVOL) { 
                Write-Log "[ERREUR] SYSVOL sur '$($result.SYSVOLPath)' (lecteur $($result.SYSVOLDrive)) – attendu sur $DataDrive (≠ C:)." "Red" 
            }
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier NTDS/SYSVOL : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteInternetAccess {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            Test-NetConnection -ComputerName "google.com" -InformationLevel Quiet -ErrorAction SilentlyContinue
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Accès à Internet disponible depuis le DC." "Green" 
        } else { 
            Write-Log "[ERREUR] Pas d'accès à Internet depuis le DC." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de tester l'accès Internet : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteIEESC {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $adminKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
            $userKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
            
            $adminESC = (Get-ItemProperty -Path $adminKey -Name "IEHarden" -ErrorAction SilentlyContinue).IEHarden
            $userESC = (Get-ItemProperty -Path $userKey -Name "IEHarden" -ErrorAction SilentlyContinue).IEHarden
            
            (($adminESC -eq $null -or $adminESC -eq 0) -and ($userESC -eq $null -or $userESC -eq 0))
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Sécurité renforcée IE désactivée pour admins et utilisateurs." "Green" 
        } else { 
            Write-Log "[ERREUR] Sécurité renforcée IE activée." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier IE ESC : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemotePingFirewall {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            $ruleInbound = Get-NetFirewallRule | Where-Object { 
                $_.DisplayName -match "ICMPv4" -and $_.Direction -eq "Inbound" 
            }
            $ruleOutbound = Get-NetFirewallRule | Where-Object { 
                $_.DisplayName -match "ICMPv4" -and $_.Direction -eq "Outbound" 
            }
            
            @{
                InboundOk = ($ruleInbound -and $ruleInbound.Enabled -eq "True")
                OutboundOk = ($ruleOutbound -and $ruleOutbound.Enabled -eq "True")
            }
        } -ErrorAction Stop
        
        $score = 0
        if ($result.InboundOk) { 
            Write-Log "[OK] Règle pare-feu ICMPv4 entrante activée." "Green" 
            $score++
        } else { 
            Write-Log "[ERREUR] Aucune règle pare-feu ICMPv4 entrante activée." "Red" 
        }
        
        if ($result.OutboundOk) { 
            Write-Log "[OK] Règle pare-feu ICMPv4 sortante activée." "Green" 
            $score++
        } else { 
            Write-Log "[ERREUR] Aucune règle pare-feu ICMPv4 sortante activée." "Red" 
        }
        
        return $score
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les règles pare-feu : $($_.Exception.Message)" "Red"
        return 0
    }
}

function Test-RemoteRDP {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)
    
    try {
        $ok = Invoke-Command -Session $Session -ScriptBlock {
            $rdpStatus = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
            ($rdpStatus -eq 0)
        } -ErrorAction Stop
        
        if ($ok) { 
            Write-Log "[OK] Bureau à Distance (RDP) activé sur le DC." "Green" 
        } else { 
            Write-Log "[ERREUR] Bureau à Distance désactivé sur le DC." "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier RDP : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteHostname {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ExpectedHostname
    )
    
    try {
        $hostname = Invoke-Command -Session $Session -ScriptBlock {
            (Get-ComputerInfo).CsName
        } -ErrorAction Stop
        
        $ok = ($hostname -eq $ExpectedHostname)
        if ($ok) { 
            Write-Log "[OK] Nom du DC correct : $hostname" "Green" 
        } else { 
            Write-Log "[ERREUR] Nom du DC = '$hostname' (attendu: '$ExpectedHostname')" "Red" 
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le hostname : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemotePartagePasOnC {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ExpectedDrive
    )
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($ExpectedDrive)
            
            # Rechercher les partages dans E:\Partages
            $partagesPath = "$ExpectedDrive\Partages"
            $exists = Test-Path -Path $partagesPath -PathType Container
            
            @{
                PartageDirExists = $exists
                Path = $partagesPath
                Drive = $ExpectedDrive
                NotOnC = ($ExpectedDrive -ine "C:")
            }
        } -ArgumentList $ExpectedDrive -ErrorAction Stop
        
        if ($result.NotOnC -and $result.PartageDirExists) {
            Write-Log "[OK] Dossier 'Partages' existe sur $($result.Drive) (hors C:) : $($result.Path)" "Green"
            return $true
        } elseif (-not $result.NotOnC) {
            Write-Log "[ERREUR] Le dossier Partages est sur C: (attendu: sur $ExpectedDrive)" "Red"
            return $false
        } else {
            Write-Log "[ERREUR] Dossier '$($result.Path)' absent." "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier le dossier Partages : $($_.Exception.Message)" "Red"
        return $false
    }
}

# =========================
# Fonctions de test LOCAL (sur le client)
# =========================

function Test-LocalGPOApplied {
    param([string]$GPOName)
    
    try {
        # Récupération des GPO appliquées localement
        Write-Log "   → Exécution de : gpresult /Scope User /v" "Gray"
        $rsopOutput = gpresult /Scope User /v 2>$null | Out-String
        
        if ($rsopOutput -match $GPOName) {
            Write-Log "[OK] GPO '$GPOName' appliquée localement (visible dans gpresult)" "Green"
            return $true
        } else {
            Write-Log "[WARNING] GPO '$GPOName' NON visible dans gpresult" "Yellow"
            Write-Log "" "Gray"
            Write-Log "💡 SOLUTION : Forcer l'application de la GPO" "Cyan"
            Write-Log "   1. Ouvrir PowerShell sur CE poste" "Cyan"
            Write-Log "   2. Exécuter : gpupdate /force" "Cyan"
            Write-Log "   3. Attendre la fin de l'exécution (~30s)" "Cyan"
            Write-Log "   4. Se déconnecter puis reconnecter" "Cyan"
            Write-Log "   5. Relancer ce script" "Cyan"
            Write-Log "" "Gray"
            Write-Log "   Note : La GPO peut être correctement configurée sur le DC" "Gray"
            Write-Log "         mais pas encore propagée à ce poste client." "Gray"
            Write-Log "" "Gray"
            return $false
        }
    } catch {
        Write-Log "[WARNING] Impossible de vérifier l'application locale de la GPO" "Yellow"
        Write-Log "   Erreur : $($_.Exception.Message)" "Gray"
        return $false
    }
}

function Test-LocalScreenSaverSettings {
    try {
        # Chemins de registre à vérifier (GPO a priorité sur paramètres utilisateur)
        $regPathGPO = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        $regPathUser = "HKCU:\Control Panel\Desktop"
        
        # Lecture des valeurs - PRIORITÉ aux clés GPO
        Write-Log "   → Recherche des paramètres dans le registre" "Gray"
        
        # Fonction pour lire une valeur avec fallback
        function Get-RegistryValue {
            param([string]$ValueName)
            
            # 1. Essayer d'abord dans la clé GPO (priorité)
            $gpoValue = (Get-ItemProperty -Path $regPathGPO -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
            if ($null -ne $gpoValue) {
                Write-Log "     $ValueName = '$gpoValue' (depuis GPO: Policies)" "Gray"
                return $gpoValue
            }
            
            # 2. Sinon, essayer dans la clé utilisateur
            $userValue = (Get-ItemProperty -Path $regPathUser -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
            if ($null -ne $userValue) {
                Write-Log "     $ValueName = '$userValue' (depuis paramètres utilisateur)" "Gray"
                return $userValue
            }
            
            # 3. Aucune valeur trouvée
            Write-Log "     $ValueName = non trouvé" "Gray"
            return $null
        }
        
        # Lecture des 3 paramètres
        $ssActive = Get-RegistryValue "ScreenSaveActive"
        $ssTimeoutRaw = Get-RegistryValue "ScreenSaveTimeOut"
        $ssSecure = Get-RegistryValue "ScreenSaverIsSecure"
        
        Write-Log "   → Valeurs attendues : ScreenSaveActive='1', ScreenSaveTimeOut='300', ScreenSaverIsSecure='1'" "Gray"
        
        $localOk = 0
        $hasErrors = $false
        
        # Test 1 : Écran de veille actif
        if ($ssActive -eq "1") {
            Write-Log "[OK] Écran de veille activé (registre)" "Green"
            $localOk++
        } else {
            Write-Log "[WARNING] Écran de veille NON activé (valeur = '$ssActive')" "Yellow"
            $hasErrors = $true
        }
        
        # Test 2 : Délai 300s (±10s de tolérance)
        if ([string]::IsNullOrEmpty($ssTimeoutRaw)) {
            Write-Log "[WARNING] Délai écran de veille non défini dans le registre" "Yellow"
            $hasErrors = $true
        } else {
            try {
                $ssTimeout = [int]$ssTimeoutRaw
                if ($ssTimeout -ge 290 -and $ssTimeout -le 310) {
                    Write-Log "[OK] Délai écran de veille = ${ssTimeout}s (cible 300s)" "Green"
                    $localOk++
                } elseif ($ssTimeout -eq 0) {
                    Write-Log "[WARNING] Délai écran de veille = 0s (GPO non appliquée ?)" "Yellow"
                    $hasErrors = $true
                } else {
                    Write-Log "[WARNING] Délai = ${ssTimeout}s (attendu 290-310s)" "Yellow"
                    $hasErrors = $true
                }
            } catch {
                Write-Log "[WARNING] Délai écran de veille invalide : '$ssTimeoutRaw'" "Yellow"
                $hasErrors = $true
            }
        }
        
        # Test 3 : Mot de passe obligatoire
        if ($ssSecure -eq "1") {
            Write-Log "[OK] Mot de passe écran de veille activé (registre)" "Green"
            $localOk++
        } else {
            Write-Log "[WARNING] Mot de passe écran de veille NON activé (valeur = '$ssSecure')" "Yellow"
            $hasErrors = $true
        }
        
        # Message d'aide si des erreurs sont détectées
        if ($hasErrors) {
            Write-Log "" "Gray"
            Write-Log "💡 DIAGNOSTIC :" "Cyan"
            Write-Log "   Les paramètres GPO sont recherchés dans :" "Cyan"
            Write-Log "   1. HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop (GPO)" "Cyan"
            Write-Log "   2. HKCU:\Control Panel\Desktop (paramètres utilisateur)" "Cyan"
            Write-Log "" "Gray"
            Write-Log "💡 SI LA GPO EST BIEN CONFIGURÉE SUR LE DC :" "Cyan"
            Write-Log "   1. Ouvrir PowerShell sur CE poste" "Cyan"
            Write-Log "   2. Exécuter : gpupdate /force" "Cyan"
            Write-Log "   3. Se déconnecter puis reconnecter" "Cyan"
            Write-Log "   4. Relancer ce script" "Cyan"
            Write-Log "" "Gray"
            Write-Log "   Note : Sur Windows non activé, l'interface de personnalisation" "Gray"
            Write-Log "          est bloquée MAIS les paramètres GPO sont quand même appliqués" "Gray"
            Write-Log "          dans le registre si la GPO est correcte." "Gray"
            Write-Log "" "Gray"
        }
        
        return ($localOk -eq 3)
        
    } catch {
        Write-Log "[WARNING] Impossible de vérifier les paramètres locaux (registre)" "Yellow"
        Write-Log "   Erreur : $($_.Exception.Message)" "Gray"
        return $false
    }
}


# =========================
# EXÉCUTION DES TESTS
# =========================

Write-Log "`n──── Vérification CLIENT ────" "Yellow"

$totalPoints += 2
if (Test-ClientDomainJoined) { $note += 2 }

# =========================
# Tests REMOTE sur le DC
# =========================

Write-Log "`n──── Structure AD (vérification REMOTE sur DC) ────" "Yellow"

$totalPoints += 4
$ouOk = 0
if (Test-RemoteOUExists -Session $global:DCSession -OUPath $OURacine -Description "OU Racine @$DomainDns") { $ouOk++ }
if (Test-RemoteOUExists -Session $global:DCSession -OUPath $OUUtilisateurs -Description "OU Utilisateurs") { $ouOk++ }
if (Test-RemoteOUExists -Session $global:DCSession -OUPath $OUEtudiants -Description "OU Etudiants") { $ouOk++ }

if ($ouOk -eq 3) { $note += 4 }
elseif ($ouOk -eq 2) { $note += 2 }
elseif ($ouOk -eq 1) { $note += 1 }

Write-Log "`n──── Utilisateur (vérification REMOTE sur DC) ────" "Yellow"

$totalPoints += 3
if (Test-RemoteUserExists -Session $global:DCSession -Login $UserLogin -FullName $UserFullName -OUPath $OUEtudiants) { $note += 3 }

Write-Log "`n──── Structure de dossiers et partage (REMOTE sur DC) ────" "Yellow"

$WallpapersPath = "$LettreDisqueSup\Partages\Communs\Wallpapers"

$totalPoints += 2
if (Test-RemoteFolderExists -Session $global:DCSession -Path $WallpapersPath) { $note += 2 }  # CORRIGÉ : 2 points au lieu de 1

$totalPoints += 2
if (Test-RemoteShareExists -Session $global:DCSession -ShareName $ShareName -ExpectedPath $WallpapersPath) { $note += 2 }

$totalPoints += 2
if (Test-RemoteSharePermission -Session $global:DCSession -ShareName $ShareName -Identity "Everyone" -AccessRight "Full") { $note += 2 }

$totalPoints += 2
if (Test-RemoteNTFSPermission -Session $global:DCSession -Path $WallpapersPath -Identity "Everyone" -Rights "Read") { $note += 2 }

Write-Log "`n──── GPO - Existence et liaison (REMOTE sur DC) ────" "Yellow"

$totalPoints += 3
if (Test-RemoteGPOExists -Session $global:DCSession -GPOName $GPOName) { $note += 3 }

$totalPoints += 3
if (Test-RemoteGPOLinkedToOU -Session $global:DCSession -GPOName $GPOName -OUPath $OUEtudiants) { $note += 3 }

Write-Log "`n──── GPO - Paramètres (REMOTE sur DC) ────" "Yellow"

$totalPoints += 4
$gpoSettingsScore = Test-RemoteGPOSettings -Session $global:DCSession -GPOName $GPOName
$note += $gpoSettingsScore

# =========================
# Tests REMOTE supplémentaires (Configuration système du DC)
# =========================

Write-Log "`n──── Configuration réseau du DC (REMOTE) ────" "Yellow"

$totalPoints += 1
if (Test-RemoteStaticIP -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteSuffixMatches -Session $global:DCSession -ExpectedSuffix $DomainDns) { $note += 1 }

$totalPoints += 1
if (Test-RemoteNicDnsLoopbackOrLocalIP -Session $global:DCSession) { $note += 1 }

Write-Log "`n──── Rôles et services du DC (REMOTE) ────" "Yellow"

$totalPoints += 1
if (Test-RemoteDnsRoleInstalled -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemotePrimaryForwardZone -Session $global:DCSession -ZoneName $DomainDns) { $note += 1 }

$totalPoints += 1
if (Test-RemoteReverseZoneExists -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteForwarder8888 -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteAdRoleInstalled -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteIsDomainController -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteNTDSRunning -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteDiscoverDC -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteADMatchesInput -Session $global:DCSession -DomainDns $DomainDns) { $note += 1 }

$totalPoints += 1
if (Test-RemoteForest -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteFSMO -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteDomainDnsResolution -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteRootOU -Session $global:DCSession -DomainDns $DomainDns) { $note += 1 }

Write-Log "`n──── Emplacements NTDS/SYSVOL et Partages (REMOTE) ────" "Yellow"

$totalPoints += 2
if (Test-RemoteNtdsSysvolOnDataDrive -Session $global:DCSession -DataDrive $LettreDisqueSup) { $note += 2 }

$totalPoints += 1
if (Test-RemotePartagePasOnC -Session $global:DCSession -ExpectedDrive $LettreDisqueSup) { $note += 1 }

Write-Log "`n──── Configuration système et sécurité du DC (REMOTE) ────" "Yellow"

$totalPoints += 1
if (Test-RemoteInternetAccess -Session $global:DCSession) { $note += 1 }

$totalPoints += 1
if (Test-RemoteIEESC -Session $global:DCSession) { $note += 1 }

$totalPoints += 2
$pingScore = Test-RemotePingFirewall -Session $global:DCSession
$note += $pingScore

$totalPoints += 1
if (Test-RemoteRDP -Session $global:DCSession) { $note += 1 }

# Test du nom d'hôte (optionnel - commenté car le nom peut varier)
# $totalPoints += 1
# if (Test-RemoteHostname -Session $global:DCSession -ExpectedHostname $ServeurDC) { $note += 1 }

# =========================
# Tests LOCAL sur le client
# =========================

Write-Log "`n──── Application GPO locale (vérification sur CE poste) ────" "Yellow"

$totalPoints += 2
if (Test-LocalGPOApplied -GPOName $GPOName) { $note += 2 }

Write-Log "`n──── Paramètres locaux écran de veille (vérification sur CE poste) ────" "Yellow"

$totalPoints += 3
if (Test-LocalScreenSaverSettings) { $note += 3 }

# NOTE : Le test du papier peint local a été retiré car Windows 10 non activé
# ne permet pas le changement de fond d'écran. La GPO configure bien le paramètre
# (vérifié dans les paramètres GPO ci-dessus), mais il ne s'applique pas visuellement.

# =========================
# Résumé et envoi
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
    $jsonFile = Join-Path $desktopPath "GPO_TP1-$Nom-$Prenom.json"
    $payload = [ordered]@{
        status       = "OK"
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        nom          = $Nom
        prenom       = $Prenom
        tp           = "TP1 - GPO Sécurité et Verrouillage"
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
    Write-Host ("TP         : TP1 - GPO Sécurité et Verrouillage") -ForegroundColor White
    Write-Host ("Étudiant   : $Prenom $Nom") -ForegroundColor White
    Write-Host ("Domaine    : $DomainDns") -ForegroundColor White
    Write-Host ("Points     : {0} / {1}" -f $Note, $Total) -ForegroundColor Cyan
    Write-Host ("Note       : {0} / 20" -f $scoreSur20) -ForegroundColor Cyan
    Write-Host ("Pourcentage: {0}%" -f $pourcentage) -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════" -ForegroundColor Cyan
    
    # Envoi optionnel
    $serverUrl = "http://www.ericm.fr/logsapi/logreceiver.php?filename=GPO_TP1-$Nom-$Prenom.json"
    try {
        Invoke-RestMethod -Uri $serverUrl -Method Post -Body $payload -ContentType "application/json; charset=utf-8"
        Write-Host "✅ Fichier JSON envoyé avec succès au serveur !" -ForegroundColor Green
    } catch {
        Write-Host "❌ Erreur lors de l'envoi du JSON : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Show-And-Send-Result -Nom $Nom -Prenom $Prenom -Note $note -Total $totalPoints -Logs $logMessages -DomainDns $DomainDns

# =========================
# Nettoyage : Fermeture de la session PSRemoting
# =========================
if ($global:DCSession) {
    Write-Log "`nFermeture de la session PSRemoting..." "Gray"
    Remove-PSSession -Session $global:DCSession
    Write-Log "[OK] Session fermée" "Green"
}

Write-Host "`n═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "RAPPEL : Pour appliquer les GPO localement, exécutez:" -ForegroundColor Yellow
Write-Host "gpupdate /force" -ForegroundColor White
Write-Host "puis reconnectez-vous pour voir les changements." -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nAppuyez sur Entrée pour quitter..." -ForegroundColor Gray
Read-Host
