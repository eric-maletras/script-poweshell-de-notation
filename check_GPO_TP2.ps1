# =========================
# Script de correction - TP Guidé 2 : Dépannage d'une GPO
# Exécution depuis un poste CLIENT Windows joint au domaine
# VERSION AVEC PSREMOTING
# =========================

# =========================
# En-tête / Inputs
# =========================
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Script de vérification TP2 - Dépannage GPO" -ForegroundColor Cyan
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

# Variables spécifiques au TP2 - Dépannage GPO
$OURacine = "OU=@$DomainDns,$DomainDN"
$OUUtilisateurs = "OU=Utilisateurs,$OURacine"
$OUTechniciens = "OU=Techniciens,$OUUtilisateurs"
$OUSecretariat = "OU=Secretariat,$OUUtilisateurs"
$UserTechnicien = "ldubois"
$UserSecretaire = "asimard"
$GPOTechniciens = "GPO_Techniciens_Desktop"
$GPOSecretariat = "GPO_Secretariat_LockScreen"

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
Write-Log "Correction TP Guidé 2 : Dépannage d'une GPO" "Cyan"
Write-Log "Domaine: $DomainDns" "Cyan"
Write-Log "Étudiant: $Prenom $Nom" "Cyan"
Write-Log "═══════════════════════════════════════════════════" "Cyan"

# =========================
# Fonctions de test REMOTE (sur le DC)
# =========================

function Test-RemoteOUExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$OUPath,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test OU '$Description'" "Red"
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

function Test-RemoteUserExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$Login,
        [string]$OUPath,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test utilisateur '$Login'" "Red"
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
        } -ArgumentList $Login, $OUPath
        
        if ($result.Exists) {
            if ($result.Enabled) {
                Write-Log "[OK] Utilisateur '$Login' ($($result.Name)) existe et est activé dans $Description" "Green"
                return $true
            } else {
                Write-Log "[ERREUR] Utilisateur '$Login' existe mais est DÉSACTIVÉ dans $Description" "Red"
                return $false
            }
        } else {
            Write-Log "[ERREUR] Utilisateur '$Login' absent dans $Description" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier l'utilisateur '$Login' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOExists {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test GPO '$GPOName'" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($name)
            Import-Module GroupPolicy -ErrorAction Stop
            $gpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
            return [bool]$gpo
        } -ArgumentList $GPOName
        
        if ($result) {
            Write-Log "[OK] GPO '$GPOName' existe" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] GPO '$GPOName' n'existe pas" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la GPO '$GPOName' : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOLinkedToOU {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName,
        [string]$OUPath
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test liaison GPO" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($gpoName, $ou)
            Import-Module GroupPolicy -ErrorAction Stop
            
            # Vérifier que la GPO existe
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) { return @{ Linked = $false; Error = "GPO inexistante" } }
            
            # Vérifier les liaisons
            $links = (Get-GPInheritance -Target $ou -ErrorAction SilentlyContinue).GpoLinks
            $isLinked = $links | Where-Object { $_.DisplayName -eq $gpoName }
            
            if ($isLinked) {
                $linkEnabled = $isLinked.Enabled
                $linkEnforced = $isLinked.Enforced
                return @{
                    Linked = $true
                    Enabled = $linkEnabled
                    Enforced = $linkEnforced
                }
            }
            return @{ Linked = $false }
        } -ArgumentList $GPOName, $OUPath
        
        if ($result.Linked) {
            if ($result.Enabled) {
                Write-Log "[OK] GPO '$GPOName' est liée et ACTIVE sur $OUPath" "Green"
                if ($result.Enforced) {
                    Write-Log "      (Liaison forcée : oui)" "DarkGray"
                }
                return $true
            } else {
                Write-Log "[ERREUR] GPO '$GPOName' est liée mais DÉSACTIVÉE sur $OUPath" "Red"
                return $false
            }
        } else {
            $errorMsg = if ($result.Error) { " ($($result.Error))" } else { "" }
            Write-Log "[ERREUR] GPO '$GPOName' n'est PAS liée à $OUPath$errorMsg" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la liaison GPO : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPODesktopWallpaperSettings {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test paramètres GPO Desktop" "Red"
        return 0
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($gpoName)
            Import-Module GroupPolicy -ErrorAction Stop
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                return @{ Score = 0; Error = "GPO inexistante" }
            }
            
            # Récupérer le rapport XML de la GPO
            $report = Get-GPOReport -Name $gpoName -ReportType Xml -ErrorAction Stop
            $xml = [xml]$report
            
            $score = 0
            $details = @()
            
            # Test 1 : Wallpaper configuré (User Config)
            $wallpaperNode = $xml.SelectSingleNode("//q1:User//q1:Extension[@xmlns:q1='http://www.microsoft.com/GroupPolicy/Settings/Registry']//q1:Policy[q1:Name='Wallpaper']")
            if ($wallpaperNode) {
                $wallpaperValue = $wallpaperNode.State
                if ($wallpaperValue -eq "Enabled" -or $wallpaperValue -match "\\\\.*\\.*") {
                    $score += 2
                    $details += "Fond d'écran configuré"
                }
            }
            
            # Test 2 : Style du fond d'écran (Center, Stretch, Fill, etc.)
            $styleNode = $xml.SelectSingleNode("//q1:User//q1:Extension[@xmlns:q1='http://www.microsoft.com/GroupPolicy/Settings/Registry']//q1:Policy[q1:Name='WallpaperStyle']")
            if ($styleNode) {
                $score += 1
                $details += "Style du fond d'écran configuré"
            }
            
            # Test 3 : Empêcher les modifications
            $preventNode = $xml.SelectSingleNode("//q1:User//q1:Extension[@xmlns:q1='http://www.microsoft.com/GroupPolicy/Settings/Registry']//q1:Policy[contains(q1:Name, 'NoChangingWallpaper') or contains(q1:Name, 'NoDesktop')]")
            if ($preventNode) {
                $score += 1
                $details += "Modification du fond d'écran bloquée"
            }
            
            return @{
                Score = $score
                Details = $details
                Error = $null
            }
        } -ArgumentList $GPOName
        
        if ($result.Error) {
            Write-Log "[ERREUR] Paramètres Desktop de '$GPOName' : $($result.Error)" "Red"
        } else {
            foreach ($detail in $result.Details) {
                Write-Log "[OK] $detail dans '$GPOName'" "Green"
            }
            if ($result.Score -eq 0) {
                Write-Log "[ERREUR] Aucun paramètre de fond d'écran configuré dans '$GPOName'" "Red"
            }
        }
        
        return $result.Score
    } catch {
        Write-Log "[ERREUR] Impossible d'analyser les paramètres de '$GPOName' : $($_.Exception.Message)" "Red"
        return 0
    }
}

function Test-RemoteGPOLockScreenSettings {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test paramètres GPO LockScreen" "Red"
        return 0
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($gpoName)
            Import-Module GroupPolicy -ErrorAction Stop
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) {
                return @{ Score = 0; Error = "GPO inexistante" }
            }
            
            # Récupérer le rapport XML de la GPO
            $report = Get-GPOReport -Name $gpoName -ReportType Xml -ErrorAction Stop
            $xml = [xml]$report
            
            $score = 0
            $details = @()
            
            # Test 1 : Image de l'écran de verrouillage configurée
            $lockScreenNode = $xml.SelectSingleNode("//q1:Computer//q1:Extension[@xmlns:q1='http://www.microsoft.com/GroupPolicy/Settings/Registry']//q1:Policy[contains(q1:Name, 'LockScreen') or contains(q1:Name, 'PersonalizationLockScreen')]")
            if ($lockScreenNode) {
                $score += 2
                $details += "Image d'écran de verrouillage configurée"
            }
            
            # Test 2 : Désactiver l'écran de verrouillage (optionnel mais souvent testé)
            $disableLockNode = $xml.SelectSingleNode("//q1:Computer//q1:Extension[@xmlns:q1='http://www.microsoft.com/GroupPolicy/Settings/Registry']//q1:Policy[contains(q1:Name, 'NoLockScreen')]")
            if ($disableLockNode) {
                $score += 1
                $details += "Options d'écran de verrouillage configurées"
            }
            
            return @{
                Score = $score
                Details = $details
                Error = $null
            }
        } -ArgumentList $GPOName
        
        if ($result.Error) {
            Write-Log "[ERREUR] Paramètres LockScreen de '$GPOName' : $($result.Error)" "Red"
        } else {
            foreach ($detail in $result.Details) {
                Write-Log "[OK] $detail dans '$GPOName'" "Green"
            }
            if ($result.Score -eq 0) {
                Write-Log "[ERREUR] Aucun paramètre d'écran de verrouillage configuré dans '$GPOName'" "Red"
            }
        }
        
        return $result.Score
    } catch {
        Write-Log "[ERREUR] Impossible d'analyser les paramètres de '$GPOName' : $($_.Exception.Message)" "Red"
        return 0
    }
}

function Test-RemoteGPONotLinkedToWrongOU {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName,
        [string]$WrongOUPath,
        [string]$Description
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test liaison incorrecte" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($gpoName, $wrongOU)
            Import-Module GroupPolicy -ErrorAction Stop
            
            # Vérifier que la GPO existe
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) { return @{ NotLinked = $true; Error = "GPO inexistante" } }
            
            # Vérifier les liaisons sur la mauvaise OU
            $links = (Get-GPInheritance -Target $wrongOU -ErrorAction SilentlyContinue).GpoLinks
            $isLinked = $links | Where-Object { $_.DisplayName -eq $gpoName }
            
            return @{ NotLinked = (-not $isLinked) }
        } -ArgumentList $GPOName, $WrongOUPath
        
        if ($result.NotLinked) {
            Write-Log "[OK] GPO '$GPOName' n'est PAS liée à $Description (correct !)" "Green"
            return $true
        } else {
            Write-Log "[ERREUR] GPO '$GPOName' est encore liée à $Description (devrait être déliée)" "Red"
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier la liaison incorrecte : $($_.Exception.Message)" "Red"
        return $false
    }
}

function Test-RemoteGPOPermissionsFixed {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$GPOName,
        [string]$SecurityGroup
    )
    
    if (-not $Session -or $Session.State -ne 'Opened') {
        Write-Log "[ERREUR] Session PSRemoting invalide pour test permissions GPO" "Red"
        return $false
    }
    
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($gpoName, $group)
            Import-Module GroupPolicy -ErrorAction Stop
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            if (-not $gpo) { return @{ Fixed = $false; Error = "GPO inexistante" } }
            
            # Récupérer les permissions
            $permissions = Get-GPPermission -Name $gpoName -All -ErrorAction SilentlyContinue
            
            # Chercher les permissions pour le groupe spécifié
            $groupPerm = $permissions | Where-Object { $_.Trustee.Name -like "*$group" }
            
            if ($groupPerm) {
                # Vérifier que le groupe a au moins "GpoRead" et "GpoApply"
                $hasRead = $groupPerm | Where-Object { $_.Permission -match "GpoRead" }
                $hasApply = $groupPerm | Where-Object { $_.Permission -match "GpoApply" }
                
                return @{
                    Fixed = ($hasRead -and $hasApply)
                    HasRead = [bool]$hasRead
                    HasApply = [bool]$hasApply
                }
            }
            
            return @{ Fixed = $false; HasRead = $false; HasApply = $false }
        } -ArgumentList $GPOName, $SecurityGroup
        
        if ($result.Error) {
            Write-Log "[ERREUR] Permissions GPO '$GPOName' : $($result.Error)" "Red"
            return $false
        }
        
        if ($result.Fixed) {
            Write-Log "[OK] Groupe '$SecurityGroup' a les permissions correctes sur '$GPOName' (Lecture + Application)" "Green"
            return $true
        } else {
            if (-not $result.HasRead) {
                Write-Log "[ERREUR] Groupe '$SecurityGroup' n'a PAS la permission 'Lecture' sur '$GPOName'" "Red"
            }
            if (-not $result.HasApply) {
                Write-Log "[ERREUR] Groupe '$SecurityGroup' n'a PAS la permission 'Appliquer' sur '$GPOName'" "Red"
            }
            return $false
        }
    } catch {
        Write-Log "[ERREUR] Impossible de vérifier les permissions de '$GPOName' : $($_.Exception.Message)" "Red"
        return $false
    }
}

# =========================
# Tests LOCAL (sur le client)
# =========================

function Test-LocalGPOApplied {
    param([string]$GPOName)
    
    try {
        $gpResult = gpresult /r /scope:user 2>$null
        $gpoApplied = $gpResult | Select-String -Pattern $GPOName
        
        if ($gpoApplied) {
            Write-Log "[OK] GPO '$GPOName' est appliquée sur CE poste" "Green"
            return $true
        } else {
            Write-Log "[WARNING] GPO '$GPOName' n'apparaît pas dans gpresult (peut nécessiter gpupdate /force + reconnexion)" "Yellow"
            return $false
        }
    } catch {
        Write-Log "[WARNING] Impossible d'exécuter gpresult : $($_.Exception.Message)" "Yellow"
        return $false
    }
}

# =========================
# Lancement des tests
# =========================

Write-Log "`n──── Structure AD ────" "Yellow"

$totalPoints += 1
if (Test-RemoteOUExists -Session $global:DCSession -OUPath $OUTechniciens -Description "OU Techniciens") { $note += 1 }

$totalPoints += 1
if (Test-RemoteOUExists -Session $global:DCSession -OUPath $OUSecretariat -Description "OU Secrétariat") { $note += 1 }

Write-Log "`n──── Utilisateurs ────" "Yellow"

$totalPoints += 2
if (Test-RemoteUserExists -Session $global:DCSession -Login $UserTechnicien -OUPath $OUTechniciens -Description "OU Techniciens") { $note += 2 }

$totalPoints += 2
if (Test-RemoteUserExists -Session $global:DCSession -Login $UserSecretaire -OUPath $OUSecretariat -Description "OU Secrétariat") { $note += 2 }

Write-Log "`n──── GPO Techniciens - Existence et liaison ────" "Yellow"

$totalPoints += 2
if (Test-RemoteGPOExists -Session $global:DCSession -GPOName $GPOTechniciens) { $note += 2 }

$totalPoints += 3
if (Test-RemoteGPOLinkedToOU -Session $global:DCSession -GPOName $GPOTechniciens -OUPath $OUTechniciens) { $note += 3 }

$totalPoints += 2
if (Test-RemoteGPONotLinkedToWrongOU -Session $global:DCSession -GPOName $GPOTechniciens -WrongOUPath $OUSecretariat -Description "OU Secrétariat") { $note += 2 }

Write-Log "`n──── GPO Techniciens - Paramètres Desktop ────" "Yellow"

$totalPoints += 4
$desktopScore = Test-RemoteGPODesktopWallpaperSettings -Session $global:DCSession -GPOName $GPOTechniciens
$note += $desktopScore

Write-Log "`n──── GPO Secrétariat - Existence et liaison ────" "Yellow"

$totalPoints += 2
if (Test-RemoteGPOExists -Session $global:DCSession -GPOName $GPOSecretariat) { $note += 2 }

$totalPoints += 3
if (Test-RemoteGPOLinkedToOU -Session $global:DCSession -GPOName $GPOSecretariat -OUPath $OUSecretariat) { $note += 3 }

$totalPoints += 2
if (Test-RemoteGPONotLinkedToWrongOU -Session $global:DCSession -GPOName $GPOSecretariat -WrongOUPath $OUTechniciens -Description "OU Techniciens") { $note += 2 }

Write-Log "`n──── GPO Secrétariat - Paramètres LockScreen ────" "Yellow"

$totalPoints += 3
$lockScreenScore = Test-RemoteGPOLockScreenSettings -Session $global:DCSession -GPOName $GPOSecretariat
$note += $lockScreenScore

Write-Log "`n──── GPO Techniciens - Permissions ────" "Yellow"

$totalPoints += 3
if (Test-RemoteGPOPermissionsFixed -Session $global:DCSession -GPOName $GPOTechniciens -SecurityGroup "Utilisateurs du domaine") { $note += 3 }

Write-Log "`n──── Application locale des GPO ────" "Yellow"

$totalPoints += 2
if (Test-LocalGPOApplied -GPOName $GPOTechniciens) { $note += 2 }

$totalPoints += 2
if (Test-LocalGPOApplied -GPOName $GPOSecretariat) { $note += 2 }

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
    $jsonFile = Join-Path $desktopPath "GPO_TP2-$Nom-$Prenom.json"
    $payload = [ordered]@{
        status       = "OK"
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        nom          = $Nom
        prenom       = $Prenom
        tp           = "TP Guidé 2 - Dépannage GPO"
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
    Write-Host ("TP         : TP Guidé 2 - Dépannage GPO") -ForegroundColor White
    Write-Host ("Étudiant   : $Prenom $Nom") -ForegroundColor White
    Write-Host ("Domaine    : $DomainDns") -ForegroundColor White
    Write-Host ("Points     : {0} / {1}" -f $Note, $Total) -ForegroundColor Cyan
    Write-Host ("Note       : {0} / 20" -f $scoreSur20) -ForegroundColor Cyan
    Write-Host ("Pourcentage: {0}%" -f $pourcentage) -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════" -ForegroundColor Cyan
    
    # Envoi optionnel
    $serverUrl = "http://www.ericm.fr/logsapi/logreceiver.php?filename=GPO_TP2-$Nom-$Prenom.json"
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
Write-Host "RAPPEL - Points de vérification corrigés :" -ForegroundColor Yellow
Write-Host "  ✓ GPO liées aux bonnes OU" -ForegroundColor White
Write-Host "  ✓ Liaisons incorrectes supprimées" -ForegroundColor White
Write-Host "  ✓ Permissions GPO corrigées" -ForegroundColor White
Write-Host "  ✓ Paramètres configurés correctement" -ForegroundColor White
Write-Host ""
Write-Host "Pour appliquer les GPO localement, exécutez:" -ForegroundColor Yellow
Write-Host "  gpupdate /force" -ForegroundColor White
Write-Host "puis reconnectez-vous pour voir les changements." -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nAppuyez sur Entrée pour quitter..." -ForegroundColor Gray
Read-Host
