cls
# =========================
# VERIFICATION PREALABLE : Droits administrateur
# =========================
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Red
    Write-Host "  AVERTISSEMENT : Droits administrateur requis" -ForegroundColor Red
    Write-Host "=======================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Ce script necessite des droits administrateur." -ForegroundColor Yellow
    Write-Host "Veuillez relancer PowerShell en tant qu'administrateur." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Appuyez sur Entree pour quitter"
    exit 1
}

# =========================
# En-tete / Inputs
# =========================
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Script de verification TP - DNS + DHCP + Active Directory" -ForegroundColor Cyan
Write-Host "  BTS SIO SISR - Eric MALETRAS" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$Nom = Read-Host "Entrez votre nom"
while ([string]::IsNullOrWhiteSpace($Nom)) { $Nom = Read-Host "Le nom ne peut pas etre vide. Entrez votre nom" }

$Prenom = Read-Host "Entrez votre prenom"
while ([string]::IsNullOrWhiteSpace($Prenom)) { $Prenom = Read-Host "Le prenom ne peut pas etre vide. Entrez votre prenom" }

$Domain = Read-Host "Entrez le nom du domaine (FQDN ex: dupont.lan)"
$DomainDns = ([string]$Domain).Trim().TrimEnd('.')
while ([string]::IsNullOrWhiteSpace($DomainDns) -or ($DomainDns -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')) {
    $Domain = Read-Host "FQDN invalide. Entrez le nom du domaine (ex: dupont.lan)"
    $DomainDns = ([string]$Domain).Trim().TrimEnd('.')
}

$LettreDisqueSup = Read-Host "Entrez la lettre du disque supplementaire (E: par defaut)"
if (-not $LettreDisqueSup) { $LettreDisqueSup = "E:" }
$LettreDisqueSup = $LettreDisqueSup.Trim()
if ($LettreDisqueSup -notmatch '^[A-Za-z]:$') { $LettreDisqueSup = $LettreDisqueSup.Substring(0,1) + ":" }
while ($LettreDisqueSup -ieq 'C:') {
    $LettreDisqueSup = Read-Host "Le disque supplementaire ne peut pas etre C:. Entrez une autre lettre (ex: E:)"
    if ($LettreDisqueSup -notmatch '^[A-Za-z]:$') { $LettreDisqueSup = $LettreDisqueSup.Substring(0,1) + ":" }
}

# =========================
# Valeurs deduites automatiquement
# =========================
$DomainDN = ($DomainDns -split '\.' | ForEach-Object { "DC=$_" }) -join ','

# Deduction du reseau depuis l'interface Ethernet
$EthAdapter = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
if (-not $EthAdapter) {
    Write-Host "[ERREUR] Impossible de trouver une interface Ethernet avec une IP valide." -ForegroundColor Red
    Read-Host "Appuyez sur Entree pour quitter"
    exit 1
}

$IpServeur = $EthAdapter.IPAddress
$octets = $IpServeur -split '\.'
$Reseau = "$($octets[0]).$($octets[1]).$($octets[2])"
$Passerelle = "$Reseau.1"
$IpSrvWeb = "$Reseau.10"
$IpSrvBdd = "$Reseau.11"

Write-Host ""
Write-Host "--- Valeurs deduites ---" -ForegroundColor Cyan
Write-Host "  IP serveur    : $IpServeur" -ForegroundColor White
Write-Host "  Reseau        : $Reseau.0/24" -ForegroundColor White
Write-Host "  Passerelle    : $Passerelle" -ForegroundColor White
Write-Host "  IP srv-web    : $IpSrvWeb" -ForegroundColor White
Write-Host "  IP srv-bdd    : $IpSrvBdd" -ForegroundColor White
Write-Host "  Domaine DN    : $DomainDN" -ForegroundColor White
Write-Host "------------------------" -ForegroundColor Cyan
Write-Host ""

# =========================
# Logs / Score
# =========================
$logMessages = @()
$note = 0
$totalPoints = 0

function Write-Log([string]$Message, [string]$Color = "Gray") {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    $global:logMessages += $line
    Write-Host $line -ForegroundColor $Color
}

Write-Log "Debut des verifications pour le domaine: $DomainDns" "Cyan"
Write-Log "IP detectee: $IpServeur | Reseau: $Reseau.0/24" "Cyan"

# ==========================================================
# SECTION 0 : Configuration VM (bonus)
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== SECTION 0 : Configuration VM ===" "Cyan"

function Test-IEEnhancedSecurityDisabled {
    try {
        $adminKey = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -ErrorAction SilentlyContinue
        $ok = ($adminKey -and $adminKey.IsInstalled -eq 0)
        if ($ok) { Write-Log "[OK] Securite renforcee IE desactivee (Administrateurs)." "Green" }
        else { Write-Log "[ERREUR] Securite renforcee IE encore activee (Administrateurs)." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de verifier la securite renforcee IE." "Red"
        return $false
    }
}

function Test-FirewallICMP {
    try {
        $rules = Get-NetFirewallRule -DisplayName "*ICMPv4*" -ErrorAction SilentlyContinue
        if (-not $rules) {
            $rules = Get-NetFirewallRule | Where-Object {
                $_.DisplayName -match "ICMP" -or $_.DisplayName -match "Ping" -or
                $_.DisplayName -match "Echo Request" -or $_.DisplayName -match "echo"
            } -ErrorAction SilentlyContinue
        }
        $enabled = $rules | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' -and $_.Direction -eq 'Inbound' }
        $ok = [bool]$enabled
        if ($ok) { Write-Log "[OK] Regle pare-feu ICMP entrant activee." "Green" }
        else { Write-Log "[ERREUR] Aucune regle pare-feu ICMP entrant activee (ping bloque)." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] Impossible de verifier les regles pare-feu ICMP." "Red"
        return $false
    }
}

function Test-PasswordPolicy {
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $complexOk = $policy.ComplexityEnabled -eq $true
        $lengthOk = $policy.MinPasswordLength -ge 7
        $ok = $complexOk -and $lengthOk
        if ($ok) { Write-Log "[OK] Politique de mot de passe AD correcte (complexite activee, longueur min >= 7)." "Green" }
        else {
            if (-not $complexOk) { Write-Log "[ERREUR] Complexite des mots de passe non activee dans AD." "Red" }
            if (-not $lengthOk) { Write-Log "[ERREUR] Longueur minimale du mot de passe < 7 (actuel: $($policy.MinPasswordLength))." "Red" }
        }
        return $ok
    } catch {
        Write-Log "[WARNING] Impossible de verifier la politique de mot de passe AD (DC non promu ?)." "Yellow"
        return $false
    }
}

function Test-LocalAdminPasswordChanged {
    try {
        $admin = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-21-*-500' } | Select-Object -First 1
        if (-not $admin) {
            Write-Log "[WARNING] Compte administrateur local introuvable." "Yellow"
            return $false
        }
        $changed = $admin.PasswordLastSet
        $creation = $admin.PasswordLastSet
        $ok = ($changed -and $changed -gt (Get-Date).AddYears(-1))
        if ($ok) { Write-Log "[OK] Mot de passe administrateur local modifie (derniere modif: $changed)." "Green" }
        else { Write-Log "[ERREUR] Mot de passe administrateur local semble etre celui par defaut." "Red" }
        return $ok
    } catch {
        Write-Log "[WARNING] Impossible de verifier le mot de passe administrateur local." "Yellow"
        return $false
    }
}

$totalPoints++; if (Test-IEEnhancedSecurityDisabled) { $note++ }
$totalPoints++; if (Test-FirewallICMP) { $note++ }
$totalPoints++; if (Test-PasswordPolicy) { $note++ }
$totalPoints++; if (Test-LocalAdminPasswordChanged) { $note++ }

# ==========================================================
# SECTION 1 : Reseau (3 points)
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== SECTION 1 : Reseau ===" "Cyan"

function Test-StaticIP {
    $ipCfg = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
    $ok = ($ipCfg.Dhcp -eq "Disabled")
    if ($ok) { Write-Log "[OK] R1 - L'IP est configuree en statique (DHCP desactive)." "Green" }
    else { Write-Log "[ERREUR] R1 - L'IP n'est pas en statique (DHCP encore actif)." "Red" }
    return $ok
}

function Test-DnsClientConfig {
    $dnsCfg = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' } | Select-Object -ExpandProperty ServerAddresses
    $ok = ($dnsCfg -contains '127.0.0.1' -or $dnsCfg -contains $IpServeur)
    if ($ok) { Write-Log "[OK] R2 - DNS client pointe sur 127.0.0.1 ou l'IP locale ($IpServeur)." "Green" }
    else { Write-Log "[ERREUR] R2 - DNS client ne pointe pas sur 127.0.0.1 ni sur $IpServeur (actuel: $($dnsCfg -join ', '))." "Red" }
    return $ok
}

function Test-DnsSuffix {
    $suffix = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
    $ok = ($suffix -eq $DomainDns)
    if ($ok) { Write-Log "[OK] R3 - Suffixe DNS principal = '$DomainDns'." "Green" }
    else { Write-Log "[ERREUR] R3 - Suffixe DNS '$suffix' != '$DomainDns'." "Red" }
    return $ok
}

$totalPoints++; if (Test-StaticIP) { $note++ }
$totalPoints++; if (Test-DnsClientConfig) { $note++ }
$totalPoints++; if (Test-DnsSuffix) { $note++ }

# ==========================================================
# SECTION 2 : DNS (10 points)
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== SECTION 2 : DNS ===" "Cyan"

function Test-DnsRoleInstalled {
    try {
        $ok = (Get-WindowsFeature -Name "DNS" -ErrorAction SilentlyContinue).Installed
        if ($ok) { Write-Log "[OK] D1 - Role DNS installe." "Green" }
        else { Write-Log "[ERREUR] D1 - Role DNS non installe." "Red" }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] D1 - Impossible de verifier le role DNS." "Red"
        return $false
    }
}

function Test-ForwardZoneExists {
    try {
        $zone = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneName -eq $DomainDns -and $_.ZoneType -eq 'Primary' }
        $ok = [bool]$zone
        if ($ok) { Write-Log "[OK] D2 - Zone de recherche directe '$DomainDns' (Primary) existe." "Green" }
        else { Write-Log "[ERREUR] D2 - Zone de recherche directe '$DomainDns' (Primary) absente." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] D2 - Impossible de verifier les zones DNS." "Red"
        return $false
    }
}

function Test-ReverseZoneExists {
    try {
        $zone = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsReverseLookupZone -eq $true }
        $ok = [bool]$zone
        if ($ok) { Write-Log "[OK] D3 - Zone de recherche inverse (ZRI) configuree." "Green" }
        else { Write-Log "[ERREUR] D3 - Aucune zone de recherche inverse configuree." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] D3 - Impossible de verifier les zones inverses." "Red"
        return $false
    }
}

function Test-RecordA {
    param([string]$TestId, [string]$HostName, [string]$ExpectedIp)
    try {
        $r = Get-DnsServerResourceRecord -ZoneName $DomainDns -Name $HostName -RRType 'A' -ErrorAction SilentlyContinue
        $ok = ($r -and ($r.RecordData.IPv4Address.IPAddressToString -eq $ExpectedIp))
        if ($ok) { Write-Log "[OK] $TestId - Enregistrement A '$HostName' = $ExpectedIp." "Green" }
        else { Write-Log "[ERREUR] $TestId - Enregistrement A '$HostName' ($ExpectedIp) absent ou incorrect." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier l'enregistrement A '$HostName'." "Red"
        return $false
    }
}

function Test-RecordCname {
    param([string]$TestId, [string]$Alias, [string]$TargetHost)
    try {
        $r = Get-DnsServerResourceRecord -ZoneName $DomainDns -Name $Alias -RRType 'CNAME' -ErrorAction SilentlyContinue
        $expected = "$TargetHost.$DomainDns."
        $ok = ($r -and ($r.RecordData.HostNameAlias -eq $expected))
        if ($ok) { Write-Log "[OK] $TestId - CNAME '$Alias' -> '$TargetHost.$DomainDns.'." "Green" }
        else {
            $actual = if ($r) { $r.RecordData.HostNameAlias } else { "absent" }
            Write-Log "[ERREUR] $TestId - CNAME '$Alias' attendu '$expected', obtenu '$actual'." "Red"
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier le CNAME '$Alias'." "Red"
        return $false
    }
}

function Test-Forwarder8888 {
    try {
        $fwds = (Get-DnsServerForwarder -ErrorAction SilentlyContinue).IPAddress.IPAddressToString
        $ok = ($fwds -contains '8.8.8.8')
        if ($ok) { Write-Log "[OK] D10 - Redirecteur 8.8.8.8 configure." "Green" }
        else { Write-Log "[ERREUR] D10 - Redirecteur 8.8.8.8 absent." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] D10 - Impossible de verifier les redirecteurs DNS." "Red"
        return $false
    }
}

$totalPoints++; if (Test-DnsRoleInstalled) { $note++ }
$totalPoints++; if (Test-ForwardZoneExists) { $note++ }
$totalPoints++; if (Test-ReverseZoneExists) { $note++ }

# Verifications des enregistrements (seulement si la zone existe)
$zrdExist = [bool](Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneName -eq $DomainDns -and $_.ZoneType -eq 'Primary' })

$totalPoints++
if ($zrdExist) { if (Test-RecordA "D4" "srv-web" $IpSrvWeb) { $note++ } }
else { Write-Log "[ERREUR] D4 - Verification A 'srv-web' ignoree (ZRD absente)." "Yellow" }

$totalPoints++
if ($zrdExist) { if (Test-RecordA "D5" "srv-bdd" $IpSrvBdd) { $note++ } }
else { Write-Log "[ERREUR] D5 - Verification A 'srv-bdd' ignoree (ZRD absente)." "Yellow" }

$totalPoints++
if ($zrdExist) { if (Test-RecordCname "D6" "glpi" "srv-web") { $note++ } }
else { Write-Log "[ERREUR] D6 - Verification CNAME 'glpi' ignoree (ZRD absente)." "Yellow" }

$totalPoints++
if ($zrdExist) { if (Test-RecordCname "D7" "intranet" "srv-web") { $note++ } }
else { Write-Log "[ERREUR] D7 - Verification CNAME 'intranet' ignoree (ZRD absente)." "Yellow" }

$totalPoints++
if ($zrdExist) { if (Test-RecordCname "D8" "phpmyadmin" "srv-bdd") { $note++ } }
else { Write-Log "[ERREUR] D8 - Verification CNAME 'phpmyadmin' ignoree (ZRD absente)." "Yellow" }

$totalPoints++
if ($zrdExist) { if (Test-RecordCname "D9" "zabbix" "srv-bdd") { $note++ } }
else { Write-Log "[ERREUR] D9 - Verification CNAME 'zabbix' ignoree (ZRD absente)." "Yellow" }

$totalPoints++; if (Test-Forwarder8888) { $note++ }

# ==========================================================
# SECTION 3 : DHCP (7 points)
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== SECTION 3 : DHCP ===" "Cyan"

function Test-DhcpRoleInstalled {
    try {
        $ok = (Get-WindowsFeature -Name "DHCP" -ErrorAction SilentlyContinue).Installed
        if ($ok) { Write-Log "[OK] H1 - Role DHCP installe." "Green" }
        else { Write-Log "[ERREUR] H1 - Role DHCP non installe." "Red" }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] H1 - Impossible de verifier le role DHCP." "Red"
        return $false
    }
}

function Test-DhcpScopeExists {
    try {
        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        $ok = [bool]$scopes
        if ($ok) { Write-Log "[OK] H2 - Au moins une etendue DHCP configuree." "Green" }
        else { Write-Log "[ERREUR] H2 - Aucune etendue DHCP configuree." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] H2 - Impossible de verifier les etendues DHCP." "Red"
        return $false
    }
}

function Test-DhcpScopeActive {
    try {
        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        $active = $scopes | Where-Object { $_.State -eq 'Active' }
        $ok = [bool]$active
        if ($ok) { Write-Log "[OK] H3 - Etendue DHCP active." "Green" }
        else { Write-Log "[ERREUR] H3 - Aucune etendue DHCP active (State != Active)." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] H3 - Impossible de verifier l'etat de l'etendue DHCP." "Red"
        return $false
    }
}

function Test-DhcpScopeRange {
    try {
        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        $expectedStart = "$Reseau.100"
        $expectedEnd = "$Reseau.200"
        $ok = $scopes | Where-Object {
            $_.StartRange.IPAddressToString -eq $expectedStart -and $_.EndRange.IPAddressToString -eq $expectedEnd
        }
        if ($ok) { Write-Log "[OK] H4 - Plage IP correcte : $expectedStart - $expectedEnd." "Green" }
        else { Write-Log "[ERREUR] H4 - Plage IP attendue $expectedStart - $expectedEnd non trouvee." "Red" }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] H4 - Impossible de verifier la plage IP DHCP." "Red"
        return $false
    }
}

function Test-DhcpOption {
    param([string]$TestId, [int]$OptionId, [string]$ExpectedValue, [string]$Description)
    try {
        $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
        if (-not $scopes) {
            Write-Log "[ERREUR] $TestId - Aucune etendue DHCP pour verifier l'option $OptionId ($Description)." "Red"
            return $false
        }
        foreach ($scope in $scopes) {
            $opt = Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId -OptionId $OptionId -ErrorAction SilentlyContinue
            if ($opt) {
                $val = $opt.Value -join ','
                $ok = ($val -eq $ExpectedValue)
                if ($ok) {
                    Write-Log "[OK] $TestId - Option DHCP $OptionId ($Description) = '$ExpectedValue'." "Green"
                    return $true
                } else {
                    Write-Log "[ERREUR] $TestId - Option DHCP $OptionId ($Description) = '$val', attendu '$ExpectedValue'." "Red"
                    return $false
                }
            }
        }
        Write-Log "[ERREUR] $TestId - Option DHCP $OptionId ($Description) non configuree sur l'etendue." "Red"
        return $false
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier l'option DHCP $OptionId ($Description)." "Red"
        return $false
    }
}

$totalPoints++; if (Test-DhcpRoleInstalled) { $note++ }
$totalPoints++; if (Test-DhcpScopeExists) { $note++ }
$totalPoints++; if (Test-DhcpScopeActive) { $note++ }
$totalPoints++; if (Test-DhcpScopeRange) { $note++ }
$totalPoints++; if (Test-DhcpOption "H5" 3 $Passerelle "Routeur") { $note++ }
$totalPoints++; if (Test-DhcpOption "H6" 6 $IpServeur "DNS") { $note++ }
$totalPoints++; if (Test-DhcpOption "H7" 15 $DomainDns "Domaine") { $note++ }

# ==========================================================
# SECTION 4 : Active Directory (23 points)
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== SECTION 4 : Active Directory ===" "Cyan"

# --- Infrastructure AD ---
function Test-AdRoleInstalled {
    try {
        $ok = (Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue).Installed
        if ($ok) { Write-Log "[OK] A1 - Role AD DS installe." "Green" }
        else { Write-Log "[ERREUR] A1 - Role AD DS non installe." "Red" }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] A1 - Impossible de verifier le role AD DS." "Red"
        return $false
    }
}

function Test-IsDomainController {
    try {
        $ok = ((Get-WmiObject Win32_ComputerSystem).DomainRole -eq 5)
        if ($ok) { Write-Log "[OK] A2 - Le serveur est un controleur de domaine (DomainRole=5)." "Green" }
        else { Write-Log "[ERREUR] A2 - Le serveur n'est pas promu en DC." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A2 - Impossible de verifier le role du serveur." "Red"
        return $false
    }
}

function Test-NTDSRunning {
    $svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
    $ok = ($svc -and $svc.Status -eq "Running")
    if ($ok) { Write-Log "[OK] A3 - Service NTDS actif." "Green" }
    else { Write-Log "[ERREUR] A3 - Service NTDS inactif ou absent." "Red" }
    return $ok
}

function Test-DiscoverDC {
    try {
        $ok = [bool](Get-ADDomainController -Discover -ErrorAction SilentlyContinue)
        if ($ok) { Write-Log "[OK] A4 - Controleur de domaine detecte." "Green" }
        else { Write-Log "[ERREUR] A4 - Aucun controleur de domaine detecte." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A4 - Impossible de decouvrir un DC." "Red"
        return $false
    }
}

function Test-ADDomainMatch {
    try {
        $ad = Get-ADDomain -ErrorAction Stop
        $ok = ($ad.DNSRoot -ieq $DomainDns)
        if ($ok) { Write-Log "[OK] A5 - Domaine AD conforme : $($ad.DNSRoot)." "Green" }
        else { Write-Log "[ERREUR] A5 - Domaine AD '$($ad.DNSRoot)' != '$DomainDns'." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A5 - Impossible d'interroger le domaine AD." "Red"
        return $false
    }
}

function Test-Forest {
    try {
        $f = Get-ADForest -ErrorAction Stop
        Write-Log "[OK] A6 - Foret detectee : $($f.Name)." "Green"
        return $true
    } catch {
        Write-Log "[ERREUR] A6 - Aucune foret AD detectee." "Red"
        return $false
    }
}

function Test-FSMO {
    try {
        $fsmo = netdom query fsmo 2>$null
        $ok = [bool]$fsmo
        if ($ok) { Write-Log "[OK] A7 - Roles FSMO attribues." "Green" }
        else { Write-Log "[ERREUR] A7 - Impossible de recuperer les roles FSMO." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A7 - Commande netdom indisponible." "Red"
        return $false
    }
}

function Test-DomainDnsResolution {
    try {
        $ok = [bool](Resolve-DnsName -Name $DomainDns -Server 127.0.0.1 -ErrorAction SilentlyContinue)
        if ($ok) { Write-Log "[OK] A8 - Resolution DNS du domaine '$DomainDns' sur 127.0.0.1 OK." "Green" }
        else { Write-Log "[ERREUR] A8 - Resolution DNS du domaine '$DomainDns' echouee sur 127.0.0.1." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A8 - Impossible de resoudre '$DomainDns' sur 127.0.0.1." "Red"
        return $false
    }
}

function Test-NtdsSysvolOnDataDrive {
    $drv = $LettreDisqueSup
    $drvRoot = $drv + "\"

    $ntdsPath = $null
    try {
        $ntdsReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
        $ntdsPath = $ntdsReg.'DSA Working Directory'
    } catch {}
    if (-not $ntdsPath) { $ntdsPath = (Join-Path $drvRoot 'Windows\NTDS') }

    $sysvolPath = $null
    try {
        $nl = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop
        $sysvolPath = $nl.'SysVol'
    } catch {}
    if (-not $sysvolPath) { $sysvolPath = (Join-Path $drvRoot 'Windows\SYSVOL') }

    function Get-Drive([string]$p) { try { return ([System.IO.Path]::GetPathRoot($p)).TrimEnd('\') } catch { return $null } }

    $ntdsDrive = Get-Drive $ntdsPath
    $sysvolDrive = Get-Drive $sysvolPath

    $okNtds = ($ntdsDrive -and ($ntdsDrive -ne 'C:') -and ($ntdsDrive -ieq $drv))
    $okSysvol = ($sysvolDrive -and ($sysvolDrive -ne 'C:') -and ($sysvolDrive -ieq $drv))

    if ($okNtds -and $okSysvol) {
        Write-Log "[OK] A9 - NTDS et SYSVOL sur $drv (hors C:)." "Green"
        return $true
    }
    if (-not $okNtds) { Write-Log "[ERREUR] A9 - NTDS sur '$ntdsPath' - attendu sur $drv." "Red" }
    if (-not $okSysvol) { Write-Log "[ERREUR] A9 - SYSVOL sur '$sysvolPath' - attendu sur $drv." "Red" }
    return $false
}

# --- OUs ---
$OURacine = "OU=@$DomainDns,$DomainDN"
$OUUtilisateurs = "OU=utilisateurs,$OURacine"
$OUOrdinateurs = "OU=ordinateurs,$OURacine"
$OUGroupes = "OU=groupes,$OURacine"
$OUServeurs = "OU=serveurs,$OURacine"

function Test-OUExists {
    param([string]$TestId, [string]$OUPath, [string]$Label)
    try {
        $ok = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue)
        if ($ok) { Write-Log "[OK] $TestId - OU '$Label' existe : $OUPath" "Green" }
        else { Write-Log "[ERREUR] $TestId - OU '$Label' absente : $OUPath" "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier l'OU '$Label'." "Red"
        return $false
    }
}

# --- Utilisateurs ---
function Test-UsersCount {
    try {
        $count = (Get-ADUser -Filter * -SearchBase $OUUtilisateurs -ErrorAction SilentlyContinue | Measure-Object).Count
        $ok = ($count -ge 4)
        if ($ok) { Write-Log "[OK] A15 - $count utilisateur(s) dans l'OU utilisateurs (>= 4)." "Green" }
        else { Write-Log "[ERREUR] A15 - $count utilisateur(s) dans l'OU utilisateurs (attendu >= 4)." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] A15 - Impossible de compter les utilisateurs dans l'OU." "Red"
        return $false
    }
}

function Test-UserExists {
    param([string]$TestId, [string]$Sam, [string]$ExpectedGivenName, [string]$ExpectedSurname)
    try {
        $user = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -Properties GivenName, Surname, Enabled -ErrorAction SilentlyContinue
        if (-not $user) {
            Write-Log "[ERREUR] $TestId - Utilisateur '$Sam' introuvable." "Red"
            return $false
        }
        $okEnabled = $user.Enabled -eq $true
        $okGiven = $user.GivenName -ieq $ExpectedGivenName
        $okSurname = $user.Surname -ieq $ExpectedSurname
        $ok = $okEnabled -and $okGiven -and $okSurname
        if ($ok) {
            Write-Log "[OK] $TestId - Utilisateur '$Sam' : actif, GivenName='$ExpectedGivenName', Surname='$ExpectedSurname'." "Green"
        } else {
            $details = @()
            if (-not $okEnabled) { $details += "desactive" }
            if (-not $okGiven) { $details += "GivenName='$($user.GivenName)' (!= '$ExpectedGivenName')" }
            if (-not $okSurname) { $details += "Surname='$($user.Surname)' (!= '$ExpectedSurname')" }
            Write-Log "[ERREUR] $TestId - Utilisateur '$Sam' : $($details -join ', ')." "Red"
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier l'utilisateur '$Sam'." "Red"
        return $false
    }
}

# --- Groupes ---
function Test-GroupExists {
    param([string]$TestId, [string]$GroupName)
    try {
        $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -Properties GroupScope, GroupCategory -ErrorAction SilentlyContinue
        if (-not $grp) {
            Write-Log "[ERREUR] $TestId - Groupe '$GroupName' introuvable." "Red"
            return $false
        }
        $okScope = $grp.GroupScope -eq 'Global'
        $okCategory = $grp.GroupCategory -eq 'Security'
        $ok = $okScope -and $okCategory
        if ($ok) {
            Write-Log "[OK] $TestId - Groupe '$GroupName' existe (Global/Security)." "Green"
        } else {
            Write-Log "[ERREUR] $TestId - Groupe '$GroupName' existe mais type incorrect (Scope=$($grp.GroupScope), Category=$($grp.GroupCategory))." "Red"
        }
        return $ok
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier le groupe '$GroupName'." "Red"
        return $false
    }
}

function Test-GroupMembers {
    param([string]$TestId, [string]$GroupName, [string[]]$ExpectedMembers)
    try {
        $members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        $allPresent = $true
        $missing = @()
        foreach ($m in $ExpectedMembers) {
            if ($members -notcontains $m) {
                $allPresent = $false
                $missing += $m
            }
        }
        if ($allPresent) {
            Write-Log "[OK] $TestId - Groupe '$GroupName' contient : $($ExpectedMembers -join ', ')." "Green"
        } else {
            Write-Log "[ERREUR] $TestId - Groupe '$GroupName' : membre(s) manquant(s) : $($missing -join ', ')." "Red"
        }
        return $allPresent
    } catch {
        Write-Log "[ERREUR] $TestId - Impossible de verifier les membres de '$GroupName'." "Red"
        return $false
    }
}

# --- Execution AD ---
$totalPoints++; if (Test-AdRoleInstalled) { $note++ }
$totalPoints++; if (Test-IsDomainController) { $note++ }
$totalPoints++; if (Test-NTDSRunning) { $note++ }
$totalPoints++; if (Test-DiscoverDC) { $note++ }
$totalPoints++; if (Test-ADDomainMatch) { $note++ }
$totalPoints++; if (Test-Forest) { $note++ }
$totalPoints++; if (Test-FSMO) { $note++ }
$totalPoints++; if (Test-DomainDnsResolution) { $note++ }
$totalPoints++; if (Test-NtdsSysvolOnDataDrive) { $note++ }

$totalPoints++; if (Test-OUExists "A10" $OURacine "racine @$DomainDns") { $note++ }
$totalPoints++; if (Test-OUExists "A11" $OUUtilisateurs "utilisateurs") { $note++ }
$totalPoints++; if (Test-OUExists "A12" $OUOrdinateurs "ordinateurs") { $note++ }
$totalPoints++; if (Test-OUExists "A13" $OUGroupes "groupes") { $note++ }
$totalPoints++; if (Test-OUExists "A14" $OUServeurs "serveurs") { $note++ }

$totalPoints++; if (Test-UsersCount) { $note++ }
$totalPoints++; if (Test-UserExists "A16" "j.dupont" "Jean" "DUPONT") { $note++ }
$totalPoints++; if (Test-UserExists "A17" "m.martin" "Marie" "MARTIN") { $note++ }
$totalPoints++; if (Test-UserExists "A18" "p.durand" "Pierre" "DURAND") { $note++ }
$totalPoints++; if (Test-UserExists "A19" "s.bernard" "Sophie" "BERNARD") { $note++ }

$totalPoints++; if (Test-GroupExists "A20" "GRP-Direction") { $note++ }
$totalPoints++; if (Test-GroupExists "A21" "GRP-Technique") { $note++ }
$totalPoints++; if (Test-GroupMembers "A22" "GRP-Direction" @("j.dupont", "m.martin")) { $note++ }
$totalPoints++; if (Test-GroupMembers "A23" "GRP-Technique" @("p.durand", "s.bernard")) { $note++ }

# ==========================================================
# RESULTAT FINAL
# ==========================================================
Write-Log "" "Cyan"
Write-Log "=== RESULTAT FINAL ===" "Cyan"

$scoreSur20 = if ($totalPoints -gt 0) { [math]::Round(($note / $totalPoints) * 20, 2) } else { 0 }
$pourcentage = if ($totalPoints -gt 0) { [math]::Round(100 * $note / $totalPoints, 1) } else { 0 }

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  RESULTAT" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ("  Points : {0} / {1}" -f $note, $totalPoints) -ForegroundColor Cyan
Write-Host ("  Note   : {0} / 20  ( {1}% )" -f $scoreSur20, $pourcentage) -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

# =========================
# Fichier JSON + Envoi
# =========================
$jsonFile = "C:\TP_DNS_DHCP_AD-$($Nom)-$($Prenom).json"
$payload = [ordered]@{
    status       = "OK"
    timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    nom          = $Nom
    prenom       = $Prenom
    domaine      = $DomainDns
    score        = $note
    total        = $totalPoints
    note         = $scoreSur20
    commentaires = ($logMessages -join "`n")
} | ConvertTo-Json -Depth 4

$payload | Set-Content -Path $jsonFile -Encoding UTF8
Write-Log "Fichier JSON genere : $jsonFile" "Green"

$serverUrl = "http://www.ericm.fr/logsapi/logreceiver.php?filename=TP_DNS_DHCP_AD-$($Nom)-$($Prenom).json"
try {
    Invoke-RestMethod -Uri $serverUrl -Method Post -Body $payload -ContentType "application/json; charset=utf-8"
    Write-Log "Fichier JSON envoye avec succes !" "Green"
} catch {
    Write-Log "Erreur lors de l'envoi du fichier JSON : $($_.Exception.Message)" "Red"
}

Write-Host ""
Read-Host "Appuyez sur Entree pour quitter"
