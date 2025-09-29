# =========================
# En-tête / Inputs
# =========================
$Nom            = Read-Host "Entrez votre nom"
$Prenom         = Read-Host "Entrez votre prénom"
$Domain         = Read-Host "Entrez le nom du domaine (FQDN ex: labo.lan)"
$LettreDisqueSup= Read-Host "Entrez la lettre du disque supplémentaire: (E: par défaut)"
if (-not $LettreDisqueSup) { $LettreDisqueSup = "E:" }

$NomServeurWeb  = Read-Host "Entrez le nom du serveur web (ex: srv-web)"
$IpServeurWeb   = Read-Host "Entrez l'IP du serveur web (ex: 192.168.62.3)"
$NomSiteWeb     = Read-Host "Entrez le nom du site web (CNAME) (ex: glpi)"
if (-not $NomSiteWeb) { $NomSiteWeb = "glpi" }

# Normalisation domaine
$DomainDns = ([string]$Domain).Trim().TrimEnd('.')
if ([string]::IsNullOrWhiteSpace($DomainDns) -or ($DomainDns -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$')) {
    throw "Le domaine saisi '$Domain' n'est pas un FQDN valide (ex: labo.lan)."
}
$DomainDN = ($DomainDns -split '\.' | ForEach-Object { "DC=$_" }) -join ','

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

Write-Log "Début des vérifications pour le domaine: $DomainDns" "Cyan"

# =========================
# Fonctions de test (retourne $true / $false et écrit dans les logs)
# =========================
function Test-DnsRoleInstalled {
    $ok = (Get-WindowsFeature -Name "DNS").Installed
    if ($ok) { Write-Log "[OK] Le rôle DNS est installé." "Green" } else { Write-Log "[ERREUR] Le rôle DNS n'est pas installé." "Red" }
    return $ok
}

function Test-PrimaryForwardZone {
    param([string]$ZoneName)
    $ok = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $ZoneName -and $_.ZoneType -eq 'Primary' }
    if ($ok){ Write-Log "[OK] La ZRD '$ZoneName' (principale) existe." "Green" } else { Write-Log "[ERREUR] La ZRD '$ZoneName' (principale) est absente." "Red" }
    return [bool]$ok
}

function Test-ReverseZoneExists {
    $ok = Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -eq $true }
    if ($ok){ Write-Log "[OK] Une zone de recherche inverse (ZRI) est configurée." "Green" } else { Write-Log "[ERREUR] Aucune ZRI configurée." "Red" }
    return [bool]$ok
}

function Test-NicDnsLoopbackOrLocalIP {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }).IPAddress
    $dnsCfg  = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
    $ok = ($dnsCfg -contains '127.0.0.1' -or $dnsCfg -contains $localIP)
    if ($ok){ Write-Log "[OK] Le DNS client pointe sur 127.0.0.1 ou l'IP locale." "Green" } else { Write-Log "[ERREUR] Le DNS client n'est pas correctement configuré." "Red" }
    return $ok
}

function Test-RecordAExact {
    param([string]$Zone,[string]$HostName,[string]$Ip)
    $r = Get-DnsServerResourceRecord -ZoneName $Zone -Name $HostName -RRType 'A' -ErrorAction SilentlyContinue
    $ok = ($r -and ($r.RecordData.IPv4Address.IPAddressToString -eq $Ip))
    if ($ok){ Write-Log "[OK] Enregistrement A '$HostName' = $Ip présent." "Green" } else { Write-Log "[ERREUR] Enregistrement A '$HostName' ($Ip) absent/incorrect." "Red" }
    return $ok
}

function Test-RecordCnameExact {
    param([string]$Zone,[string]$Alias,[string]$TargetHost)
    $r = Get-DnsServerResourceRecord -ZoneName $Zone -Name $Alias -RRType 'CNAME' -ErrorAction SilentlyContinue
    $expected = "$TargetHost.$Zone."
    $ok = ($r -and ($r.RecordData.HostNameAlias -eq $expected))
    if ($ok){ Write-Log "[OK] CNAME '$Alias' -> '$TargetHost' présent." "Green" } else { Write-Log "[ERREUR] CNAME '$Alias' -> '$TargetHost' absent/incorrect." "Red" }
    return $ok
}

function Test-Forwarder8888 {
    $fwds = (Get-DnsServerForwarder).IPAddress.IPAddressToString
    $ok = ($fwds -contains '8.8.8.8')
    if ($ok){ Write-Log "[OK] Redirecteur 8.8.8.8 configuré." "Green" } else { Write-Log "[ERREUR] Redirecteur 8.8.8.8 absent." "Red" }
    return $ok
}

function Test-StaticIP {
    $ipCfg = Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -match 'Ethernet' }
    $ok = ($ipCfg.Dhcp -eq "Disabled")
    if ($ok){ Write-Log "[OK] L'IP est configurée en statique." "Green" } else { Write-Log "[ERREUR] L'IP n'est pas configurée en statique." "Red" }
    return $ok
}

function Test-SuffixMatches {
    param([string]$ExpectedSuffix)
    $suffix = (Get-DnsClientGlobalSetting).SuffixSearchList | Select-Object -First 1
    $ok = ($suffix -eq $ExpectedSuffix)
    if ($ok){ Write-Log "[OK] Suffixe DNS principal = '$ExpectedSuffix'." "Green" } else { Write-Log "[ERREUR] Suffixe DNS '$suffix' ≠ '$ExpectedSuffix'." "Red" }
    return $ok
}

# ==== Bloc AD (11 étapes « bonus » max) ====
function Test-AdRoleInstalled {
    $ok = (Get-WindowsFeature -Name AD-Domain-Services).Installed
    if ($ok){ Write-Log "[OK] Rôle AD DS installé." "Green" } else { Write-Log "[ERREUR] Rôle AD DS non installé." "Red" }
    return $ok
}
function Test-IsDomainController {
    $ok = ((Get-WmiObject Win32_ComputerSystem).DomainRole -eq 5)
    if ($ok){ Write-Log "[OK] Le serveur est un contrôleur de domaine (DC)." "Green" } else { Write-Log "[ERREUR] Le serveur n'est pas promu en DC." "Yellow" }
    return $ok
}
function Test-NTDSRunning {
    $svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
    $ok = ($svc -and $svc.Status -eq "Running")
    if ($ok){ Write-Log "[OK] Service NTDS actif." "Green" } else { Write-Log "[ERREUR] Service NTDS inactif." "Red" }
    return $ok
}
function Test-DiscoverDC {
    $ok = [bool](Get-ADDomainController -Discover -ErrorAction SilentlyContinue)
    if ($ok){ Write-Log "[OK] Un contrôleur de domaine est détecté." "Green" } else { Write-Log "[ERREUR] Aucun contrôleur de domaine détecté." "Red" }
    return $ok
}
function Test-ADMatchesInput {
    param([string]$DomainDns)
    try {
        $ad = Get-ADDomain -Server $DomainDns -ErrorAction Stop
        $ok = ($ad.DNSRoot -ieq $DomainDns)
        if ($ok){ Write-Log "[OK] Domaine AD conforme à l'input : $($ad.DNSRoot)." "Green" } else { Write-Log "[ERREUR] Domaine détecté '$($ad.DNSRoot)' ≠ '$DomainDns'." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] Interrogation du domaine '$DomainDns' : $($_.Exception.Message)" "Red"
        return $false
    }
}
function Test-Forest {
    try { $f = Get-ADForest -ErrorAction Stop; Write-Log "[OK] Forêt détectée : $($f.Name)." "Green"; return $true }
    catch { Write-Log "[ERREUR] Aucune forêt AD détectée." "Red"; return $false }
}
function Test-FSMO {
    try {
        $fsmo = netdom query fsmo 2>$null | ForEach-Object { $_ -replace "\s+", " " }
        $ok = [bool]$fsmo
        if ($ok){ Write-Log "[OK] Rôles FSMO attribués." "Green" } else { Write-Log "[ERREUR] Impossible de récupérer les rôles FSMO." "Red" }
        return $ok
    } catch {
        Write-Log "[ERREUR] netdom indisponible." "Red"; return $false
    }
}
function Test-DomainDnsResolution {
    try {
        $dn = (Get-ADDomain).DNSRoot
        $ok = ($dn -and (Resolve-DnsName -Name $dn -Server 127.0.0.1 -ErrorAction SilentlyContinue))
        if ($ok){ Write-Log "[OK] Résolution DNS du domaine '$dn' OK." "Green" } else { Write-Log "[ERREUR] Problème de résolution DNS pour '$dn'." "Red" }
        return [bool]$ok
    } catch {
        Write-Log "[ERREUR] Impossible de récupérer le DNSRoot du domaine." "Red"
        return $false
    }
}
function Test-Replication {
    try {
        $rep = repadmin /showrepl 2>$null | Select-String "successfully"
        $ok = [bool]$rep
        if ($ok){ Write-Log "[OK] Réplication AD fonctionnelle." "Green" } else { Write-Log "[WARNING] La réplication AD ne semble pas totalement OK." "Yellow" }
        return $ok
    } catch {
        Write-Log "[WARNING] 'repadmin' indisponible." "Yellow"
        return $false
    }
}
function Test-RootOU {
    param([string]$DomainDns)
    $domainDN = (Get-ADDomain).DistinguishedName
    $ouRoot   = "OU=@$DomainDns,$domainDN"
    $ok = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouRoot'" -ErrorAction SilentlyContinue)
    if ($ok){ Write-Log "[OK] OU racine '$ouRoot' existe." "Green" } else { Write-Log "[ERREUR] OU racine '$ouRoot' absente." "Red" }
    return $ok
}
function Test-UsersOU {
    param([string]$DomainDns)
    $domainDN = (Get-ADDomain).DistinguishedName
    $ouRoot   = "OU=@$DomainDns,$domainDN"
    $ouUsers  = "OU=utilisateurs,$ouRoot"
    $ok = [bool](Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouUsers'" -ErrorAction SilentlyContinue)
    if ($ok){ Write-Log "[OK] OU 'utilisateurs' existe : $ouUsers" "Green" } else { Write-Log "[ERREUR] OU 'utilisateurs' absente." "Red" }
    return $ok
}
function Test-UsersPresence {
    param([string]$DomainDns)
    $domainDN = (Get-ADDomain).DistinguishedName
    $ouRoot   = "OU=@$DomainDns,$domainDN"
    $ouUsers  = "OU=utilisateurs,$ouRoot"
    $count = (Get-ADUser -Filter * -SearchBase "$ouUsers" -ErrorAction SilentlyContinue | Measure-Object).Count
    $ok = ($count -gt 0)
    if ($ok){ Write-Log "[OK] $count utilisateur(s) dans l'OU 'utilisateurs'." "Green" } else { Write-Log "[ERREUR] Aucun utilisateur trouvé dans l'OU 'utilisateurs'." "Red" }
    return $ok
}

function Test-NtdsSysvolOnDataDrive {
    param([string]$DataDrive)

    # Normalisation "E:" -> "E:\" et validation
    if (-not $DataDrive) { Write-Log "[ERREUR] Lettre de lecteur non fournie." "Red"; return $false }
    $drv = $DataDrive.Trim()
    if ($drv -notmatch '^[A-Za-z]:$') { Write-Log "[ERREUR] Lettre de lecteur invalide '$DataDrive'." "Red"; return $false }
    if ($drv -ieq 'C:') { Write-Log "[ERREUR] Le lecteur supplémentaire ne peut pas être C:." "Red"; return $false }
    $drvRoot = ($drv + "\")

    # Récup des chemins "réels" (Registre), avec fallback si absent
    $ntdsPath = $null
    try {
        $ntdsReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
        $ntdsPath = $ntdsReg.'DSA Working Directory'  # ex: E:\Windows\NTDS
    } catch {}
    if (-not $ntdsPath) { $ntdsPath = (Join-Path $drvRoot 'Windows\NTDS') }

    $sysvolPath = $null
    try {
        $nl = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop
        $sysvolPath = $nl.'SysVol'  # ex: E:\Windows\SYSVOL
    } catch {}
    if (-not $sysvolPath) { $sysvolPath = (Join-Path $drvRoot 'Windows\SYSVOL') }

    # Fonctions utilitaires
    function Get-Drive([string]$p){ try { return ([System.IO.Path]::GetPathRoot($p)).TrimEnd('\') } catch { return $null } }

    $ntdsDrive   = Get-Drive $ntdsPath
    $sysvolDrive = Get-Drive $sysvolPath

    $okNtds   = ($ntdsDrive -and ($ntdsDrive -ne 'C:') -and ($ntdsDrive -ieq $drv))
    $okSysvol = ($sysvolDrive -and ($sysvolDrive -ne 'C:') -and ($sysvolDrive -ieq $drv))

    # Existence des dossiers (avertissement si manquants)
    if ($okNtds -and -not (Test-Path $ntdsPath))   { Write-Log "[WARNING] Dossier NTDS introuvable : $ntdsPath." "Yellow" }
    if ($okSysvol -and -not (Test-Path $sysvolPath)) { Write-Log "[WARNING] Dossier SYSVOL introuvable : $sysvolPath." "Yellow" }

    if ($okNtds -and $okSysvol) {
        Write-Log "[OK] NTDS et SYSVOL sont sur $drv (hors C:) : NTDS='$ntdsPath', SYSVOL='$sysvolPath'." "Green"
        return $true
    }

    if (-not $okNtds)   { Write-Log "[ERREUR] NTDS sur '$ntdsPath' – attendu sur $drv* (≠ C:)." "Red" }
    if (-not $okSysvol) { Write-Log "[ERREUR] SYSVOL sur '$sysvolPath' – attendu sur $drv* (≠ C:)." "Red" }
    return $false
}


# =========================
# Lancement séquentiel des fonctions (DNS / réseau)
# =========================
$totalPoints++; if (Test-DnsRoleInstalled)             { $note++ }
$totalPoints++; if (Test-PrimaryForwardZone $DomainDns){ $note++ }
$totalPoints++; if (Test-ReverseZoneExists)            { $note++ }
$totalPoints++; if (Test-NicDnsLoopbackOrLocalIP)      { $note++ }

# Enregistrements A / CNAME (on compte dans tous les cas comme dans ton script)
$zrdExist = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $DomainDns -and $_.ZoneType -eq 'Primary' }
$totalPoints++;
if ($zrdExist){ if (Test-RecordAExact -Zone $DomainDns -HostName $NomServeurWeb -Ip $IpServeurWeb) { $note++ } }
else { Write-Log "[ERREUR] Vérification A ignorée (ZRD '$DomainDns' absente)." "Yellow" }

$totalPoints++;
if ($zrdExist){ if (Test-RecordCnameExact -Zone $DomainDns -Alias $NomSiteWeb -TargetHost $NomServeurWeb) { $note++ } }
else { Write-Log "[ERREUR] Vérification CNAME ignorée (ZRD '$DomainDns' absente)." "Yellow" }

$totalPoints++; if (Test-Forwarder8888)                { $note++ }
$totalPoints++; if (Test-StaticIP)                     { $note++ }
$totalPoints++; if (Test-SuffixMatches $DomainDns)     { $note++ }

# =========================
# Gestion du barème : +11 au dénominateur (comme ton script)
# =========================
$totalPoints = $totalPoints + 11
# Et « récupération » progressive : 1 point bonus par étape AD réussie (max 11)
$adBonusLeft = 11

# =========================
# Lancement séquentiel des fonctions (AD)
# =========================
function Add-PointIfOk($ok){
    if ($ok){
        $script:note++                   # point du test lui-même
        if ($script:adBonusLeft -gt 0){  # +1 pour « récupérer » 1/11
            $script:note++
            $script:adBonusLeft--
        }
    }
}

$totalPoints++; $t = Test-AdRoleInstalled              ; Add-PointIfOk $t
$totalPoints++; $t = Test-IsDomainController           ; Add-PointIfOk $t
$totalPoints++; $t = Test-NTDSRunning                  ; Add-PointIfOk $t
$totalPoints++; $t = Test-DiscoverDC                   ; Add-PointIfOk $t
$totalPoints++; $t = Test-ADMatchesInput $DomainDns    ; Add-PointIfOk $t
$totalPoints++; $t = Test-Forest                       ; Add-PointIfOk $t
$totalPoints++; $t = Test-FSMO                         ; Add-PointIfOk $t
$totalPoints++; $t = Test-DomainDnsResolution          ; Add-PointIfOk $t
#$totalPoints++; $t = Test-Replication                 ; Add-PointIfOk $t
$totalPoints++; $t = Test-RootOU $DomainDns            ; Add-PointIfOk $t
$totalPoints++; $t = Test-UsersOU $DomainDns           ; Add-PointIfOk $t
$totalPoints++; $t = Test-UsersPresence $DomainDns     ; Add-PointIfOk $t
$totalPoints++; $t = Test-NtdsSysvolOnDataDrive -DataDrive $LettreDisqueSup ; Add-PointIfOk $t


# =========================
# Calcul / JSON / Affichage / Envoi
# =========================
function Show-And-Send-Result {
    param(
        [string]$Nom,[string]$Prenom,[int]$Note,[int]$Total,[array]$Logs,[string]$DomainDns
    )
    $scoreSur20 = if ($Total -gt 0) { [math]::Round(($Note / $Total) * 20, 2) } else { 0 }
    $pourcentage = if ($Total -gt 0) { [math]::Round(100 * $Note / $Total, 1) } else { 0 }

    $jsonFile = "C:\AD-$($Nom)-$($Prenom).json"
    $payload = [ordered]@{
        status       = "OK"
        timestamp    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        nom          = $Nom
        prenom       = $Prenom
        domaine      = $DomainDns
        score        = $Note
        total        = $Total
        note         = $scoreSur20
        commentaires = ($Logs -join "`n")
    } | ConvertTo-Json -Depth 4

    $payload | Set-Content -Path $jsonFile -Encoding UTF8
    Write-Host "✅ Fichier JSON généré : $jsonFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "──────── Résultat ────────" -ForegroundColor Cyan
    Write-Host ("Points : {0} / {1}" -f $Note, $Total) -ForegroundColor Cyan
    Write-Host ("Note   : {0} / 20  ( {1}% )" -f $scoreSur20, $pourcentage) -ForegroundColor Cyan
    Write-Host "──────────────────────────" -ForegroundColor Cyan

    # Envoi optionnel vers logreceiver.php (même URL que ton script)
    $serverUrl = "http://www.ericm.fr/logsapi/logreceiver.php?filename=AD-$($Nom)-$($Prenom).json"
    try {
        Invoke-RestMethod -Uri $serverUrl -Method Post -Body $payload -ContentType "application/json; charset=utf-8"
        Write-Host "✅ Fichier JSON envoyé avec succès !" -ForegroundColor Green
    } catch {
        Write-Host "❌ Erreur lors de l'envoi du fichier JSON : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Show-And-Send-Result -Nom $Nom -Prenom $Prenom -Note $note -Total $totalPoints -Logs $logMessages -DomainDns $DomainDns

# Pause (si tu veux)
# Read-Host -Prompt "Appuyez sur Entrée pour quitter"
