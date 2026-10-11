#Requires -Version 5.1
<#
.SYNOPSIS
  Console de contrôle parental pour Windows 11 (Home inclus) : un interrupteur par protection.

.DESCRIPTION
  Interface graphique (WPF) : chaque protection (stratégies Edge, DNS, pare-feu, Windows) a sa description
  et son interrupteur. Quand tu désactives une protection, elle peut se réactiver toute seule après un délai
  (tâche planifiée SYSTEM à usage unique).

  Lancement : clic droit > Exécuter avec PowerShell, ou
      powershell -ExecutionPolicy Bypass -File .\ControleParental.ps1
  Le script demande l'élévation (UAC). Un compte enfant standard ne peut donc pas s'en servir.

  Mode ligne de commande (sans interface) :
      .\ControleParental.ps1 -Status
      .\ControleParental.ps1 -FsRun <json en base64>             (tâches planifiées Family Safety : reblocage automatique)
      .\ControleParental.ps1 -Diagnostic                         (comptes, navigateurs/VPN en trop, disque, démarrage)
      .\ControleParental.ps1 -Apply edge-downloads,edge-ext      (active des protections)
      .\ControleParental.ps1 -Apply recommended                  (active toutes les protections recommandées)
      .\ControleParental.ps1 -Revert edge-downloads              (désactive)
      .\ControleParental.ps1 -FsImport sites.txt -FsChild Prenom  (ajout en masse de sites autorisés ; -FsBlock pour bloquer)

  IMPORTANT : enregistre ce fichier en UTF-8 avec BOM (accents dans l'interface).
#>
[CmdletBinding()]
param(
    [string[]]$Apply,
    [string[]]$Revert,
    [switch]$Status,
    [switch]$Diagnostic,
    [string]$FsRun,
    [switch]$FsProbe,
    [string]$FsImport,
    [string]$FsChild,
    [switch]$FsBlock,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$script:CliMode = [bool]($Apply -or $Revert -or $Status -or $Diagnostic -or $FsRun -or $FsProbe -or $FsImport)

# ====================================================================== élévation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($script:CliMode) { throw 'Exécute ce script en administrateur pour utiliser -Apply, -Revert, -Status ou -Diagnostic.' }
    if (-not $PSCommandPath) { throw 'Enregistre le script en fichier .ps1 puis lance-le.' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    return
}
if (-not $script:CliMode -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    return
}

# ====================================================================== constantes
$script:AppDir    = Join-Path $env:ProgramData 'ControleParental'
$script:Installed = Join-Path $script:AppDir 'ControleParental.ps1'
$script:EdgeKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$script:FwGroup   = 'ControleParental-DNS'
$script:Dns4      = @('1.1.1.3', '1.0.0.3')                                  # Cloudflare Family
$script:Dns6      = @('2606:4700:4700::1113', '2606:4700:4700::1003')
$ExplorerPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$SystemPol   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$UacPol      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$E = $script:EdgeKey

# ====================================================================== outils registre / listes
function Set-Reg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}
function Get-ListItems([string]$Path) {
    if (-not (Test-Path $Path)) { return @() }
    $k = Get-Item -Path $Path
    @($k.GetValueNames() | Where-Object { $_ -match '^\d+$' } | Sort-Object { [int]$_ } | ForEach-Object { [string]$k.GetValue($_) })
}
function Set-ListItems([string]$Path, [string[]]$Items) {
    if (Test-Path $Path) { Remove-Item -Path $Path -Recurse -Force }
    if (-not $Items -or $Items.Count -eq 0) { return }
    New-Item -Path $Path -Force | Out-Null
    $i = 1
    foreach ($x in $Items) { New-ItemProperty -Path $Path -Name "$i" -Value $x -PropertyType String -Force | Out-Null; $i++ }
}
function Add-ListItems([string]$Path, [string[]]$Items) {
    $cur = @(Get-ListItems $Path)
    Set-ListItems $Path (@($cur) + @($Items | Where-Object { $cur -notcontains $_ }))
}
function Remove-ListItems([string]$Path, [string[]]$Items) {
    $cur = @(Get-ListItems $Path)
    Set-ListItems $Path @($cur | Where-Object { $Items -notcontains $_ })
}

# ====================================================================== outils DNS / pare-feu
function ConvertTo-BigInt([string]$Ip) {
    $b = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
    [Array]::Reverse($b)
    [System.Numerics.BigInteger]::new([byte[]]($b + [byte]0))
}
function ConvertFrom-BigInt($N, [int]$Len) {
    $src = $N.ToByteArray()
    $buf = New-Object byte[] $Len
    for ($i = 0; $i -lt $Len -and $i -lt $src.Length; $i++) { $buf[$i] = $src[$i] }
    [Array]::Reverse($buf)
    ([System.Net.IPAddress]::new($buf)).ToString()
}
function Get-ComplementRanges([string[]]$Addresses, [int]$Len) {
    # Plages couvrant tout l'espace d'adresses SAUF $Addresses (un blocage l'emporte sur une autorisation dans le pare-feu).
    $max   = [System.Numerics.BigInteger]::Pow(2, 8 * $Len) - 1
    $nums  = @($Addresses | Where-Object { $_ } | ForEach-Object { ConvertTo-BigInt $_ } | Sort-Object -Unique)
    $start = [System.Numerics.BigInteger]::Zero
    $out   = @()
    foreach ($n in $nums) {
        if ($n -gt $start) { $out += ('{0}-{1}' -f (ConvertFrom-BigInt $start $Len), (ConvertFrom-BigInt ($n - 1) $Len)) }
        $start = $n + 1
    }
    if ($start -le $max) { $out += ('{0}-{1}' -f (ConvertFrom-BigInt $start $Len), (ConvertFrom-BigInt $max $Len)) }
    $out
}
function Remove-DnsFirewall { Get-NetFirewallRule -Group $script:FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule }

# ====================================================================== sauvegarde, maintenance, diagnostic
$script:BackedUp = $false

function Backup-State {
    # Exporte l'état des clés modifiées avant le premier changement de la session (20 sauvegardes conservées).
    if ($script:BackedUp) { return }
    $script:BackedUp = $true
    $ErrorActionPreference = 'Continue'
    try {
        $dir = Join-Path $script:AppDir ('Backups\{0:yyyy-MM-dd_HHmmss}' -f (Get-Date))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $keys = [ordered]@{
            Edge          = 'HKLM\SOFTWARE\Policies\Microsoft\Edge'
            WindowsSystem = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'
            Explorer      = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            Uac           = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Location      = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
            Widgets       = 'HKLM\SOFTWARE\Policies\Microsoft\Dsh'
            UsbStorage    = 'HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR'
        }
        foreach ($k in $keys.GetEnumerator()) {
            try { & reg.exe export $k.Value (Join-Path $dir "$($k.Key).reg") /y 2>&1 | Out-Null } catch {}
        }
        try { Get-DnsClientServerAddress | Select-Object InterfaceAlias, AddressFamily, ServerAddresses | ConvertTo-Json | Set-Content -Path (Join-Path $dir 'dns.json') -Encoding UTF8 } catch {}
        $root = Join-Path $script:AppDir 'Backups'
        Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -Skip 20 | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

# Scripts exécutés par les tâches de maintenance hebdomadaires (écrits dans C:\ProgramData\ControleParental)
$script:MaintTempScript = @'
$cut  = (Get-Date).AddDays(-7)
$log  = Join-Path $env:ProgramData 'ControleParental\maintenance.log'
$dirs = @(Join-Path $env:windir 'Temp') + @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
$n = 0
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { continue }
    Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cut } | ForEach-Object {
        try { Remove-Item $_.FullName -Force -ErrorAction Stop; $n++ } catch {}
    }
}
('{0:s} fichiers temporaires de plus de 7 jours supprimés : {1}' -f (Get-Date), $n) | Add-Content -Path $log
'@

$script:MaintWingetScript = @'
$log = Join-Path $env:ProgramData 'ControleParental\maintenance.log'
$w = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
     Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $w) { ('{0:s} winget introuvable' -f (Get-Date)) | Add-Content -Path $log; return }
('{0:s} winget upgrade --all' -f (Get-Date)) | Add-Content -Path $log
& $w.FullName upgrade --all --silent --disable-interactivity --accept-source-agreements --accept-package-agreements *>> $log
'@

function Register-MaintTask([string]$TaskName, [string]$FileName, [string]$Content, [string]$At) {
    Install-Self
    $path = Join-Path $script:AppDir $FileName
    Set-Content -Path $path -Value $Content -Encoding UTF8
    $a  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$path`""
    $tr = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $At
    $p  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $s  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $tr -Principal $p -Settings $s -Force | Out-Null
}

function Get-AdminNames {
    try {
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] })
    } catch {
        $g = (Get-LocalGroup -SID 'S-1-5-32-544').Name
        @(([ADSI]"WinNT://./$g,group").Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
    }
}

function Get-DiagnosticReport {
    $r = New-Object System.Collections.Generic.List[string]

    $r.Add('=== COMPTES ===')
    try {
        $admins = @(Get-AdminNames)
        $std = @(Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' -and ($admins -notcontains $_.Name) } | ForEach-Object { $_.Name })
        $r.Add('Administrateurs : ' + ($admins -join ', '))
        $r.Add('Comptes standard : ' + ($std -join ', '))
        $r.Add("-> Le compte de l'enfant doit figurer parmi les comptes standard, jamais parmi les administrateurs.")
    } catch { $r.Add("Lecture des comptes impossible : $($_.Exception.Message)") }

    $r.Add(''); $r.Add('=== PROTECTIONS RECOMMANDÉES ===')
    $off = @($script:Tweaks | Where-Object { $_.Rec -and -not (Test-Tweak $_) } | ForEach-Object { $_.Name })
    if ($off.Count -eq 0) { $r.Add('OK : toutes les protections recommandées sont actives.') }
    else { foreach ($n in $off) { $r.Add("DÉSACTIVÉE : $n") } }

    $r.Add(''); $r.Add('=== DÉPENDANCES SUPPOSÉES DE FAMILY SAFETY (d''après le dépôt phillkimpton ; non vérifié) ===')
    $cdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc' -Name Start -ErrorAction SilentlyContinue).Start
    if ($cdp -eq 4) { $r.Add('ATTENTION : le service CDPSvc (plateforme des appareils connectés) est désactivé.') } else { $r.Add('OK : CDPSvc non désactivé.') }
    $dt = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
    if ($dt -and $dt.StartType -eq 'Disabled') { $r.Add('ATTENTION : le service DiagTrack est désactivé.') } else { $r.Add('OK : DiagTrack non désactivé.') }
    $tel = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
    if ($tel -eq 0) { $r.Add('ATTENTION : la stratégie AllowTelemetry vaut 0 (typique des scripts de durcissement pour adultes).') } else { $r.Add('OK : télémétrie non forcée à 0.') }

    $r.Add(''); $r.Add('=== DISQUE ===')
    $d = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    if ($d) {
        $free = [math]::Round($d.Free / 1GB, 1)
        if ($free -lt 10) { $r.Add("ATTENTION : seulement $free Go libres sur C:.") } else { $r.Add("OK : $free Go libres sur C:.") }
    }

    $r.Add(''); $r.Add('=== AUTRES NAVIGATEURS, VPN ET PROXYS (contournements possibles) ===')
    $names = 'chrome.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'opera_gx.exe', 'vivaldi.exe', 'tor.exe', 'openvpn.exe', 'wireguard.exe', 'psiphon3.exe', 'ultrasurf.exe', 'nordvpn.exe', 'protonvpn.exe'
    $found = 0
    $installed = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
                   "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe")
    foreach ($f in $installed) { if (Test-Path $f) { $r.Add("  installé : $f"); $found++ } }
    $roots = @(Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users' } | ForEach-Object { $_.FullName })
    foreach ($root in $roots) {
        foreach ($sub in 'AppData\Local', 'AppData\Roaming', 'Downloads', 'Desktop', 'Documents') {
            $path = Join-Path $root $sub
            if (-not (Test-Path $path)) { continue }
            Get-ChildItem -Path $path -Recurse -Depth 5 -File -Include $names -ErrorAction SilentlyContinue | ForEach-Object { $r.Add("  trouvé : $($_.FullName)"); $found++ }
        }
    }
    if ($found -eq 0) { $r.Add('OK : aucun navigateur alternatif ni outil VPN connu détecté.') }
    else { $r.Add("-> $found élément(s) à examiner : bloque-les dans Family Safety (applications) ou supprime-les.") }

    $r.Add(''); $r.Add('=== PROGRAMMES AU DÉMARRAGE (hors Microsoft/Windows) ===')
    $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Where-Object { $_.Command -notmatch 'Microsoft|Windows' })
    if ($startup.Count -eq 0) { $r.Add('OK : rien d''inattendu.') }
    else { foreach ($i in $startup) { $r.Add("  $($i.Name) : $($i.Command)") } }

    $r
}

# ====================================================================== catalogue des protections
# Rec = recommandée (incluse dans « Tout activer »). Reg = valeurs de registre ; Lists = éléments ajoutés
# à une liste de stratégies Edge (fusionnés, jamais écrasés) ; Apply/Undo/Test = logique spécifique.
$script:Tweaks = @(
    @{ Id = 'edge-ext'; Cat = 'Navigateur Edge'; Rec = $true; Name = "Bloquer l'installation d'extensions"
       Desc = "Interdit toute extension (Store, installation externe, mode développeur) et la page edge://extensions. Empêche les extensions VPN ou proxy."
       Reg = @(@{ P = $E; N = 'BlockExternalExtensions'; V = 1 }, @{ P = $E; N = 'ExtensionDeveloperModeSettings'; V = 1 })
       Lists = @(@{ Name = 'ExtensionInstallBlocklist'; Items = @('*') }, @{ Name = 'URLBlocklist'; Items = @('edge://extensions') }) },

    @{ Id = 'edge-private'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Désactiver la navigation privée et le mode invité'
       Desc = "Supprime InPrivate et les sessions invité, qui échappent à l'historique et à certains contrôles."
       Reg = @(@{ P = $E; N = 'InPrivateModeAvailability'; V = 1 }, @{ P = $E; N = 'BrowserGuestModeEnabled'; V = 0 }) },

    @{ Id = 'edge-profiles'; Cat = 'Navigateur Edge'; Rec = $true; Name = "Interdire l'ajout de profils"
       Desc = "Empêche de créer un autre profil Edge (sans compte, hors des contrôles Family Safety)."
       Reg = @(@{ P = $E; N = 'BrowserAddProfileEnabled'; V = 0 }) },

    @{ Id = 'edge-devtools'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Bloquer les outils de développement et pages techniques'
       Desc = "Désactive F12 et les pages edge://flags, inspect, net-internals et net-export."
       Reg = @(@{ P = $E; N = 'DeveloperToolsAvailability'; V = 2 })
       Lists = @(@{ Name = 'URLBlocklist'; Items = @('edge://flags', 'edge://inspect', 'edge://net-internals', 'edge://net-export') }) },

    @{ Id = 'edge-history'; Cat = 'Navigateur Edge'; Rec = $true; Name = "Empêcher l'effacement de l'historique"
       Desc = "L'historique de navigation ne peut être supprimé ni depuis les paramètres ni par raccourci."
       Reg = @(@{ P = $E; N = 'AllowDeletingBrowserHistory'; V = 0 }) },

    @{ Id = 'edge-downloads'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Bloquer les téléchargements dangereux ou indésirables'
       Desc = "Bloque les fichiers jugés dangereux ou indésirables par Edge/SmartScreen (programmes, pièces jointes suspectes...). Désactive-la temporairement pour télécharger un fichier légitime. Si le fichier reste refusé, désactive aussi « Interdire de passer outre SmartScreen »."
       Reg = @(@{ P = $E; N = 'DownloadRestrictions'; V = 2 }) },

    @{ Id = 'edge-smartscreen'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Activer SmartScreen (sites et applications indésirables)'
       Desc = "Avertit et bloque les sites d'hameçonnage, de logiciels malveillants et les applications potentiellement indésirables."
       Reg = @(@{ P = $E; N = 'SmartScreenEnabled'; V = 1 }, @{ P = $E; N = 'SmartScreenPuaEnabled'; V = 1 }) },

    @{ Id = 'edge-smartscreen-lock'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Interdire de passer outre les avertissements SmartScreen'
       Desc = "Supprime le bouton « Ignorer / Conserver » sur les sites et fichiers signalés par SmartScreen. À lever en même temps que les téléchargements si un fichier légitime est signalé."
       Reg = @(@{ P = $E; N = 'PreventSmartScreenPromptOverride'; V = 1 }, @{ P = $E; N = 'PreventSmartScreenPromptOverrideForFiles'; V = 1 }) },

    @{ Id = 'edge-safesearch'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Forcer SafeSearch (Google et Bing)'
       Desc = "Impose le filtrage strict des résultats de recherche d'images, de vidéos et de sites pour adultes."
       Reg = @(@{ P = $E; N = 'ForceGoogleSafeSearch'; V = 1 }, @{ P = $E; N = 'ForceBingSafeSearch'; V = 2 }) },

    @{ Id = 'edge-youtube'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Forcer le mode restreint strict de YouTube'
       Desc = "Masque les vidéos signalées comme inappropriées pour les mineurs (ne remplace pas la supervision)."
       Reg = @(@{ P = $E; N = 'ForceYouTubeRestrict'; V = 2 }) },

    @{ Id = 'edge-sidebar'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Masquer la barre latérale et les recommandations'
       Desc = "Désactive la barre latérale d'Edge (Copilot, Discover...) et les contenus recommandés."
       Reg = @(@{ P = $E; N = 'HubsSidebarEnabled'; V = 0 }, @{ P = $E; N = 'ShowRecommendationsEnabled'; V = 0 }) },

    @{ Id = 'edge-privacy'; Cat = 'Navigateur Edge'; Rec = $true; Name = 'Refuser position, cartes bancaires et paiements'
       Desc = "Refuse la géolocalisation aux sites, désactive le remplissage automatique des cartes et la détection de moyens de paiement."
       Reg = @(@{ P = $E; N = 'DefaultGeolocationSetting'; V = 2 }, @{ P = $E; N = 'AutofillCreditCardEnabled'; V = 0 }, @{ P = $E; N = 'PaymentMethodQueryEnabled'; V = 0 }) },

    @{ Id = 'edge-proxy'; Cat = 'Réseau et DNS'; Rec = $true; Name = 'Verrouiller le proxy dans Edge (connexion directe)'
       Desc = "Edge ne peut plus utiliser de proxy. Désactive-le pour passer par un proxy d'entreprise ou de maison (Diladele...)."
       Reg = @(@{ P = $E; N = 'ProxySettings'; V = '{"ProxyMode":"direct"}'; T = 'String' }) },

    @{ Id = 'edge-dns'; Cat = 'Réseau et DNS'; Rec = $true; Name = 'Edge : utiliser le DNS de Windows (pas de DNS sécurisé)'
       Desc = "Désactive le DNS sécurisé (DoH) et le résolveur interne d'Edge, qui contourneraient le DNS filtrant imposé à Windows."
       Reg = @(@{ P = $E; N = 'DnsOverHttpsMode'; V = 'off'; T = 'String' }, @{ P = $E; N = 'BuiltInDnsClientEnabled'; V = 0 }) },

    @{ Id = 'net-dns'; Cat = 'Réseau et DNS'; Rec = $true; Name = 'Imposer le DNS filtrant (Cloudflare Family 1.1.1.3)'
       Desc = "Pose le DNS filtrant sur toutes les cartes réseau physiques (IPv4 et IPv6). En le désactivant, le DNS repasse en automatique et le pare-feu DNS est retiré aussi."
       Apply = {
           foreach ($nic in Get-NetAdapter -Physical) {
               try   { Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses (@($script:Dns4) + @($script:Dns6)) }
               catch { Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $script:Dns4 }
           }
           Clear-DnsClientCache
       }
       Undo = {
           Remove-DnsFirewall
           foreach ($nic in Get-NetAdapter -Physical) { Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses }
           Clear-DnsClientCache
       }
       Test = {
           $nics = @(Get-NetAdapter -Physical)
           if ($nics.Count -eq 0) { return $false }
           foreach ($n in $nics) {
               $cur = @((Get-DnsClientServerAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4).ServerAddresses)
               if (($cur -join ',') -ne ($script:Dns4 -join ',')) { return $false }
           }
           $true
       } },

    @{ Id = 'net-fw'; Cat = 'Réseau et DNS'; Rec = $true; Name = 'Pare-feu : bloquer tout autre DNS (ports 53 et 853)'
       Desc = "Bloque les requêtes DNS vers tout serveur autre que le DNS filtrant, y compris le DNS chiffré dédié. Active aussi le DNS imposé. Sur un Wi-Fi à portail captif, désactive-le temporairement."
       Apply = {
           $dns = $script:ById['net-dns']
           if (-not (Test-Tweak $dns)) { Invoke-TweakApply $dns }
           Remove-DnsFirewall
           $v4 = Get-ComplementRanges $script:Dns4 4
           $v6 = Get-ComplementRanges $script:Dns6 16
           foreach ($proto in 'UDP', 'TCP') {
               New-NetFirewallRule -DisplayName "DNS non autorisé IPv4 ($proto)" -Group $script:FwGroup -Direction Outbound -Action Block -Protocol $proto -RemotePort 53 -RemoteAddress $v4 -Profile Any | Out-Null
               New-NetFirewallRule -DisplayName "DNS non autorisé IPv6 ($proto)" -Group $script:FwGroup -Direction Outbound -Action Block -Protocol $proto -RemotePort 53 -RemoteAddress $v6 -Profile Any | Out-Null
               New-NetFirewallRule -DisplayName "DNS chiffré dédié 853 ($proto)" -Group $script:FwGroup -Direction Outbound -Action Block -Protocol $proto -RemotePort 853 -Profile Any | Out-Null
           }
       }
       Undo = { Remove-DnsFirewall }
       Test = { @(Get-NetFirewallRule -Group $script:FwGroup -ErrorAction SilentlyContinue).Count -gt 0 } },

    @{ Id = 'win-smartscreen'; Cat = 'Windows'; Rec = $true; Name = 'SmartScreen des applications en mode « Bloquer »'
       Desc = "Bloque l'exécution des programmes inconnus ou malveillants, sans bouton pour passer outre. Concerne aussi ta session."
       Reg = @(@{ P = $SystemPol; N = 'EnableSmartScreen'; V = 1 }, @{ P = $SystemPol; N = 'ShellSmartScreenLevel'; V = 'Block'; T = 'String' }) },

    @{ Id = 'win-widgets'; Cat = 'Windows'; Rec = $true; Name = 'Désactiver les widgets et les suggestions web du menu Démarrer'
       Desc = "Supprime le fil d'actualités des widgets et les résultats web dans la recherche Windows (qui ouvrent Edge)."
       Reg = @(@{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; N = 'AllowNewsAndInterests'; V = 0 },
               @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; N = 'DisableSearchBoxSuggestions'; V = 1 }) },

    @{ Id = 'win-store'; Cat = 'Windows (optionnel)'; Rec = $false; Name = 'Applications du Microsoft Store uniquement'
       Desc = "Refuse l'installation de programmes téléchargés ailleurs. S'applique aussi à ton compte : désactive-le quand tu dois installer un programme."
       Reg = @(@{ P = $ExplorerPol; N = 'AicEnabled'; V = 'StoreOnly'; T = 'String' }) },

    @{ Id = 'win-usb'; Cat = 'Windows (optionnel)'; Rec = $false; Name = 'Désactiver le stockage USB'
       Desc = "Bloque les clés et disques USB, donc les navigateurs portables et programmes sur clé. S'applique à tous les comptes."
       Reg = @(@{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR'; N = 'Start'; V = 4; Restore = 3 }) },

    @{ Id = 'win-uac'; Cat = 'Windows (optionnel)'; Rec = $false; Name = "Refuser toute demande d'élévation aux comptes standard"
       Desc = "Le compte enfant n'obtient plus d'invite de mot de passe administrateur : impossible de le deviner. Pour installer, ouvre ta propre session."
       Reg = @(@{ P = $UacPol; N = 'ConsentPromptBehaviorUser'; V = 0; Restore = 3 }) },

    @{ Id = 'priv-activity'; Cat = 'Vie privée (optionnel)'; Rec = $false; Name = "Désactiver l'historique d'activités (Chronologie)"
       Desc = "Arrête l'enregistrement local des applications et fichiers ouverts, et leur envoi à Microsoft. D'après le dépôt phillkimpton/windows-child-maintenance, cela n'affecte pas les rapports d'activité de Family Safety (non vérifié de mon côté : surveille ton rapport après activation)."
       Reg = @(@{ P = $SystemPol; N = 'EnableActivityFeed'; V = 0 }, @{ P = $SystemPol; N = 'PublishUserActivities'; V = 0 }, @{ P = $SystemPol; N = 'UploadUserActivities'; V = 0 }) },

    @{ Id = 'priv-location'; Cat = 'Vie privée (optionnel)'; Rec = $false; Name = 'Désactiver les services de localisation de Windows'
       Desc = "Empêche les applications de lire la position de l'appareil. Peut aussi désactiver des fonctions de localisation de l'appareil que tu utilises toi-même (Localiser mon appareil, localisation par Family Safety) : à tester avant de l'adopter."
       Reg = @(@{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; N = 'DisableLocation'; V = 1 }) },

    @{ Id = 'maint-temp'; Cat = 'Maintenance (optionnel)'; Rec = $false; Name = 'Nettoyage hebdomadaire des fichiers temporaires'
       Desc = "Chaque dimanche à 09:00, supprime les fichiers temporaires de plus de 7 jours (Windows et tous les profils). Ne touche ni à Prefetch ni aux fichiers récents. Journal : C:\ProgramData\ControleParental\maintenance.log."
       Apply = { Register-MaintTask 'ControleParental-Maint-Temp' 'Maint-Temp.ps1' $script:MaintTempScript '09:00' }
       Undo  = { Get-ScheduledTask -TaskName 'ControleParental-Maint-Temp' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }
       Test  = { [bool](Get-CpTask 'ControleParental-Maint-Temp') } },

    @{ Id = 'maint-winget'; Cat = 'Maintenance (optionnel)'; Rec = $false; Name = 'Mise à jour hebdomadaire des applications (winget)'
       Desc = "Chaque dimanche à 08:00, lance « winget upgrade --all » sous le compte SYSTEM pour garder les applications à jour. winget sous SYSTEM est parfois capricieux : consulte maintenance.log les premières semaines. Ne remplace pas Windows Update."
       Apply = { Register-MaintTask 'ControleParental-Maint-Winget' 'Maint-Winget.ps1' $script:MaintWingetScript '08:00' }
       Undo  = { Get-ScheduledTask -TaskName 'ControleParental-Maint-Winget' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }
       Test  = { [bool](Get-CpTask 'ControleParental-Maint-Winget') } }
)
$script:ById = @{}
foreach ($t in $script:Tweaks) { $script:ById[$t.Id] = $t }

# ====================================================================== moteur
function Invoke-TweakApply($t) {
    foreach ($r in @($t.Reg)) { if ($r) { $type = 'DWord'; if ($r.T) { $type = $r.T }; Set-Reg $r.P $r.N $r.V $type } }
    foreach ($l in @($t.Lists)) { if ($l) { Add-ListItems (Join-Path $script:EdgeKey $l.Name) $l.Items } }
    if ($t.Apply) { & $t.Apply }
}
function Invoke-TweakUndo($t) {
    foreach ($r in @($t.Reg)) {
        if (-not $r) { continue }
        if ($r.ContainsKey('Restore')) { Set-Reg $r.P $r.N $r.Restore 'DWord' }
        else { Remove-ItemProperty -Path $r.P -Name $r.N -ErrorAction SilentlyContinue }
    }
    foreach ($l in @($t.Lists)) { if ($l) { Remove-ListItems (Join-Path $script:EdgeKey $l.Name) $l.Items } }
    if ($t.Undo) { & $t.Undo }
}
function Test-Tweak($t) {
    if ($t.Test) { return [bool](& $t.Test) }
    foreach ($r in @($t.Reg)) {
        if (-not $r) { continue }
        $cur = (Get-ItemProperty -Path $r.P -Name $r.N -ErrorAction SilentlyContinue).($r.N)
        if ($null -eq $cur -or "$cur" -ne "$($r.V)") { return $false }
    }
    foreach ($l in @($t.Lists)) {
        if (-not $l) { continue }
        $cur = @(Get-ListItems (Join-Path $script:EdgeKey $l.Name))
        foreach ($i in $l.Items) { if ($cur -notcontains $i) { return $false } }
    }
    $true
}

# ====================================================================== installation locale + réactivation différée
function Install-Self {
    if (-not (Test-Path $script:AppDir)) { New-Item -ItemType Directory -Path $script:AppDir -Force | Out-Null }
    & icacls.exe $script:AppDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($PSCommandPath -and ($PSCommandPath -ne $script:Installed)) { Copy-Item -Path $PSCommandPath -Destination $script:Installed -Force }
    $mod = Join-Path $PSScriptRoot 'FamilySafety.psm1'
    $modDest = Join-Path $script:AppDir 'FamilySafety.psm1'
    if ($PSScriptRoot -and (Test-Path $mod) -and ($mod -ne $modDest)) { Copy-Item -Path $mod -Destination $modDest -Force }
}
# Chaque appel à Get-ScheduledTask coûte 1 à 2 s : pendant un rafraîchissement, une seule requête alimente un cache.
$script:TaskCache = $null
function Update-TaskCache {
    $script:TaskCache = @{}
    foreach ($t in @(Get-ScheduledTask -TaskName 'ControleParental-*' -ErrorAction SilentlyContinue)) { $script:TaskCache[$t.TaskName] = $t }
}
function Get-CpTask([string]$Name) {
    if ($null -ne $script:TaskCache) { return $script:TaskCache[$Name] }
    Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}
function Get-ReapplyTask([string]$Id) { Get-CpTask "ControleParental-Reapply-$Id" }
function Remove-Reapply([string]$Id) { Get-ReapplyTask $Id | Unregister-ScheduledTask -Confirm:$false }
function Add-Reapply([string]$Id, [int]$Minutes) {
    Install-Self
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($script:Installed)`" -Apply $Id -Quiet"
    $tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes)
    $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -StartWhenAvailable
    Register-ScheduledTask -TaskName "ControleParental-Reapply-$Id" -Action $a -Trigger $tr -Principal $p -Settings $s -Force | Out-Null
}
function Get-ReapplyText([string]$Id) {
    $task = Get-ReapplyTask $Id
    if ($task -and $task.Triggers -and $task.Triggers[0].StartBoundary) {
        return ('Protection levée : réactivation automatique à {0:HH:mm}' -f [datetime]$task.Triggers[0].StartBoundary)
    }
    ''
}
function Resolve-Ids([string[]]$Ids) {
    $out = @()
    foreach ($i in $Ids) {
        if ($i -eq 'recommended') { $out += @($script:Tweaks | Where-Object { $_.Rec } | ForEach-Object { $_.Id }) }
        elseif ($i -eq 'all')     { $out += @($script:Tweaks | ForEach-Object { $_.Id }) }
        elseif ($script:ById.ContainsKey($i)) { $out += $i }
        else { throw "Identifiant inconnu : $i" }
    }
    $out | Select-Object -Unique
}

# ====================================================================== Family Safety (API non officielle)
function Import-FamilySafety {
    foreach ($candidate in @((Join-Path $PSScriptRoot 'FamilySafety.psm1'), (Join-Path $script:AppDir 'FamilySafety.psm1'))) {
        if ($candidate -and (Test-Path $candidate)) { Import-Module $candidate -Force -DisableNameChecking -Global; return $true }
    }
    $false
}

function Add-FsFollowUp([hashtable]$Cmd, [int]$Minutes) {
    # Tâche SYSTEM à usage unique (ex. rebloquer une application dans N minutes). Le jeton est lu depuis le coffre DPAPI.
    Install-Self
    $name = 'ControleParental-Fs-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $Cmd['task'] = $name
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Cmd | ConvertTo-Json -Compress)))
    $a  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($script:Installed)`" -FsRun $b64"
    $tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($Minutes)
    $p  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $s  = New-ScheduledTaskSettingsSet -StartWhenAvailable
    Register-ScheduledTask -TaskName $name -Action $a -Trigger $tr -Principal $p -Settings $s -Force | Out-Null
    $name
}

function Invoke-FsRunFromTask([string]$B64) {
    $log = Join-Path $script:AppDir 'family-safety.log'
    $cmd = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($B64)) | ConvertFrom-Json
    try {
        if (-not (Import-FamilySafety)) { throw 'Module FamilySafety.psm1 introuvable.' }
        Invoke-FsCommand $cmd
        ('{0:s} OK {1} {2}' -f (Get-Date), $cmd.cmd, $cmd.appId) | Add-Content -Path $log
    } catch {
        ('{0:s} ERREUR {1} : {2}' -f (Get-Date), $cmd.cmd, $_.Exception.Message) | Add-Content -Path $log
        return    # on garde la tâche : elle sera relancée au prochain démarrage (StartWhenAvailable) ou à la main
    }
    if ($cmd.task) { Get-ScheduledTask -TaskName $cmd.task -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false }
}

# ====================================================================== mode ligne de commande
if ($script:CliMode) {
    if ($FsRun) { Invoke-FsRunFromTask $FsRun; return }
    if ($FsProbe) {
        # Lecture seule de l'API Family Safety ; réponses dans api-samples (lisible sans élévation, jamais de jeton).
        if (-not (Import-FamilySafety)) { throw 'Module FamilySafety.psm1 introuvable.' }
        Invoke-FsProbe -OutDir (Join-Path $script:AppDir 'api-samples') | ForEach-Object { Write-Host $_ }
        return
    }
    if ($FsImport) {
        # Ajout en masse : .\ControleParental.ps1 -FsImport sites.txt -FsChild Prenom [-FsBlock]
        if (-not (Import-FamilySafety)) { throw 'Module FamilySafety.psm1 introuvable.' }
        if (-not (Test-Path $FsImport)) { throw "Fichier introuvable : $FsImport" }
        $members = @(Get-FsMembers)
        $child = @($members | Where-Object { $_.Id -eq $FsChild -or $_.FirstName -eq $FsChild -or $_.Name -eq $FsChild })[0]
        if (-not $child) { throw "Enfant introuvable : « $FsChild ». Membres : $(($members | ForEach-Object { "$($_.FirstName) ($($_.Id))" }) -join ', ')" }
        $plan = ConvertTo-FsSiteList (Get-Content -Path $FsImport -Encoding UTF8) -DefaultAllowed (-not $FsBlock)
        Write-Host ("{0} site(s) valide(s) pour {1}, {2} ligne(s) ignorée(s)." -f @($plan.Sites).Count, $child.Name, @($plan.Invalid).Count)
        $res = Add-FsWebExceptionsBulk -UserId $child.Id -Sites @($plan.Sites) -SkipAlreadySent -OnProgress {
            param($i, $n, $site, $st) if (-not $Quiet -or ($st -ne 'ok' -and $st -ne 'déjà envoyé')) { Write-Host ("[{0}/{1}] {2} : {3}" -f $i, $n, $site, $st) } }
        Write-Host ("Terminé : {0} ajouté(s), {1} déjà envoyé(s), {2} erreur(s)." -f $res.Ok, $res.Skipped, $res.Failed.Count)
        return
    }
    if (($Apply -or $Revert) -and -not $Quiet) { Backup-State }
    if ($Diagnostic) { Get-DiagnosticReport | ForEach-Object { Write-Host $_ } }
    if ($Apply)  { foreach ($id in (Resolve-Ids $Apply))  { Invoke-TweakApply $script:ById[$id]; Remove-Reapply $id; if (-not $Quiet) { Write-Host "[ON ] $id" } } }
    if ($Revert) { foreach ($id in (Resolve-Ids $Revert)) { Invoke-TweakUndo  $script:ById[$id]; if (-not $Quiet) { Write-Host "[OFF] $id" } } }
    if ($Status) {
        Update-TaskCache
        foreach ($t in $script:Tweaks) {
            $state = 'OFF'; if (Test-Tweak $t) { $state = 'ON ' }
            Write-Host ('[{0}] {1,-24} {2}' -f $state, $t.Id, $t.Name)
        }
    }
    return
}

# ====================================================================== interface graphique
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Install-Self

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Contrôle parental - Console" Width="860" Height="760" MinWidth="640" MinHeight="480"
        WindowStartupLocation="CenterScreen" Background="#F3F3F3" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style x:Key="SwitchStyle" TargetType="ToggleButton">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ToggleButton">
            <Border x:Name="Track" Width="46" Height="24" CornerRadius="12" Background="#B0B0B0">
              <Ellipse x:Name="Knob" Width="18" Height="18" Fill="White" HorizontalAlignment="Left" Margin="3,0,0,0"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Track" Property="Background" Value="#2E8B57"/>
                <Setter TargetName="Knob" Property="HorizontalAlignment" Value="Right"/>
                <Setter TargetName="Knob" Property="Margin" Value="0,0,3,0"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid Margin="14">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" FontSize="22" FontWeight="SemiBold" Text="Contrôle parental"/>
    <Border Grid.Row="1" Background="White" CornerRadius="6" Padding="10" Margin="0,10,0,0">
      <WrapPanel VerticalAlignment="Center">
        <TextBlock VerticalAlignment="Center" Text="Quand je désactive une protection, la réactiver après : "/>
        <ComboBox x:Name="Delay" Width="120" SelectedIndex="3" Margin="4,0,16,0">
          <ComboBoxItem Content="Jamais" Tag="0"/>
          <ComboBoxItem Content="15 minutes" Tag="15"/>
          <ComboBoxItem Content="30 minutes" Tag="30"/>
          <ComboBoxItem Content="1 heure" Tag="60"/>
          <ComboBoxItem Content="2 heures" Tag="120"/>
          <ComboBoxItem Content="4 heures" Tag="240"/>
        </ComboBox>
        <Button x:Name="BtnAll" Content="Tout activer (recommandé)" Padding="12,4" Margin="0,0,8,0"/>
        <Button x:Name="BtnRefresh" Content="Rafraîchir" Padding="12,4" Margin="0,0,8,0"/>
        <Button x:Name="BtnDiag" Content="Diagnostic" Padding="12,4" Margin="0,0,8,0"/>
        <Button x:Name="BtnFs" Content="Family Safety (cloud)..." Padding="12,4"/>
      </WrapPanel>
    </Border>
    <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" Margin="0,4,0,0">
      <StackPanel x:Name="Panel" Margin="0,0,8,0"/>
    </ScrollViewer>
    <TextBlock Grid.Row="3" x:Name="StatusText" Margin="0,10,0,0" TextWrapping="Wrap" Foreground="#333333"/>
  </Grid>
</Window>
'@
$window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$panel  = $window.FindName('Panel')
$script:StatusText = $window.FindName('StatusText')
$script:Delay      = $window.FindName('Delay')
$script:UI         = @{}
$bc = New-Object System.Windows.Media.BrushConverter

function Set-StatusText([string]$Text) { $script:StatusText.Text = $Text }

function Write-UiError([string]$Where, $Err) {
    # Journal des erreurs de l'interface (jamais de jeton : seuls le message et la position sont écrits).
    try {
        $msg = $Err; $pos = ''
        if ($Err -is [System.Management.Automation.ErrorRecord]) { $msg = $Err.Exception.Message; $pos = $Err.InvocationInfo.PositionMessage }
        elseif ($Err -is [Exception]) { $msg = $Err.ToString() }
        ('{0:s} [{1}] {2}{3}' -f (Get-Date), $Where, $msg, $(if ($pos) { "`r`n$pos" } else { '' })) |
            Add-Content -Path (Join-Path $script:AppDir 'ui-errors.log') -Encoding UTF8
    } catch {}
}

function Update-AllStates {
    try {
        Update-TaskCache
        foreach ($t in $script:Tweaks) {
            $ui = $script:UI[$t.Id]
            try { $ui.Toggle.IsChecked = [bool](Test-Tweak $t) } catch { Write-UiError "Test $($t.Id)" $_ }
            $ui.Info.Text = Get-ReapplyText $t.Id
        }
    } finally { $script:TaskCache = $null }
}

function Invoke-UserToggle([string]$Id, [bool]$Want) {
    $t = $script:ById[$Id]
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Backup-State
        if ($Want) {
            Invoke-TweakApply $t
            Remove-Reapply $Id
            Set-StatusText "Activée : $($t.Name)"
        } else {
            Invoke-TweakUndo $t
            $min = [int]$script:Delay.SelectedItem.Tag
            if ($min -gt 0) {
                Add-Reapply $Id $min
                Set-StatusText "Désactivée : $($t.Name) - réactivation automatique dans $min min."
            } else {
                Remove-Reapply $Id
                Set-StatusText "Désactivée : $($t.Name) - sans réactivation automatique."
            }
        }
    } catch {
        Write-UiError "Toggle $Id" $_
        Set-StatusText "Erreur : $($_.Exception.Message)"
    } finally {
        $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    }
    Update-AllStates
}

function Show-DiagnosticWindow {
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try { $text = (Get-DiagnosticReport) -join "`r`n" }
    catch { $text = "Erreur : $($_.Exception.Message)" }
    finally { $window.Cursor = [System.Windows.Input.Cursors]::Arrow }
    $w = New-Object System.Windows.Window
    $w.Title = 'Diagnostic'
    $w.Width = 820; $w.Height = 620
    $w.Owner = $window
    $w.WindowStartupLocation = 'CenterOwner'
    $tb = New-Object System.Windows.Controls.TextBox
    $tb.Text = $text
    $tb.IsReadOnly = $true
    $tb.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $tb.Margin = New-Object System.Windows.Thickness(10)
    $tb.VerticalScrollBarVisibility = 'Auto'
    $tb.HorizontalScrollBarVisibility = 'Auto'
    $w.Content = $tb
    [void]$w.ShowDialog()
}

# ---------------------------------------------------------------------- fenêtre Family Safety
$script:FsXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Family Safety (cloud)" Width="1040" Height="820" MinWidth="820" MinHeight="600"
        WindowStartupLocation="CenterOwner" Background="#F3F3F3" FontFamily="Segoe UI" FontSize="13">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="130"/>
    </Grid.RowDefinitions>
    <WrapPanel Grid.Row="0" VerticalAlignment="Center">
      <TextBlock x:Name="FsStatus" FontWeight="SemiBold" VerticalAlignment="Center" Margin="0,0,16,0"/>
      <TextBlock Text="Membre : " VerticalAlignment="Center"/>
      <ComboBox x:Name="FsMember" Width="240" Margin="0,0,8,0"/>
      <Button x:Name="BtnFsReload" Content="Actualiser" Padding="12,3"/>
    </WrapPanel>
    <TabControl Grid.Row="1" Margin="0,10,0,10">
      <TabItem Header="Connexion">
        <StackPanel Margin="12">
          <TextBlock TextWrapping="Wrap" Text="L'API utilisée n'est pas officielle : elle peut cesser de fonctionner, et son usage est probablement contraire aux conditions d'utilisation de Microsoft. Le jeton est stocké chiffré, dans un dossier réservé aux administrateurs."/>
          <Button x:Name="BtnFsAuto" Content="Se connecter (automatique, recommandé)" Margin="0,12,0,0" Padding="12,6" FontWeight="SemiBold" HorizontalAlignment="Left"/>
          <TextBlock TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#555555" Text="Une fenêtre Edge séparée s'ouvre : connecte-toi avec ton compte parent. Elle se ferme d'elle-même une fois le code récupéré (5 minutes maximum)."/>
          <TextBlock Text="Méthode manuelle, si la connexion automatique échoue :" Margin="0,18,0,0" FontWeight="SemiBold"/>
          <Button x:Name="BtnFsLogin" Content="1. Ouvrir la page de connexion Microsoft" Margin="0,8,0,0" Padding="12,4" HorizontalAlignment="Left"/>
          <TextBlock TextWrapping="Wrap" Margin="0,12,0,4" Text="2. AVANT de saisir ton mot de passe : dans l'onglet de connexion, appuie sur F12, va dans « Réseau » (Network) et coche « Conserver le journal » (Keep log). Connecte-toi avec ton compte parent (si tu l'étais déjà, recharge la page de connexion avec F12 ouvert). Une page « qui n'est normalement pas affichée » apparaît : dans F12, fais un clic droit sur la ligne oauth20_desktop.srf?code=… &gt; Copier (Copy) &gt; Copier l'URL (Copy URL), puis colle-la ici (le code expire en quelques minutes) :"/>
          <TextBox x:Name="FsRedirect" Height="60" TextWrapping="Wrap" AcceptsReturn="False"/>
          <StackPanel Orientation="Horizontal" Margin="0,8,0,0">
            <Button x:Name="BtnFsConnect" Content="3. Se connecter" Padding="12,4" Margin="0,0,8,0"/>
            <Button x:Name="BtnFsDisconnect" Content="Se déconnecter (efface le jeton)" Padding="12,4"/>
          </StackPanel>
        </StackPanel>
      </TabItem>
      <TabItem Header="Sites web">
        <Grid Margin="10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="380"/>
            <ColumnDefinition Width="*"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0" Margin="0,0,14,0">
            <TextBlock x:Name="FsWebTitle" Text="Filtre web" FontWeight="SemiBold" FontSize="15" TextWrapping="Wrap"/>
            <Border Background="White" CornerRadius="6" Padding="12" Margin="0,8,0,0">
              <StackPanel>
                <TextBlock x:Name="FsFlagFilter" TextWrapping="Wrap"/>
                <TextBlock x:Name="FsFlagAllowedOnly" TextWrapping="Wrap" Margin="0,6,0,0"/>
                <TextBlock x:Name="FsFlagBrowsers" TextWrapping="Wrap" Margin="0,6,0,0"/>
                <TextBlock x:Name="FsFlagEdu" TextWrapping="Wrap" Margin="0,6,0,0"/>
              </StackPanel>
            </Border>
            <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="11" Margin="0,8,0,0" Text="Lecture seule. Microsoft ne communique plus les listes de sites à cette API : elles se consultent et se suppriment sur le site officiel."/>
            <Button x:Name="BtnFsOfficial" Content="Gérer les sites sur le site officiel" Padding="12,6" FontWeight="SemiBold" Margin="0,12,0,0" HorizontalAlignment="Left"/>
            <Button x:Name="BtnFsBlocked" Content="Tentatives bloquées..." Padding="12,6" Margin="0,8,0,0" HorizontalAlignment="Left"/>
            <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="11" Margin="0,4,0,0" Text="Un site s'affiche mal ? Fais-le ouvrir sur la session de l'enfant, puis regarde ici ce que le filtre a bloqué."/>
            <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
              <Button x:Name="BtnFsWebReload" Content="Relire" Padding="12,4" Margin="0,0,8,0"/>
              <Button x:Name="BtnFsWebRaw" Content="Réponse brute (diagnostic)" Padding="10,4" FontSize="11"/>
            </StackPanel>
            <TextBlock x:Name="FsRequestsTitle" Text="Demandes d'accès en attente" FontWeight="SemiBold" Margin="0,18,0,4"/>
            <ListBox x:Name="FsRequests" Height="90"/>
          </StackPanel>
          <StackPanel Grid.Column="1">
            <TextBlock Text="Ajouter un site" FontWeight="SemiBold" FontSize="14"/>
            <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="11" Margin="0,4,0,6" Text="Par l'API mobile (ajout vérifié le 11/10/2026). Le retrait d'un site se fait sur le site officiel."/>
            <StackPanel Orientation="Horizontal">
              <TextBox x:Name="FsSite" Width="260" Margin="0,0,8,0" VerticalContentAlignment="Center"/>
              <ComboBox x:Name="FsSiteMode" Width="100" SelectedIndex="0" Margin="0,0,8,0">
                <ComboBoxItem Content="Autoriser"/>
                <ComboBoxItem Content="Bloquer"/>
              </ComboBox>
              <Button x:Name="BtnFsSiteAdd" Content="Ajouter" Padding="12,3"/>
            </StackPanel>
            <TextBlock Text="Ajout en masse" FontWeight="SemiBold" FontSize="14" Margin="0,18,0,0"/>
            <TextBlock TextWrapping="Wrap" Foreground="#666666" FontSize="11" Margin="0,4,0,6" Text="Un site par ligne : site.com, adresse complète, ou syntaxe de filtres @@||site.com^ (autoriser) / ||site.com^ (bloquer). Les lignes simples prennent le mode choisi ci-dessous. Commentaires : lignes commençant par ! ou #."/>
            <TextBox x:Name="FsBulk" Height="170" AcceptsReturn="True" TextWrapping="NoWrap" FontFamily="Consolas"
                     VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
            <WrapPanel Margin="0,8,0,0">
              <Button x:Name="BtnFsBulkFile" Content="Charger un fichier..." Padding="10,3" Margin="0,0,12,4"/>
              <TextBlock Text="Lignes simples : " VerticalAlignment="Center" Margin="0,0,0,4"/>
              <ComboBox x:Name="FsBulkMode" Width="100" SelectedIndex="0" Margin="0,0,12,4">
                <ComboBoxItem Content="Autoriser"/>
                <ComboBoxItem Content="Bloquer"/>
              </ComboBox>
              <CheckBox x:Name="FsBulkSkip" Content="Ne pas renvoyer les sites déjà envoyés" IsChecked="True" VerticalAlignment="Center" Margin="0,0,0,4"/>
            </WrapPanel>
            <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
              <Button x:Name="BtnFsBulkCheck" Content="Analyser" Padding="12,3" Margin="0,0,8,0"/>
              <Button x:Name="BtnFsBulkSend" Content="Envoyer" Padding="14,3" FontWeight="SemiBold" Margin="0,0,8,0"/>
              <Button x:Name="BtnFsBulkStop" Content="Arrêter" Padding="12,3" IsEnabled="False"/>
            </StackPanel>
            <ProgressBar x:Name="FsBulkProgress" Height="10" Margin="0,10,0,0"/>
            <TextBlock x:Name="FsBulkStatus" TextWrapping="Wrap" Margin="0,4,0,0" Foreground="#444444"/>
          </StackPanel>
        </Grid>
      </TabItem>
      <TabItem Header="Applications">
        <StackPanel Margin="12">
          <StackPanel Orientation="Horizontal">
            <Button x:Name="BtnFsAppsLoad" Content="Charger les applications (aujourd'hui)" Padding="12,3" Margin="0,0,8,0"/>
            <Button x:Name="BtnFsAppBlock" Content="Bloquer" Padding="12,3" Margin="0,0,8,0"/>
            <Button x:Name="BtnFsAppUnblock" Content="Débloquer" Padding="12,3" Margin="0,0,8,0"/>
            <Button x:Name="BtnFsAppTemp" Content="Débloquer, puis rebloquer après la durée" Padding="12,3"/>
          </StackPanel>
          <ListView x:Name="FsApps" Height="300" Margin="0,10,0,0" SelectionMode="Single">
            <ListView.View>
              <GridView>
                <GridViewColumn Header="Application" Width="420" DisplayMemberBinding="{Binding Name}"/>
                <GridViewColumn Header="Utilisation (min)" Width="130" DisplayMemberBinding="{Binding UsageMinutes}"/>
                <GridViewColumn Header="État" Width="110" DisplayMemberBinding="{Binding State}"/>
              </GridView>
            </ListView.View>
          </ListView>
        </StackPanel>
      </TabItem>
      <TabItem Header="Appareil">
        <StackPanel Margin="12">
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="Plateforme : " VerticalAlignment="Center"/>
            <ComboBox x:Name="FsTarget" Width="110" SelectedIndex="0" Margin="0,0,16,0">
              <ComboBoxItem Content="Desktop"/>
              <ComboBoxItem Content="Mobile"/>
              <ComboBoxItem Content="Xbox"/>
            </ComboBox>
            <TextBlock Text="Durée : " VerticalAlignment="Center"/>
            <ComboBox x:Name="FsMinutes" Width="120" SelectedIndex="2">
              <ComboBoxItem Content="5 minutes" Tag="5"/>
              <ComboBoxItem Content="15 minutes" Tag="15"/>
              <ComboBoxItem Content="30 minutes" Tag="30"/>
              <ComboBoxItem Content="1 heure" Tag="60"/>
              <ComboBoxItem Content="2 heures" Tag="120"/>
              <ComboBoxItem Content="4 heures" Tag="240"/>
            </ComboBox>
          </StackPanel>
          <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
            <Button x:Name="BtnFsDevBlock" Content="Bloquer la plateforme pendant la durée" Padding="12,3" Margin="0,0,8,0"/>
            <Button x:Name="BtnFsDevCancel" Content="Annuler le blocage" Padding="12,3"/>
          </StackPanel>
          <TextBlock TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#555555" Text="Première utilisation : essaie avec 5 minutes et vérifie que le blocage se lève bien à l'heure (gestion du fuseau horaire non confirmée)."/>
          <TextBlock Text="Limite quotidienne (tous les jours) :" Margin="0,18,0,4" FontWeight="SemiBold"/>
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="Minutes : " VerticalAlignment="Center"/>
            <TextBox x:Name="FsLimitMin" Width="60" Text="120" Margin="0,0,16,0"/>
            <TextBlock Text="Plage autorisée (HH:MM:SS, facultatif) de " VerticalAlignment="Center"/>
            <TextBox x:Name="FsLimitBegin" Width="80" Text="08:00:00" Margin="4,0,4,0"/>
            <TextBlock Text="à" VerticalAlignment="Center"/>
            <TextBox x:Name="FsLimitEnd" Width="80" Text="20:00:00" Margin="4,0,16,0"/>
            <Button x:Name="BtnFsLimit" Content="Appliquer" Padding="12,3"/>
          </StackPanel>
          <TextBlock TextWrapping="Wrap" Margin="0,6,0,0" Foreground="#555555" Text="Remplace les limites de la plateforme choisie. Laisse la plage vide pour ne limiter que la durée."/>
        </StackPanel>
      </TabItem>
      <TabItem Header="Activité">
        <StackPanel Margin="12">
          <WrapPanel>
            <Button x:Name="BtnFsUsage" Content="Temps d'écran aujourd'hui" Padding="12,3" Margin="0,0,8,6"/>
            <Button x:Name="BtnFsWebAct" Content="Historique web (24 h)" Padding="12,3" Margin="0,0,8,6"/>
            <Button x:Name="BtnFsSearchAct" Content="Recherches (24 h)" Padding="12,3" Margin="0,0,8,6"/>
            <Button x:Name="BtnFsDevices" Content="Appareils" Padding="12,3" Margin="0,0,8,6"/>
          </WrapPanel>
          <TextBlock TextWrapping="Wrap" Foreground="#555555" Text="Les résultats s'affichent dans la zone du bas. Le format des réponses d'historique n'est pas documenté : l'affichage est volontairement brut."/>
        </StackPanel>
      </TabItem>
    </TabControl>
    <TextBox Grid.Row="2" x:Name="FsOut" IsReadOnly="True" FontFamily="Consolas" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
  </Grid>
</Window>
'@

function Write-FsOut([string]$Text) {
    $o = $script:Fs.Out
    $o.AppendText(('[{0:HH:mm:ss}] {1}' -f (Get-Date), $Text) + "`r`n")
    $o.ScrollToEnd()
}
function Invoke-FsUi([scriptblock]$Block) {
    $script:Fs.Window.Cursor = [System.Windows.Input.Cursors]::Wait
    try { & $Block } catch { Write-UiError 'Family Safety' $_; Write-FsOut ('Erreur : ' + $_.Exception.Message) }
    finally { $script:Fs.Window.Cursor = [System.Windows.Input.Cursors]::Arrow }
}
function Get-FsSelectedMember {
    $item = $script:Fs.Member.SelectedItem
    if (-not $item) { throw "Choisis d'abord un membre (connecte-toi, puis « Actualiser »)." }
    [string]$item.Tag
}
function Get-FsMinutesChoice { [int]$script:Fs.Minutes.SelectedItem.Tag }
function Update-FsHeader {
    if (Test-FsConnected) { $script:Fs.Status.Text = 'Connecté à Family Safety' } else { $script:Fs.Status.Text = 'Non connecté' }
}
function Update-FsMembers {
    $script:Fs.Member.Items.Clear()
    if (-not (Test-FsConnected)) { return }
    foreach ($m in @(Get-FsMembers)) {
        $i = New-Object System.Windows.Controls.ComboBoxItem
        $i.Content = "$($m.Name) ($($m.Role))"; $i.Tag = $m.Id
        [void]$script:Fs.Member.Items.Add($i)
    }
    if ($script:Fs.Member.Items.Count -gt 0) { $script:Fs.Member.SelectedIndex = 0 }
    Write-FsOut "$($script:Fs.Member.Items.Count) membre(s) avec la sécurité numérique activée."
}
function Format-FsRecords($Obj, [int]$Max = 60) {
    if ($null -eq $Obj) { return '(aucune donnée)' }
    $arr = $null
    foreach ($p in $Obj.PSObject.Properties) {
        if ($p.Value -is [System.Array] -and $p.Value.Count -gt 0 -and $p.Value[0] -isnot [string]) { $arr = $p.Value; break }
    }
    if ($arr) {
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($item in ($arr | Select-Object -First $Max)) {
            $parts = foreach ($q in $item.PSObject.Properties) {
                $v = $q.Value
                if ($v -is [string] -or $v -is [ValueType]) { "$($q.Name)=$v" } else { "$($q.Name)=" + ($v | ConvertTo-Json -Compress -Depth 4) }
            }
            $lines.Add(($parts -join ' | '))
        }
        if ($arr.Count -gt $Max) { $lines.Add("... (+$($arr.Count - $Max) autres)") }
        return ($lines -join "`r`n")
    }
    $json = $Obj | ConvertTo-Json -Depth 6
    if ($json.Length -gt 12000) { $json = $json.Substring(0, 12000) + "`r`n... (tronqué)" }
    $json
}

function Format-FsFlag([string]$Label, $Value) {
    $t = '?'; if ($Value -eq $true) { $t = 'oui' } elseif ($Value -eq $false) { $t = 'NON' }
    "$($Label) : $t"
}

function Update-FsWebView {
    # Réglages du filtre web lus par l'API mobile (les listes de sites n'y figurent plus).
    $id = Get-FsSelectedMember
    $name = [string]$script:Fs.Member.SelectedItem.Content
    $r = Get-FsWebRestrictions -UserId $id
    $edu = $null; if ($r.categories -and $r.categories.PSObject.Properties['educ']) { $edu = [bool]$r.categories.educ }
    $script:Fs.WebTitle.Text = "Filtre web : $name"
    $script:Fs.FlagFilter.Text = Format-FsFlag 'Filtrer les sites web et les recherches inappropriés' $r.enabled
    $script:Fs.FlagAllowedOnly.Text = Format-FsFlag 'Utiliser uniquement les sites web autorisés' $r.useAllowedListOnly
    $script:Fs.FlagBrowsers.Text = Format-FsFlag "Bloquer les navigateurs autres qu'Edge" $r.blockedBrowsersEnabled
    $script:Fs.FlagEdu.Text = Format-FsFlag 'Toujours autoriser les sites web éducatifs' $edu

    $script:Fs.Requests.Items.Clear()
    $req = @()
    try { $req = @((Get-FsPendingRequests).pendingRequests | Where-Object { $null -ne $_ }) } catch { Write-FsOut "Demandes d'accès illisibles : $($_.Exception.Message)" }
    foreach ($q in $req) {
        $txt = $null
        foreach ($k in 'website', 'url', 'domain', 'appName', 'displayName') { if ($q.PSObject.Properties[$k]) { $txt = [string]$q.$k; break } }
        if (-not $txt) { $txt = $q | ConvertTo-Json -Compress -Depth 4 }
        [void]$script:Fs.Requests.Items.Add($txt)
    }
    $script:Fs.RequestsTitle.Text = "Demandes d'accès en attente : $($req.Count)"
    Write-FsOut "Filtre web de $name relu."
}

$script:FsBlockedXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Tentatives bloquées" Width="680" Height="560" MinWidth="520" MinHeight="400"
        WindowStartupLocation="CenterOwner" Background="#F3F3F3" FontFamily="Segoe UI" FontSize="13">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock x:Name="BTitle" Grid.Row="0" FontWeight="SemiBold" FontSize="15"/>
    <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,10,0,0">
      <TextBlock Text="Période : " VerticalAlignment="Center"/>
      <ComboBox x:Name="BPeriod" Width="140" SelectedIndex="0" Margin="0,0,8,0">
        <ComboBoxItem Content="Dernière heure" Tag="1"/>
        <ComboBoxItem Content="24 heures" Tag="24"/>
        <ComboBoxItem Content="7 jours" Tag="168"/>
      </ComboBox>
      <Button x:Name="BLoad" Content="Charger" Padding="12,3" Margin="0,0,8,0"/>
      <Button x:Name="BAll" Content="Tout sélectionner" Padding="10,3"/>
    </StackPanel>
    <ListView x:Name="BList" Grid.Row="2" Margin="0,10,0,0" SelectionMode="Extended">
      <ListView.View>
        <GridView>
          <GridViewColumn Header="Domaine bloqué" Width="380" DisplayMemberBinding="{Binding Domain}"/>
          <GridViewColumn Header="Tentatives" Width="90" DisplayMemberBinding="{Binding Attempts}"/>
          <GridViewColumn Header="Dernière" Width="110" DisplayMemberBinding="{Binding Last}"/>
        </GridView>
      </ListView.View>
    </ListView>
    <TextBlock x:Name="BInfo" Grid.Row="3" TextWrapping="Wrap" Foreground="#555555" Margin="0,8,0,0"
               Text="Sélectionne les domaines à autoriser (Ctrl+clic ou Maj+clic), puis ajoute-les à la zone « Ajout en masse ». N'autorise que ce qui est nécessaire : publicité et pistage sont inutiles."/>
    <StackPanel Grid.Row="4" Orientation="Horizontal" Margin="0,10,0,0">
      <Button x:Name="BAdd" Content="Ajouter la sélection à l'ajout en masse" Padding="12,4" FontWeight="SemiBold" Margin="0,0,8,0"/>
      <Button x:Name="BRaw" Content="Enregistrer la réponse brute" Padding="10,4" Margin="0,0,8,0"/>
      <Button x:Name="BClose" Content="Fermer" Padding="12,4"/>
    </StackPanel>
  </Grid>
</Window>
'@

function Show-FsBlockedWindow {
    $id = Get-FsSelectedMember
    $name = [string]$script:Fs.Member.SelectedItem.Content
    $w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$script:FsBlockedXaml)))
    $w.Owner = $script:Fs.Window
    $script:Fb = @{ Window = $w; Id = $id; Name = $name; Raw = $null }
    foreach ($n in 'BTitle', 'BPeriod', 'BList', 'BInfo') { $script:Fb[$n] = $w.FindName($n) }
    $script:Fb.BTitle.Text = "Sites bloqués par le filtre : $name"
    $script:Fb.BPeriod.SelectedIndex = 1

    $load = {
        $w2 = $script:Fb.Window
        $w2.Cursor = [System.Windows.Input.Cursors]::Wait
        try {
            $h = [int]$script:Fb.BPeriod.SelectedItem.Tag
            $r = Get-FsBlockedSites -UserId $script:Fb.Id -Hours $h
            $script:Fb.Raw = $r.Raw
            $script:Fb.BList.ItemsSource = [object[]]@($r.Items)
            $n = @($r.Items).Count
            if ($n -eq 0) {
                $script:Fb.BInfo.Text = "Aucun domaine bloqué reconnu sur la période (lecture : $($r.Mode)). Si l'enfant a bien rencontré un blocage, clique sur « Enregistrer la réponse brute » : le format du rapport est peut-être différent de celui attendu."
            } else {
                $script:Fb.BInfo.Text = "$n domaine(s) bloqué(s) (lecture : $($r.Mode)). Sélectionne ceux à autoriser (Ctrl+clic), puis « Ajouter la sélection »."
            }
            Write-FsOut "Tentatives bloquées ($($script:Fb.Name), $h h) : $n domaine(s)."
        } catch {
            Write-UiError 'Tentatives bloquées' $_
            $script:Fb.BInfo.Text = "Erreur : $($_.Exception.Message)"
        } finally { $w2.Cursor = [System.Windows.Input.Cursors]::Arrow }
    }
    $script:FbLoad = $load
    $w.FindName('BLoad').Add_Click({ & $script:FbLoad })
    $w.FindName('BAll').Add_Click({ $script:Fb.BList.SelectAll() })
    $w.FindName('BClose').Add_Click({ $script:Fb.Window.Close() })
    $w.FindName('BAdd').Add_Click({
        $sel = @($script:Fb.BList.SelectedItems | ForEach-Object { $_.Domain })
        if ($sel.Count -eq 0) { $script:Fb.BInfo.Text = "Sélectionne d'abord au moins un domaine."; return }
        $existing = @($script:Fs.Bulk.Text -split '\r?\n' | ForEach-Object { $_.Trim().ToLowerInvariant() })
        $new = @($sel | Where-Object { $existing -notcontains $_ })
        $txt = $script:Fs.Bulk.Text.TrimEnd()
        if ($new.Count) {
            if ($txt) { $txt += "`r`n" }
            $txt += "! Tentatives bloquées ($(Get-Date -Format 'dd/MM HH:mm'))`r`n" + ($new -join "`r`n")
            $script:Fs.Bulk.Text = $txt
        }
        $script:Fb.BInfo.Text = "$($new.Count) domaine(s) ajouté(s) à la zone « Ajout en masse » ($($sel.Count - $new.Count) déjà présent(s)). Vérifie le mode « Autoriser », puis Analyser et Envoyer."
        Write-FsOut "$($new.Count) domaine(s) bloqué(s) copiés dans l'ajout en masse."
    })
    $w.FindName('BRaw').Add_Click({
        if ($null -eq $script:Fb.Raw) { $script:Fb.BInfo.Text = "Charge d'abord le rapport."; return }
        $dir = Join-Path $script:AppDir 'api-samples'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $f = Join-Path $dir 'web-activity.json'
        $script:Fb.Raw | ConvertTo-Json -Depth 15 | Set-Content -Path $f -Encoding UTF8
        $script:Fb.BInfo.Text = "Réponse enregistrée : $f (historique web de l'enfant : supprime le fichier une fois analysé)."
    })
    $w.Add_ContentRendered({ & $script:FbLoad })
    [void]$w.ShowDialog()
}

function Get-FsBulkPlan([switch]$Report) {
    # Analyse la liste collée : sites valides, lignes ignorées, sites déjà envoyés par la console.
    $id = Get-FsSelectedMember
    $r = ConvertTo-FsSiteList @($script:Fs.Bulk.Text) -DefaultAllowed ($script:Fs.BulkMode.SelectedIndex -eq 0)
    $sites = @($r.Sites)
    $sent = Get-FsSentSites $id
    $already = @($sites | Where-Object { $p = $sent[$_.Website]; $p -and [bool]$p.allowed -eq [bool]$_.Allowed })
    $skip = [bool]$script:Fs.BulkSkip.IsChecked
    $toSend = $sites.Count; if ($skip) { $toSend -= $already.Count }
    $nA = @($sites | Where-Object { $_.Allowed }).Count
    $plan = [pscustomobject]@{ Sites = $sites; Invalid = @($r.Invalid); Already = $already.Count; ToSend = $toSend; Allowed = $nA; Blocked = $sites.Count - $nA; Skip = $skip }
    if ($Report) {
        $txt = '{0} site(s) valide(s) : {1} à autoriser, {2} à bloquer. Déjà envoyés par la console : {3}{4}. À envoyer : {5}.' -f `
            $sites.Count, $plan.Allowed, $plan.Blocked, $plan.Already, $(if ($skip) { ' (sautés)' } else { ' (renvoyés)' }), $toSend
        if ($plan.Invalid.Count) { $txt += " Lignes ignorées : $($plan.Invalid.Count)." }
        $script:Fs.BulkStatus.Text = $txt
        Write-FsOut $txt
        foreach ($l in @($plan.Invalid | Select-Object -First 15)) { Write-FsOut "   ignorée : $l" }
    }
    $plan
}

function Send-FsBulk {
    $plan = Get-FsBulkPlan -Report
    if ($plan.ToSend -le 0) { Write-FsOut 'Rien à envoyer.'; return }
    $name = [string]$script:Fs.Member.SelectedItem.Content
    $sec = [math]::Ceiling($plan.ToSend * 0.8)
    $msg = "Envoyer $($plan.ToSend) site(s) à Family Safety pour $name ?`r`n`r`n$($plan.Allowed) à autoriser, $($plan.Blocked) à bloquer.`r`nDurée estimée : environ $sec s."
    if ([System.Windows.MessageBox]::Show($msg, 'Ajout en masse', 'YesNo', 'Question') -ne 'Yes') { Write-FsOut 'Envoi annulé.'; return }

    $id = Get-FsSelectedMember
    $fs = $script:Fs
    $btnSend = $fs.Window.FindName('BtnFsBulkSend'); $btnStop = $fs.Window.FindName('BtnFsBulkStop')
    $script:FsBulkStop = $false
    $btnSend.IsEnabled = $false; $btnStop.IsEnabled = $true; $fs.Member.IsEnabled = $false; $fs.Bulk.IsReadOnly = $true
    $fs.BulkProgress.Minimum = 0; $fs.BulkProgress.Maximum = [math]::Max(1, $plan.Sites.Count); $fs.BulkProgress.Value = 0
    # Garde l'interface réactive (progression, bouton Arrêter) entre deux envois.
    $script:FsPump = {
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        [void]$script:Fs.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background,
            [System.Windows.Threading.DispatcherOperationCallback] { param($f) $f.Continue = $false; $null }, $frame)
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    }
    $onProgress = {
        param($i, $n, $site, $st)
        $script:Fs.BulkProgress.Value = $i
        $script:Fs.BulkStatus.Text = "$i / $n : $site ($st)"
        if ($st -ne 'ok' -and $st -ne 'déjà envoyé') { Write-FsOut "   ERREUR $site : $st" }
        & $script:FsPump
    }
    Write-FsOut "Ajout en masse pour $name : $($plan.ToSend) site(s)..."
    try {
        $res = Add-FsWebExceptionsBulk -UserId $id -Sites $plan.Sites -SkipAlreadySent:$plan.Skip -OnProgress $onProgress -ShouldStop { [bool]$script:FsBulkStop }
    } finally {
        $btnSend.IsEnabled = $true; $btnStop.IsEnabled = $false; $fs.Member.IsEnabled = $true; $fs.Bulk.IsReadOnly = $false
    }
    $sum = 'Terminé : {0} ajouté(s), {1} déjà envoyé(s), {2} erreur(s){3}.' -f $res.Ok, $res.Skipped, $res.Failed.Count, $(if ($res.Stopped) { ', INTERROMPU' } else { '' })
    $fs.BulkStatus.Text = $sum
    Write-FsOut $sum
    Write-FsOut "Journal : $(Join-Path $script:AppDir 'sites-ajoutes.log'). Vérifie quelques sites sur le site officiel."
}

function Show-FamilySafetyWindow {
    if (-not (Import-FamilySafety)) { [System.Windows.MessageBox]::Show('FamilySafety.psm1 est introuvable : place-le à côté de ControleParental.ps1.', 'Family Safety') | Out-Null; return }
    $w = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader ([xml]$script:FsXaml)))
    $w.Owner = $window
    $script:Fs = @{ Window = $w }
    foreach ($n in 'FsStatus', 'FsMember', 'FsRedirect', 'FsSite', 'FsSiteMode', 'FsApps', 'FsTarget', 'FsMinutes',
                   'FsLimitMin', 'FsLimitBegin', 'FsLimitEnd', 'FsOut', 'FsWebTitle', 'FsFlagFilter', 'FsFlagAllowedOnly', 'FsFlagBrowsers',
                   'FsFlagEdu', 'FsRequests', 'FsRequestsTitle', 'FsBulk', 'FsBulkMode', 'FsBulkSkip', 'FsBulkProgress', 'FsBulkStatus') { $script:Fs[$n.Substring(2)] = $w.FindName($n) }

    $w.FindName('BtnFsAuto').Add_Click({ Invoke-FsUi {
        $fsw = $script:Fs.Window
        Write-FsOut 'Fenêtre Edge ouverte : connecte-toi avec ton compte parent...'
        $fsw.IsEnabled = $false
        try {
            # Garde l'interface vivante (redessin) pendant l'attente, sans accepter de clics.
            $pump = {
                $frame = New-Object System.Windows.Threading.DispatcherFrame
                [void]$fsw.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background,
                    [System.Windows.Threading.DispatcherOperationCallback] { param($f) $f.Continue = $false; $null }, $frame)
                [System.Windows.Threading.Dispatcher]::PushFrame($frame)
            }
            Connect-FsWithEdge -OnWait $pump
        } finally { $fsw.IsEnabled = $true }
        Write-FsOut 'Connecté.'; Update-FsHeader; Update-FsMembers } })
    $w.FindName('BtnFsLogin').Add_Click({ Invoke-FsUi {
        # Lancé depuis une session élevée, le navigateur peut ne pas s'ouvrir : l'adresse est aussi copiée.
        $url = Get-FsLoginUrl
        [System.Windows.Clipboard]::SetText($url)
        Write-FsOut "Adresse de connexion copiée dans le presse-papiers. Si aucun navigateur ne s'ouvre, colle-la dans Edge."
        try { Start-Process $url; Write-FsOut 'Page de connexion ouverte dans ton navigateur.' }
        catch { Write-UiError 'Ouverture du navigateur' $_; Write-FsOut "Le navigateur ne s'est pas ouvert ($($_.Exception.Message))." } } })
    $w.FindName('BtnFsConnect').Add_Click({ Invoke-FsUi {
        if ([string]::IsNullOrWhiteSpace($script:Fs.Redirect.Text)) { throw "Colle d'abord l'URL contenant « code= » (étape 2)." }
        Connect-Fs -RedirectUrl $script:Fs.Redirect.Text; $script:Fs.Redirect.Text = ''
        Write-FsOut 'Connecté.'; Update-FsHeader; Update-FsMembers } })
    $w.FindName('BtnFsDisconnect').Add_Click({ Invoke-FsUi { Disconnect-Fs; Update-FsHeader; $script:Fs.Member.Items.Clear(); Write-FsOut 'Jeton effacé.' } })
    $w.FindName('BtnFsReload').Add_Click({ Invoke-FsUi { Update-FsHeader; Update-FsMembers } })

    # Changer de membre recharge le filtre web de ce membre.
    $script:Fs.Member.Add_SelectionChanged({ if ($script:Fs.Member.SelectedItem) { Invoke-FsUi { Update-FsWebView } } })
    $w.FindName('BtnFsWebReload').Add_Click({ Invoke-FsUi { Update-FsWebView } })
    $w.FindName('BtnFsBlocked').Add_Click({ Invoke-FsUi { Show-FsBlockedWindow } })
    $w.FindName('BtnFsOfficial').Add_Click({ Invoke-FsUi {
        Start-Process 'https://account.microsoft.com/family/'
        Write-FsOut "Site officiel ouvert : choisis l'enfant, puis l'onglet Web safety." } })
    $w.FindName('BtnFsWebRaw').Add_Click({ Invoke-FsUi {
        Write-FsOut ("Réponse brute ($($script:Fs.Member.SelectedItem.Content)) :`r`n" + ((Get-FsWebRestrictions -UserId (Get-FsSelectedMember)) | ConvertTo-Json -Depth 8)) } })
    $w.FindName('BtnFsSiteAdd').Add_Click({ Invoke-FsUi {
        $id = Get-FsSelectedMember; $site = $script:Fs.Site.Text.Trim()
        if (-not $site) { throw 'Saisis un domaine ou une URL.' }
        $allow = ($script:Fs.SiteMode.SelectedIndex -eq 0)
        Add-FsWebException -UserId $id -Website $site -Allowed $allow -Source 'ControleParental' | Out-Null
        Write-FsOut ("Demande envoyée : {0} ({1}). Vérifie sur le site officiel qu'il apparaît dans la liste." -f $site, $(if ($allow) { 'autorisé' } else { 'bloqué' }))
        $script:Fs.Site.Text = '' } })
    $script:Fs.Site.Add_KeyDown({ param($s, $e) if ($e.Key -eq 'Return') { $script:Fs.Window.FindName('BtnFsSiteAdd').RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Button]::ClickEvent))) } })
    # ---- ajout en masse
    $w.FindName('BtnFsBulkFile').Add_Click({ Invoke-FsUi {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Listes de sites (*.txt)|*.txt|Tous les fichiers (*.*)|*.*'
        if ($PSScriptRoot) { $dlg.InitialDirectory = $PSScriptRoot }
        if ($dlg.ShowDialog($script:Fs.Window)) {
            $script:Fs.Bulk.Text = [IO.File]::ReadAllText($dlg.FileName, [Text.Encoding]::UTF8)
            Write-FsOut "Fichier chargé : $($dlg.FileName)"
        } } })
    $w.FindName('BtnFsBulkCheck').Add_Click({ Invoke-FsUi { [void](Get-FsBulkPlan -Report) } })
    $w.FindName('BtnFsBulkStop').Add_Click({ $script:FsBulkStop = $true; $script:Fs.BulkStatus.Text = 'Arrêt demandé...' })
    $w.FindName('BtnFsBulkSend').Add_Click({ Invoke-FsUi { Send-FsBulk } })

    $w.FindName('BtnFsAppsLoad').Add_Click({ Invoke-FsUi {
        $apps = @(Get-FsApps -UserId (Get-FsSelectedMember)); $script:Fs.Apps.ItemsSource = [object[]]$apps
        Write-FsOut "$($apps.Count) application(s) dans le rapport du jour." } })
    $appAction = {
        param([string]$Mode)
        Invoke-FsUi {
            $id = Get-FsSelectedMember; $app = $script:Fs.Apps.SelectedItem
            if (-not $app) { throw "Sélectionne d'abord une application dans la liste." }
            if ($Mode -eq 'block') { Set-FsAppBlock -UserId $id -AppId $app.AppId -Block $true; Write-FsOut "Bloquée : $($app.Name)" }
            else {
                Set-FsAppBlock -UserId $id -AppId $app.AppId -Block $false
                if ($Mode -eq 'temp') {
                    $min = Get-FsMinutesChoice
                    $task = Add-FsFollowUp @{ cmd = 'app-block'; userId = $id; appId = $app.AppId } $min
                    Write-FsOut "Débloquée : $($app.Name). Reblocage automatique dans $min min (tâche $task)."
                } else { Write-FsOut "Débloquée : $($app.Name)" }
            }
            $script:Fs.Apps.ItemsSource = [object[]]@(Get-FsApps -UserId $id)
        }
    }
    $script:FsAppAction = $appAction
    $w.FindName('BtnFsAppBlock').Add_Click({ & $script:FsAppAction 'block' })
    $w.FindName('BtnFsAppUnblock').Add_Click({ & $script:FsAppAction 'unblock' })
    $w.FindName('BtnFsAppTemp').Add_Click({ & $script:FsAppAction 'temp' })

    $w.FindName('BtnFsDevBlock').Add_Click({ Invoke-FsUi {
        $id = Get-FsSelectedMember; $min = Get-FsMinutesChoice; $t = [string]$script:Fs.Target.SelectedItem.Content
        Set-FsDeviceBlock -UserId $id -Target $t -Action Block -Minutes $min
        Write-FsOut "Blocage demandé : $t pendant $min min." } })
    $w.FindName('BtnFsDevCancel').Add_Click({ Invoke-FsUi {
        $id = Get-FsSelectedMember; $t = [string]$script:Fs.Target.SelectedItem.Content
        Set-FsDeviceBlock -UserId $id -Target $t -Action Cancel
        Write-FsOut "Blocage annulé : $t." } })
    $w.FindName('BtnFsLimit').Add_Click({ Invoke-FsUi {
        $id = Get-FsSelectedMember; $t = [string]$script:Fs.Target.SelectedItem.Content
        $min = 0
        if (-not [int]::TryParse($script:Fs.LimitMin.Text, [ref]$min) -or $min -lt 0 -or $min -gt 1440) { throw 'Minutes : saisis un nombre entre 0 et 1440.' }
        $spec = @{ Minutes = $min }
        $b = $script:Fs.LimitBegin.Text.Trim(); $e = $script:Fs.LimitEnd.Text.Trim()
        if ($b -and $e) {
            if ($b -notmatch '^\d{2}:\d{2}:\d{2}$' -or $e -notmatch '^\d{2}:\d{2}:\d{2}$') { throw 'Plage : format HH:MM:SS.' }
            $spec['Begin'] = $b; $spec['End'] = $e
        }
        $days = @{}
        foreach ($d in 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday') { $days[$d] = $spec }
        Set-FsDeviceLimits -UserId $id -Platform $t -Days $days | Out-Null
        Write-FsOut "Limite appliquée à $t : $min min/jour." } })

    $w.FindName('BtnFsUsage').Add_Click({ Invoke-FsUi {
        $r = Get-FsScreenTime -UserId (Get-FsSelectedMember)
        $ag = $r.deviceUsageAggregates
        Write-FsOut ("Aujourd'hui : {0} min (moyenne quotidienne : {1} min)" -f [math]::Round($ag.totalScreenTime / 60000, 0), [math]::Round($ag.dailyAverage / 60000, 0))
        foreach ($d in @($ag.deviceAggregates)) { Write-FsOut ("   appareil {0} : {1} min" -f $d.deviceId, [math]::Round($d.timeUsed / 60000, 0)) } } })
    $w.FindName('BtnFsWebAct').Add_Click({ Invoke-FsUi { Write-FsOut ("Historique web (24 h) :`r`n" + (Format-FsRecords (Get-FsActivity -UserId (Get-FsSelectedMember) -Kind web))) } })
    $w.FindName('BtnFsSearchAct').Add_Click({ Invoke-FsUi { Write-FsOut ("Recherches (24 h) :`r`n" + (Format-FsRecords (Get-FsActivity -UserId (Get-FsSelectedMember) -Kind search))) } })
    $w.FindName('BtnFsDevices').Add_Click({ Invoke-FsUi {
        foreach ($d in @(Get-FsDevices -UserId (Get-FsSelectedMember))) { Write-FsOut ("{0} | {1} {2} | {3} | vu : {4}" -f $d.Name, $d.Make, $d.Model, $d.Os, $d.LastSeen) } } })

    Update-FsHeader
    try { if (Test-FsConnected) { Update-FsMembers } } catch { Write-FsOut ('Erreur : ' + $_.Exception.Message) }
    [void]$w.ShowDialog()
}

# Construction de la liste
foreach ($cat in @($script:Tweaks | ForEach-Object { $_.Cat } | Select-Object -Unique)) {
    $h = New-Object System.Windows.Controls.TextBlock
    $h.Text = $cat
    $h.FontSize = 15
    $h.FontWeight = [System.Windows.FontWeights]::SemiBold
    $h.Margin = New-Object System.Windows.Thickness(2, 16, 0, 2)
    [void]$panel.Children.Add($h)

    foreach ($t in @($script:Tweaks | Where-Object { $_.Cat -eq $cat })) {
        $card = New-Object System.Windows.Controls.Border
        $card.Background = [System.Windows.Media.Brushes]::White
        $card.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $card.Padding = New-Object System.Windows.Thickness(12)
        $card.Margin = New-Object System.Windows.Thickness(0, 6, 0, 0)

        $grid = New-Object System.Windows.Controls.Grid
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
        $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = [System.Windows.GridLength]::Auto
        [void]$grid.ColumnDefinitions.Add($c1); [void]$grid.ColumnDefinitions.Add($c2)

        $sp = New-Object System.Windows.Controls.StackPanel
        $name = New-Object System.Windows.Controls.TextBlock
        $name.Text = $t.Name
        $name.FontWeight = [System.Windows.FontWeights]::SemiBold
        $name.TextWrapping = 'Wrap'
        $desc = New-Object System.Windows.Controls.TextBlock
        $desc.Text = $t.Desc
        $desc.TextWrapping = 'Wrap'
        $desc.Foreground = $bc.ConvertFromString('#555555')
        $desc.Margin = New-Object System.Windows.Thickness(0, 3, 12, 0)
        $info = New-Object System.Windows.Controls.TextBlock
        $info.TextWrapping = 'Wrap'
        $info.Foreground = $bc.ConvertFromString('#B35900')
        $info.Margin = New-Object System.Windows.Thickness(0, 3, 0, 0)
        [void]$sp.Children.Add($name); [void]$sp.Children.Add($desc); [void]$sp.Children.Add($info)

        $toggle = New-Object System.Windows.Controls.Primitives.ToggleButton
        $toggle.Style = $window.FindResource('SwitchStyle')
        $toggle.Tag = $t.Id
        $toggle.VerticalAlignment = 'Center'
        $toggle.Add_Click({ param($s, $e) Invoke-UserToggle -Id ([string]$s.Tag) -Want ([bool]$s.IsChecked) })

        [System.Windows.Controls.Grid]::SetColumn($toggle, 1)
        [void]$grid.Children.Add($sp); [void]$grid.Children.Add($toggle)
        $card.Child = $grid
        [void]$panel.Children.Add($card)
        $script:UI[$t.Id] = @{ Toggle = $toggle; Info = $info }
    }
}

# Rappels manuels
$note = New-Object System.Windows.Controls.TextBlock
$note.TextWrapping = 'Wrap'
$note.Margin = New-Object System.Windows.Thickness(2, 18, 0, 10)
$note.Foreground = $bc.ConvertFromString('#333333')
$note.Text = "À faire à la main (non automatisable) :`n" +
    "- Family Safety (account.microsoft.com/family) : filtre web en mode « sites autorisés uniquement », blocage des autres navigateurs.`n" +
    "- Le compte de l'enfant doit être un compte standard, jamais administrateur.`n" +
    "- Les stratégies Edge s'appliquent à toute la machine, ta session comprise. Edge les recharge en quelques minutes ; sinon ouvre edge://policy et clique sur « Reload policies »."
[void]$panel.Children.Add($note)

$window.FindName('BtnRefresh').Add_Click({ Update-AllStates; Set-StatusText 'États relus.' })
$window.FindName('BtnDiag').Add_Click({ Show-DiagnosticWindow })
$window.FindName('BtnFs').Add_Click({ Show-FamilySafetyWindow })
$window.FindName('BtnAll').Add_Click({
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Backup-State
        foreach ($t in @($script:Tweaks | Where-Object { $_.Rec })) {
            if (-not (Test-Tweak $t)) { Invoke-TweakApply $t }
            Remove-Reapply $t.Id
        }
        Set-StatusText 'Toutes les protections recommandées sont activées.'
    } catch { Write-UiError 'Tout activer' $_; Set-StatusText "Erreur : $($_.Exception.Message)" }
    finally { $window.Cursor = [System.Windows.Input.Cursors]::Arrow }
    Update-AllStates
})

# Toute exception non interceptée dans un gestionnaire d'événement est journalisée au lieu de fermer la console.
$window.Dispatcher.Add_UnhandledException({
    param($s, $e)
    Write-UiError 'Non interceptée' $e.Exception
    Set-StatusText "Erreur : $($e.Exception.Message) (détails dans ui-errors.log)"
    $e.Handled = $true
})

# La fenêtre s'affiche d'abord, les états sont lus ensuite (interrupteurs inactifs pendant la lecture).
$panel.IsEnabled = $false
Set-StatusText 'Lecture des états des protections...'
$window.Add_ContentRendered({
    $window.Cursor = [System.Windows.Input.Cursors]::Wait
    try {
        Update-AllStates
        Set-StatusText 'Prêt. Un interrupteur vert = protection active.'
    } catch { Write-UiError 'Lecture initiale' $_; Set-StatusText "Erreur : $($_.Exception.Message)" }
    finally { $panel.IsEnabled = $true; $window.Cursor = [System.Windows.Input.Cursors]::Arrow }
})
try { [void]$window.ShowDialog() } catch { Write-UiError 'ShowDialog' $_; throw }
