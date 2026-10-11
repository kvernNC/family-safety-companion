<#
.SYNOPSIS
  Client PowerShell de l'API NON OFFICIELLE « mobile aggregator » de Microsoft Family Safety.

.DESCRIPTION
  Portage en PowerShell des appels étudiés dans le projet pyfamilysafety :
      https://github.com/pantherale0/pyfamilysafety   (MIT, Copyright (c) 2023 Jordan H)
  Ce module reprend de ce projet la méthode d'authentification (OAuth, identifiant client de l'application
  Android officielle), la liste des points d'accès et la forme des requêtes. Il ne contient pas son code.

  Avertissements :
    - API non documentée par Microsoft : elle peut changer ou disparaître sans préavis.
    - Les requêtes se présentent comme l'application Android Family Safety (identifiant client, User-Agent) :
      cet usage est probablement contraire aux conditions d'utilisation de Microsoft. Risque pour ton compte familial.
    - Le jeton de rafraîchissement donne accès à Family Safety pour toute la famille : il est stocké chiffré
      (DPAPI, portée machine) dans un dossier réservé à SYSTEM et aux administrateurs. Ne le copie nulle part.

  -------------------------------------------------------------------------------------------------
  Notice de licence du projet dont la méthode est reprise (MIT) :

  MIT License
  Copyright (c) 2023 Jordan H
  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
  associated documentation files (the "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
  following conditions: The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
  KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
  ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  -------------------------------------------------------------------------------------------------
#>

# ====================================================================== constantes (modifiables pour les tests)
$script:FsBaseUrl       = 'https://mobileaggregator.family.microsoft.com/api'
$script:FsTokenEndpoint = 'https://login.live.com/oauth20_token.srf'
$script:FsRedirectUrl   = 'https://login.live.com/oauth20_desktop.srf'
$script:FsClientId      = '000000000004893A'
$script:FsScope         = 'service::familymobile.microsoft.com::MBI_SSL'
$script:FsAuthUserAgent = 'Mozilla/5.0 (Linux; Android 13; Pixel 4 XL Build/TQ3A.230705.001.B4; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/115.0.5790.166 Mobile Safari/537.36'
$script:FsApiUserAgent  = 'Family Safety-prod/(v 2.0.6.1139) Android/33 google/Pixel 4 XL'
$script:FsAccess        = $null
$script:FsDataDir       = $null

$script:FsEndpoints = @{
    roster           = @{ Url = '{BASE}/v2/roster';                                                                                         Method = 'GET' }
    devices          = @{ Url = '{BASE}/v1/devices/{USER_ID}';                                                                              Method = 'GET' }
    deviceUsage      = @{ Url = '{BASE}/v4/activityreport/deviceScreenTimeUsage/{USER_ID}?beginTime={BEGIN}&endTime={END}&topDeviceCount={COUNT}'; Method = 'GET' }
    appUsage         = @{ Url = '{BASE}/v4/activityReport/appUsage/{USER_ID}?beginTime={BEGIN}&endTime={END}';                              Method = 'GET' }
    webActivity      = @{ Url = '{BASE}/v1/activityreport/webactivity/{USER_ID}?beginTime={BEGIN}&endTime={END}&allowStatus={STATUS}';      Method = 'GET' }
    searchActivity   = @{ Url = '{BASE}/v1/activityreport/searchactivity/{USER_ID}?beginTime={BEGIN}&endTime={END}';                        Method = 'GET' }
    spending         = @{ Url = '{BASE}/v1/Spending/{USER_ID}';                                                                             Method = 'GET' }
    webRestrictions  = @{ Url = '{BASE}/v1/WebRestrictions/{USER_ID}';                                                                      Method = 'GET' }
    webUpdate        = @{ Url = '{BASE}/v1/WebRestrictions/{USER_ID}';                                                                      Method = 'PATCH' }
    contentRestr     = @{ Url = '{BASE}/v1/ContentRestrictions/{USER_ID}';                                                                  Method = 'GET' }
    contentUpdate    = @{ Url = '{BASE}/v1/ContentRestrictions/{USER_ID}';                                                                  Method = 'PATCH' }
    pendingRequests  = @{ Url = '{BASE}/v1/PendingRequests';                                                                                Method = 'GET' }
    rawGet           = @{ Url = '{BASE}{PATH}';                                                                                              Method = 'GET' }
    overridesGet     = @{ Url = '{BASE}/v4/devicelimits/{USER_ID}/overrides';                                                               Method = 'GET' }
    overridesPost    = @{ Url = '{BASE}/v4/devicelimits/{USER_ID}/overrides';                                                               Method = 'POST' }
    appPolicy        = @{ Url = '{BASE}/v3/appLimits/policies/{USER_ID}/{APP_ID}';                                                          Method = 'PATCH' }
    scheduleUpdate   = @{ Url = '{BASE}/v4/devicelimits/schedules/{USER_ID}';                                                               Method = 'PATCH' }
}

# ====================================================================== stockage du jeton (DPAPI, portée machine)
function Get-FsDataDir {
    if ($script:FsDataDir) { return $script:FsDataDir }
    $base = $env:ProgramData
    if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $script:FsDataDir = Join-Path $base 'ControleParental\secrets'
    $script:FsDataDir
}
function Initialize-FsDataDir {
    $dir = Get-FsDataDir
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # Réservé à SYSTEM et aux administrateurs : le compte enfant ne peut ni lire ni parcourir ce dossier.
        if ($env:OS -eq 'Windows_NT') { & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null }
    }
    $dir
}
function Save-FsSecret([string]$Name, [string]$Value) {
    Add-Type -AssemblyName System.Security
    $dir   = Initialize-FsDataDir
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $enc   = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes((Join-Path $dir "$Name.bin"), $enc)
}
function Read-FsSecret([string]$Name) {
    Add-Type -AssemblyName System.Security
    $path = Join-Path (Get-FsDataDir) "$Name.bin"
    if (-not (Test-Path $path)) { return $null }
    $dec = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($path), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Text.Encoding]::UTF8.GetString($dec)
}
function Remove-FsSecret([string]$Name) {
    $path = Join-Path (Get-FsDataDir) "$Name.bin"
    if (Test-Path $path) { Remove-Item $path -Force }
}

function Get-FsUserAgentArgs([string]$UserAgent, [hashtable]$Headers) {
    # PowerShell 7 valide les en-têtes et refuse certains User-Agent ; Windows PowerShell 5.1 accepte -UserAgent tel quel.
    $out = @{}
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('SkipHeaderValidation')) {
        $Headers['User-Agent'] = $UserAgent
        $out['SkipHeaderValidation'] = $true
    } else {
        $out['UserAgent'] = $UserAgent
    }
    $out
}

# ====================================================================== authentification
function Get-FsLoginUrl {
    # URL à ouvrir dans un navigateur : après connexion, le navigateur affiche une page blanche dont l'URL contient « code= ».
    $redir = [uri]::EscapeDataString($script:FsRedirectUrl)
    $scope = [uri]::EscapeDataString($script:FsScope)
    "https://login.live.com/oauth20_authorize.srf?cobrandid=b5d15d4b-695a-4cd5-93c6-13f551b310df&client_id=$($script:FsClientId)&response_type=code&redirect_uri=$redir&response_mode=query&scope=$scope&lw=1&fl=easi2&login_hint="
}

function Invoke-FsTokenRequest([hashtable]$Form) {
    $headers = @{ 'X-Requested-With' = 'com.microsoft.familysafety' }
    $ua = Get-FsUserAgentArgs $script:FsAuthUserAgent $headers
    try {
        $r = Invoke-WebRequest -Uri $script:FsTokenEndpoint -Method Post -Body $Form -Headers $headers @ua `
             -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Échange de jeton refusé par Microsoft ($($_.Exception.Message)). Reconnecte-toi."
    }
    $j = $r.Content | ConvertFrom-Json
    if (-not $j.access_token) { throw 'Réponse de jeton inattendue.' }
    $j
}

function Set-FsTokens($Tokens) {
    $script:FsAccess = @{ Token = [string]$Tokens.access_token; Expires = (Get-Date).AddSeconds([int]$Tokens.expires_in) }
    Save-FsSecret 'fs-token' (@{ refresh_token = [string]$Tokens.refresh_token; user_id = [string]$Tokens.user_id } | ConvertTo-Json -Compress)
}

function Connect-Fs {
    param([Parameter(Mandatory)][string]$RedirectUrl)
    # Accepte l'URL de redirection complète (…oauth20_desktop.srf?code=…) ou le code seul (M.C…).
    # La page de redirection efface désormais le code de la barre d'adresse (« ?removed=true ») : il faut le relever dans F12 > Réseau.
    $text = $RedirectUrl.Trim()
    $m = [regex]::Match($text, '[?&]code=([^&#\s]+)')
    if ($m.Success) { $code = [uri]::UnescapeDataString($m.Groups[1].Value) }
    elseif ($text -match '^M\.[^\s?&=/]+$') { $code = $text }
    elseif ($text -match 'removed=true') { throw "Microsoft a effacé le code de l'adresse (« removed=true »). Relève l'URL dans F12 > Réseau, comme indiqué à l'étape 2." }
    else { throw "Le texte collé ne contient pas de code (« code=M.… »). Suis l'étape 2 pour le relever." }
    $tokens = Invoke-FsTokenRequest ([ordered]@{
        client_id = $script:FsClientId; code = $code; grant_type = 'authorization_code'
        redirect_uri = $script:FsRedirectUrl; scope = $script:FsScope })
    Set-FsTokens $tokens
}

function Get-FsEdgePath {
    foreach ($p in @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    $reg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe' -ErrorAction SilentlyContinue).'(default)'
    if ($reg -and (Test-Path $reg)) { return $reg }
    throw 'Microsoft Edge introuvable.'
}

function Connect-FsWithEdge {
    # Ouvre une fenêtre Edge séparée (profil temporaire, débogage distant sur 127.0.0.1) et relève le code
    # dans la redirection vers oauth20_desktop.srf, avant que la page ne l'efface. Le code n'est jamais affiché.
    # $OnWait : appelé pendant l'attente (ex. pour garder une interface WPF réactive).
    param([scriptblock]$OnWait = {}, [int]$TimeoutMinutes = 5)
    $edge = Get-FsEdgePath
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    $profileDir = Join-Path ([IO.Path]::GetTempPath()) ('cp-fs-login-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $ws = $null
    try {
        Start-Process -FilePath $edge -ArgumentList @("--remote-debugging-port=$port", "--user-data-dir=`"$profileDir`"",
            '--no-first-run', '--no-default-browser-check', '--new-window', 'about:blank') | Out-Null

        $wsUrl = $null; $limit = (Get-Date).AddSeconds(20)
        while (-not $wsUrl -and (Get-Date) -lt $limit) {
            & $OnWait; Start-Sleep -Milliseconds 300
            try {
                $targets = Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/list" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
                $wsUrl = @($targets | Where-Object { $_.type -eq 'page' -and $_.webSocketDebuggerUrl } | Select-Object -First 1).webSocketDebuggerUrl
            } catch {}
        }
        if (-not $wsUrl) { throw "Impossible de piloter Edge. Si la protection « Bloquer les outils de développement » est active, désactive-la le temps de la connexion." }

        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        $ct = [Threading.CancellationToken]::None
        $ws.ConnectAsync([uri]$wsUrl, $ct).Wait()
        $send = {
            param($obj)
            $bytes = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Compress -Depth 5))
            $ws.SendAsync([ArraySegment[byte]]::new($bytes), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait()
        }
        & $send @{ id = 1; method = 'Network.enable' }
        & $send @{ id = 2; method = 'Page.enable' }
        & $send @{ id = 3; method = 'Page.navigate'; params = @{ url = (Get-FsLoginUrl) } }

        $buf = New-Object byte[] 65536
        $ms = New-Object IO.MemoryStream
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        $code = $null
        while (-not $code) {
            if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) { throw 'Fenêtre Edge fermée avant la fin de la connexion.' }
            $task = $ws.ReceiveAsync([ArraySegment[byte]]::new($buf), $ct)
            while (-not $task.Wait(150)) {
                & $OnWait
                if ((Get-Date) -gt $deadline) { throw "Délai dépassé ($TimeoutMinutes min) sans connexion." }
            }
            if ($task.Result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { throw 'Fenêtre Edge fermée avant la fin de la connexion.' }
            $ms.Write($buf, 0, $task.Result.Count)
            if (-not $task.Result.EndOfMessage) { continue }
            $msg = [Text.Encoding]::UTF8.GetString($ms.ToArray()); $ms.SetLength(0)
            $m = [regex]::Match($msg, 'oauth20_desktop\.srf\?[^"\s]*?\bcode=([^&"\\\s#]+)')
            if ($m.Success) { $code = [uri]::UnescapeDataString($m.Groups[1].Value) }
        }
        Connect-Fs -RedirectUrl "?code=$code"
    } finally {
        if ($ws) { try { $ws.Dispose() } catch {} }
        # Ferme uniquement les processus Edge lancés avec ce profil temporaire, puis supprime le profil.
        try {
            Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profileDir) } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch {}
        for ($i = 0; $i -lt 10 -and (Test-Path $profileDir); $i++) {
            try { Remove-Item $profileDir -Recurse -Force -ErrorAction Stop } catch { Start-Sleep -Milliseconds 300 }
        }
    }
}

function Disconnect-Fs { $script:FsAccess = $null; Remove-FsSecret 'fs-token' }

function Test-FsConnected { [bool](Read-FsSecret 'fs-token') }

function Update-FsToken {
    $raw = Read-FsSecret 'fs-token'
    if (-not $raw) { throw "Non connecté à Family Safety : utilise « Se connecter »." }
    $stored = $raw | ConvertFrom-Json
    try {
        $tokens = Invoke-FsTokenRequest ([ordered]@{ client_id = $script:FsClientId; refresh_token = $stored.refresh_token; grant_type = 'refresh_token'; scope = $script:FsScope })
    } catch {
        # Un autre processus (tâche planifiée) a peut-être déjà renouvelé le jeton : on relit une fois.
        $again = Read-FsSecret 'fs-token' | ConvertFrom-Json
        if ($again.refresh_token -eq $stored.refresh_token) { throw }
        $tokens = Invoke-FsTokenRequest ([ordered]@{ client_id = $script:FsClientId; refresh_token = $again.refresh_token; grant_type = 'refresh_token'; scope = $script:FsScope })
    }
    Set-FsTokens $tokens
}

function Get-FsAuthHeader {
    if (-not $script:FsAccess -or $script:FsAccess.Expires -lt (Get-Date).AddMinutes(1)) { Update-FsToken }
    'MSAuth1.0 usertoken="{0}", type="MSACT"' -f $script:FsAccess.Token
}

# ====================================================================== appel d'API
function Invoke-FsApi {
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        $Body = $null,
        [string]$Platform,
        [hashtable]$Params = @{}
    )
    $e = $script:FsEndpoints[$Endpoint]
    if (-not $e) { throw "Point d'accès inconnu : $Endpoint" }
    $url = $e.Url.Replace('{BASE}', $script:FsBaseUrl)
    foreach ($k in $Params.Keys) { $url = $url.Replace("{$k}", [string]$Params[$k]) }

    $headers = @{ Authorization = (Get-FsAuthHeader) }
    if ($Platform) { $headers['Plat-Info'] = $Platform }
    $args2 = @{ Uri = $url; Method = $e.Method; Headers = $headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
    $ua = Get-FsUserAgentArgs $script:FsApiUserAgent $headers
    foreach ($k in $ua.Keys) { $args2[$k] = $ua[$k] }
    if ($null -ne $Body) {
        $args2['Body'] = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 12 -Compress))
        $args2['ContentType'] = 'application/json'
    } else {
        $args2['ContentType'] = 'application/json'
    }
    try {
        $r = Invoke-WebRequest @args2
    } catch {
        $resp = $_.Exception.Response
        $code = 0
        if ($resp -and $resp.StatusCode) { $code = [int]$resp.StatusCode }
        $text = $_.ErrorDetails.Message
        switch ($code) {
            401 { throw 'Non autorisé (401) : reconnecte-toi à Family Safety.' }
            403 { throw "Accès refusé (403) : $text" }
            500 { if ($text -match 'Something went wrong in the Aggregator service') { throw "Erreur temporaire du service Microsoft (aggregator) : réessaie dans un instant." } }
        }
        throw "Erreur HTTP $code : $text"
    }
    if ($r.StatusCode -eq 204 -or [string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
    try { $r.Content | ConvertFrom-Json } catch { $r.Content }
}

# ====================================================================== formats de date de l'API
function Get-FsOffsetText([datetime]$D) {
    $off  = [TimeZoneInfo]::Local.GetUtcOffset($D)
    $sign = '+'; if ($off -lt [TimeSpan]::Zero) { $sign = '-' }
    $abs  = $off.Duration()
    '{0}{1:00}{2:00}' -f $sign, $abs.Hours, $abs.Minutes
}
function Format-FsLocalQuery([datetime]$D) {
    $inv = [Globalization.CultureInfo]::InvariantCulture
    # Même forme que la bibliothèque Python sur le réseau : « : » conservé, « + » encodé en %2B.
    [uri]::EscapeDataString($D.ToString('yyyy-MM-ddTHH:mm:ss', $inv) + (Get-FsOffsetText $D)).Replace('%3A', ':')
}
function Format-FsLocalIso([datetime]$D) {
    $D.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + (Get-FsOffsetText $D)
}
function Format-FsUtcOverride([datetime]$D) {
    $D.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + '.000+0000'
}

# ====================================================================== lecture
function Get-FsMembers {
    $r = Invoke-FsApi -Endpoint roster
    foreach ($m in @($r.members)) {
        if ($m.isDigitalSafetyEnabled) {
            [pscustomobject]@{ Id = [string]$m.id; Role = [string]$m.role; FirstName = [string]$m.user.firstName; LastName = [string]$m.user.lastName
                               Name = ('{0} {1}' -f $m.user.firstName, $m.user.lastName).Trim() }
        }
    }
}

function Get-FsDevices([Parameter(Mandatory)][string]$UserId) {
    $r = Invoke-FsApi -Endpoint devices -Params @{ USER_ID = $UserId }
    foreach ($d in @($r.devices)) {
        [pscustomobject]@{ Id = ([string]$d.deviceId).Replace('g:', ''); Name = [string]$d.deviceName; Make = [string]$d.deviceMake
                           Model = [string]$d.deviceModel; Os = [string]$d.osName; FormFactor = [string]$d.deviceFormFactor; LastSeen = [string]$d.lastSeenOn }
    }
}

function Get-FsScreenTime {
    param([Parameter(Mandatory)][string]$UserId, [datetime]$Begin = (Get-Date).Date, [datetime]$End = (Get-Date).Date.AddDays(1).AddSeconds(-1))
    $p = @{ USER_ID = $UserId; BEGIN = (Format-FsLocalQuery $Begin); END = (Format-FsLocalQuery $End); COUNT = 4 }
    Invoke-FsApi -Endpoint deviceUsage -Params $p -Platform 'ALL'
}

function Get-FsApps {
    param([Parameter(Mandatory)][string]$UserId, [datetime]$Begin = (Get-Date).Date, [datetime]$End = (Get-Date).Date.AddDays(1).AddSeconds(-1))
    $p = @{ USER_ID = $UserId; BEGIN = (Format-FsLocalQuery $Begin); END = (Format-FsLocalQuery $End) }
    $r = Invoke-FsApi -Endpoint appUsage -Params $p -Platform 'ALL'
    if ($null -eq $r -or $null -eq $r.appActivity) { throw "Réponse sans « appActivity »." }
    foreach ($a in @($r.appActivity)) {
        $blocked = ($a.blockState -eq 'Blocked') -or [bool]$a.isLegacyBlocked -or ($a.blockState -eq 'BlockedAlways')
        [pscustomobject]@{ AppId = [string]$a.appId; Name = [string]$a.displayName; UsageMinutes = [math]::Round([double]$a.usage, 1)
                           Blocked = $blocked; State = if ($blocked) { 'Bloquée' } else { 'Autorisée' } }
    }
}

function Get-FsWebRestrictions([Parameter(Mandatory)][string]$UserId) { Invoke-FsApi -Endpoint webRestrictions -Params @{ USER_ID = $UserId } }
function Get-FsContentRestrictions([Parameter(Mandatory)][string]$UserId, [string]$Platform) { Invoke-FsApi -Endpoint contentRestr -Params @{ USER_ID = $UserId } -Platform $Platform }
function Get-FsPendingRequests([string]$Platform) { Invoke-FsApi -Endpoint pendingRequests -Platform $Platform }

function Invoke-FsProbe {
    # Lecture seule : interroge des points d'accès connus ou candidats pour chaque membre et enregistre les réponses
    # (jamais le jeton) dans $OutDir, pour analyser leur format.
    param([Parameter(Mandatory)][string]$OutDir)
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $summary = New-Object System.Collections.Generic.List[string]
    $save = {
        param([string]$Name, [scriptblock]$Call)
        try {
            $res = & $Call
            $json = $res | ConvertTo-Json -Depth 20
            Set-Content -Path (Join-Path $OutDir "$Name.json") -Value $json -Encoding UTF8
            $summary.Add(('OK   {0} ({1} octets)' -f $Name, [string]$json.Length))
        } catch { $summary.Add(('ERR  {0} : {1}' -f $Name, $_.Exception.Message)) }
    }
    $members = @(Get-FsMembers)
    $members | Select-Object Id, Role, FirstName | ConvertTo-Json | Set-Content -Path (Join-Path $OutDir 'members.json') -Encoding UTF8
    & $save 'PendingRequests' { Get-FsPendingRequests }
    & $save 'PendingRequests-ALL' { Get-FsPendingRequests -Platform 'ALL' }
    foreach ($m in $members) {
        $n = ($m.FirstName -replace '[^\w]', '')
        $paths = [ordered]@{
            'WebRestrictions-v1'     = "/v1/WebRestrictions/$($m.Id)"
            'WebRestrictions-v2'     = "/v2/WebRestrictions/$($m.Id)"
            'ContentRestrictions-v1' = "/v1/ContentRestrictions/$($m.Id)"
            'ContentRestrictions-v2' = "/v2/ContentRestrictions/$($m.Id)"
        }
        foreach ($k in $paths.Keys) {
            foreach ($plat in @('', 'ALL', 'WINDOWS')) {
                $p = $paths[$k]; $pl = $plat
                $label = "$n-$k"; if ($pl) { $label += "-$pl" }
                & $save $label { Invoke-FsApi -Endpoint rawGet -Params @{ PATH = $p } -Platform $pl }
            }
        }
    }
    $summary | Set-Content -Path (Join-Path $OutDir 'summary.txt') -Encoding UTF8
    $summary
}

function Find-FsWebsiteNodes($Node, $Found) {
    # Parcours récursif : relève tout objet qui possède une propriété « website ».
    if ($null -eq $Node -or $Node -is [string] -or $Node -is [ValueType]) { return }
    if ($Node -is [System.Array]) { foreach ($i in $Node) { Find-FsWebsiteNodes $i $Found }; return }
    if ($Node.PSObject.Properties['website']) {
        $allowed = $null
        if ($Node.PSObject.Properties['allowed']) { $allowed = [bool]$Node.allowed }
        [void]$Found.Add([pscustomobject]@{ Website = [string]$Node.website; Allowed = $allowed })
    }
    foreach ($p in $Node.PSObject.Properties) { Find-FsWebsiteNodes $p.Value $Found }
}

function Get-FsWebExceptions {
    # Structure de la réponse non documentée : on cherche les objets portant une propriété « website », où qu'ils soient.
    param([Parameter(Mandatory)][string]$UserId)
    $found = New-Object System.Collections.ArrayList
    Find-FsWebsiteNodes (Get-FsWebRestrictions -UserId $UserId) $found
    @($found)
}

function Get-FsActivity {
    param([Parameter(Mandatory)][string]$UserId, [ValidateSet('web', 'search')][string]$Kind = 'web',
          [datetime]$Begin = (Get-Date).AddHours(-24), [datetime]$End = (Get-Date), [string]$AllowStatus = 'All')
    $p = @{ USER_ID = $UserId; BEGIN = (Format-FsLocalQuery $Begin); END = (Format-FsLocalQuery $End); STATUS = $AllowStatus }
    if ($Kind -eq 'web') { Invoke-FsApi -Endpoint webActivity -Params $p -Platform 'ALL' } else { Invoke-FsApi -Endpoint searchActivity -Params $p -Platform 'ALL' }
}

function Get-FsOverrides([Parameter(Mandatory)][string]$UserId) { Invoke-FsApi -Endpoint overridesGet -Params @{ USER_ID = $UserId } -Platform 'ALL' }

# ====================================================================== modification
function Add-FsWebException {
    param([Parameter(Mandatory)][string]$UserId, [Parameter(Mandatory)][string]$Website, [bool]$Allowed = $false, [string]$Source = '')
    $body = @{ operations = @(@{ op = 'Add'; path = '/exceptions'; source = $Source; value = @{ website = $Website; allowed = $Allowed } }) }
    Invoke-FsApi -Endpoint webUpdate -Params @{ USER_ID = $UserId } -Body $body
}

function Update-FsWebSettings {
    # $Changes : chemin -> valeur, ex. @{ '/useAllowedListOnly' = $true; '/categories/chat' = $false }
    # Opération « Replace » déduite de l'opération « Add » connue : NON CONFIRMÉE, l'appelant doit relire pour vérifier.
    param([Parameter(Mandatory)][string]$UserId, [Parameter(Mandatory)][hashtable]$Changes)
    $ops = @(foreach ($k in $Changes.Keys) { @{ op = 'Replace'; path = $k; value = $Changes[$k] } })
    Invoke-FsApi -Endpoint webUpdate -Params @{ USER_ID = $UserId } -Body @{ operations = $ops }
}

function Get-FsPlatformOfApp([string]$AppId) {
    if ($AppId.StartsWith('x:')) { return 'XBOX' }
    if ($AppId.StartsWith('appx:')) { return 'WINDOWS' }
    if ($AppId.StartsWith('a:')) { return 'MOBILE' }
    $null
}

function Set-FsAppBlock {
    param([Parameter(Mandatory)][string]$UserId, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][bool]$Block)
    $state = 'NotBlocked'; if ($Block) { $state = 'BlockedAlways' }
    $body = @{ appId = $AppId; appTimeEnforcementPolicy = 'WeekendAndWeekday'; blockState = $state; blocked = $false; displayName = $AppId; enabled = $true }
    Invoke-FsApi -Endpoint appPolicy -Params @{ USER_ID = $UserId; APP_ID = $AppId } -Body $body -Platform (Get-FsPlatformOfApp $AppId) | Out-Null
}

function Set-FsDeviceBlock {
    # Bloque une plateforme (Desktop, Mobile, Xbox) pendant N minutes (Block) ou annule le blocage en cours (Cancel).
    param([Parameter(Mandatory)][string]$UserId, [ValidateSet('Desktop', 'Mobile', 'Xbox')][string]$Target = 'Desktop',
          [ValidateSet('Block', 'Cancel')][string]$Action = 'Block', [int]$Minutes = 60)
    $type = 'BlockUntil'; $until = (Get-Date).AddMinutes($Minutes)
    if ($Action -eq 'Cancel') { $type = 'Cancel'; $until = Get-Date }
    $body = @{ target = $Target; overrideType = $type; validUntil = (Format-FsUtcOverride $until); culture = 'en-GB' }
    Invoke-FsApi -Endpoint overridesPost -Params @{ USER_ID = $UserId } -Body $body -Platform 'ALL' | Out-Null
}

function Set-FsDeviceLimits {
    # $Days : hashtable jour (monday..sunday) -> @{ Minutes = 120; Begin = '08:00:00'; End = '20:00:00' } (Begin/End facultatifs)
    param([Parameter(Mandatory)][string]$UserId, [ValidateSet('Desktop', 'Mobile', 'Xbox')][string]$Platform = 'Desktop', [Parameter(Mandatory)][hashtable]$Days)
    $daily = @{}
    foreach ($d in $Days.Keys) {
        $spec = $Days[$d]
        $entry = @{ allowance = [int64]([int]$spec.Minutes * 60 * 1000) }
        if ($spec.Begin -and $spec.End) { $entry['allottedIntervals'] = @(@{ begin = [string]$spec.Begin; end = [string]$spec.End }) }
        $daily[([string]$d).ToLower()] = $entry
    }
    $body = @{ dailyRestrictions = $daily; mode = 'PerDeviceType'; appliesTo = $Platform; culture = 'en-GB'; time = (Format-FsLocalIso (Get-Date)) }
    Invoke-FsApi -Endpoint scheduleUpdate -Params @{ USER_ID = $UserId } -Body $body
}

# ====================================================================== ajout en masse de sites
# L'API mobile accepte l'ajout (vérifié le 11/10/2026 : le site apparaît sur la console web officielle), mais ne
# renvoie plus les listes : la console garde donc sa propre mémoire des sites déjà envoyés, par enfant.

function ConvertFrom-FilterLines {
    # ||domaine^ -> blocage ; @@||domaine[/chemin]^ -> autorisation. Les autres lignes sont ignorées.
    param([string[]]$Lines)
    foreach ($l in $Lines) {
        $t = $l.Trim()
        if (-not $t -or $t.StartsWith('!') -or $t.StartsWith('#')) { continue }
        if ($t -match '^@@\|\|([a-z0-9._-]+)(/[^\s$^*|]*)?\^?$')      { [pscustomobject]@{ Website = ($Matches[1] + $Matches[2]); Allowed = $true } }
        elseif ($t -match '^\|\|([a-z0-9._-]+)\^?$')                    { [pscustomobject]@{ Website = $Matches[1]; Allowed = $false } }
    }
}

function ConvertTo-FsSiteList {
    # Lignes acceptées : « site.com », « https://site.com/chemin », « www.site.com », et la syntaxe de filtres
    # « @@||site.com^ » (autoriser) / « ||site.com^ » (bloquer). Commentaires : lignes commençant par ! ou #.
    # Les lignes simples prennent le mode $DefaultAllowed. Doublons et lignes invalides écartés.
    param([string[]]$Lines, [bool]$DefaultAllowed = $true)
    $seen = @{}; $ok = New-Object System.Collections.Generic.List[object]; $bad = New-Object System.Collections.Generic.List[string]
    # Les commentaires sont écartés ligne par ligne AVANT le découpage aux virgules/points-virgules.
    $parts = foreach ($raw in $Lines) {
        foreach ($line in ([string]$raw -split '\r?\n')) {
            $lt = $line.Trim()
            if (-not $lt -or $lt.StartsWith('!') -or $lt.StartsWith('#')) { continue }
            $lt -split '[,;]+'
        }
    }
    foreach ($raw in @($parts)) {
        foreach ($l in @($raw)) {
            $t = $l.Trim()
            if (-not $t) { continue }
            $item = $null
            if ($t.StartsWith('@@') -or $t.StartsWith('||')) { $item = @(ConvertFrom-FilterLines @($t.ToLowerInvariant()))[0] }
            else {
                # Le domaine passe en minuscules, le chemin garde sa casse.
                $s = ($t -replace '^[A-Za-z][A-Za-z0-9+.-]*://', '').TrimEnd('/')
                $slash = $s.IndexOf('/')
                if ($slash -ge 0) { $s = $s.Substring(0, $slash).ToLowerInvariant() + $s.Substring($slash) } else { $s = $s.ToLowerInvariant() }
                $s = $s -replace '^www\.', ''
                if ($s -match '^([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$') { $item = [pscustomobject]@{ Website = $s; Allowed = $DefaultAllowed } }
            }
            if (-not $item) { $bad.Add($l.Trim()); continue }
            $key = $item.Website
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true; $ok.Add($item)
        }
    }
    [pscustomobject]@{ Sites = $ok.ToArray(); Invalid = $bad.ToArray() }
}

# ====================================================================== tentatives bloquées (rapport d'activité officiel)
function ConvertFrom-FsActivityItems($Response) {
    # Format du rapport non documenté : on relève tout objet portant une adresse ou un domaine,
    # avec si possible un nombre de tentatives, une date et un statut.
    $items = New-Object System.Collections.Generic.List[object]
    $visit = {
        param($n)
        if ($null -eq $n -or $n -is [string] -or $n -is [ValueType]) { return }
        if ($n -is [System.Array]) { foreach ($x in $n) { & $visit $x }; return }
        $props = @($n.PSObject.Properties)
        $site = $null
        foreach ($name in 'domain', 'website', 'url', 'host', 'hostName', 'siteName', 'webSite', 'displayName', 'name') {
            $pr = $props | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
            if ($pr -and $pr.Value -is [string] -and $pr.Value -match '^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}') { $site = [string]$pr.Value; break }
        }
        if ($site) {
            $count = $null; $last = $null; $status = ''
            foreach ($pr in $props) {
                if ($null -eq $count -and $pr.Name -match 'count|attempt|visit|total' -and $pr.Value -is [ValueType]) { $count = [int]$pr.Value }
                if ($null -eq $last -and $pr.Name -match 'time|date|last' -and $pr.Value) { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$pr.Value, [ref]$d)) { $last = $d } }
                if (-not $status -and $pr.Name -match 'status|allow|block|action' -and ($pr.Value -is [string] -or $pr.Value -is [bool])) { $status = "$($pr.Name)=$($pr.Value)" }
            }
            $h = ($site -replace '^https?://', '') -replace '[/?#:].*$', '' -replace '^www\.', ''
            $items.Add([pscustomobject]@{ Domain = $h.ToLowerInvariant(); Count = $count; Last = $last; Status = $status })
        }
        foreach ($pr in $props) { if ($pr.Value -isnot [string] -and $pr.Value -isnot [ValueType]) { & $visit $pr.Value } }
    }
    & $visit $Response
    $items
}

function Get-FsBlockedSites {
    # Domaines bloqués d'après le rapport d'activité web officiel (API mobile), regroupés par domaine.
    param([Parameter(Mandatory)][string]$UserId, [int]$Hours = 24)
    $begin = (Get-Date).AddHours(-$Hours); $end = Get-Date
    $mode = 'Blocked'; $raw = $null; $found = @()
    try {
        $raw = Get-FsActivity -UserId $UserId -Kind web -Begin $begin -End $end -AllowStatus 'Blocked'
        $found = @(ConvertFrom-FsActivityItems $raw)
    } catch { $found = @() }
    if ($found.Count -eq 0) {
        # Valeur « Blocked » refusée ou réponse vide : on lit tout et on garde ce qui porte un statut « bloqué ».
        $mode = 'All (filtré)'
        $raw = Get-FsActivity -UserId $UserId -Kind web -Begin $begin -End $end -AllowStatus 'All'
        $found = @(ConvertFrom-FsActivityItems $raw | Where-Object { $_.Status -match 'block|deni|deny|=false' })
    }
    $groups = $found | Group-Object Domain | ForEach-Object {
        $c = ($_.Group | Where-Object { $null -ne $_.Count } | Measure-Object Count -Sum).Sum
        if (-not $c) { $c = $_.Count }
        $l = ($_.Group | Where-Object { $_.Last } | Sort-Object Last -Descending | Select-Object -First 1).Last
        [pscustomobject]@{ Domain = $_.Name; Attempts = [int]$c; Last = $(if ($l) { $l.ToString('dd/MM HH:mm') } else { '' }) }
    }
    [pscustomobject]@{ Items = @($groups | Sort-Object Attempts -Descending); Mode = $mode; Raw = $raw }
}

function Get-FsSentPath([string]$UserId) {
    $base = $env:ProgramData; if (-not $base) { $base = [IO.Path]::GetTempPath() }
    $dir = Join-Path $base 'ControleParental'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Join-Path $dir "sites-envoyes-$UserId.json"
}

function Get-FsSentSites([Parameter(Mandatory)][string]$UserId) {
    # Table site -> @{ allowed; at } des sites déjà envoyés par la console à cet enfant.
    $p = Get-FsSentPath $UserId
    $h = @{}
    if (Test-Path $p) {
        try {
            # PowerShell 5.1 : ConvertFrom-Json renvoie le tableau d'un bloc, foreach l'énumère.
            $data = (Get-Content $p -Raw -Encoding UTF8) | ConvertFrom-Json
            foreach ($e in $data) { if ($e.website) { $h[[string]$e.website] = $e } }
        } catch {}
    }
    $h
}

function Save-FsSentSites([string]$UserId, [hashtable]$Table) {
    @($Table.Values | Sort-Object website) | ConvertTo-Json -Depth 3 | Set-Content -Path (Get-FsSentPath $UserId) -Encoding UTF8
}

function Add-FsWebExceptionsBulk {
    # Envoie les sites un par un, à rythme régulier, avec nouvel essai sur les erreurs temporaires.
    # $OnProgress : { param($Index, $Total, $Site, $Status) } (Status = 'ok', 'déjà envoyé', ou message d'erreur)
    # $ShouldStop : { $true pour interrompre proprement }
    param([Parameter(Mandatory)][string]$UserId, [Parameter(Mandatory)][object[]]$Sites, [switch]$SkipAlreadySent,
          [int]$DelayMs = 350, [scriptblock]$OnProgress = {}, [scriptblock]$ShouldStop = { $false })
    $sent = Get-FsSentSites $UserId
    $log = Join-Path (Split-Path (Get-FsSentPath $UserId)) 'sites-ajoutes.log'
    $res = [pscustomobject]@{ Total = $Sites.Count; Ok = 0; Skipped = 0; Failed = (New-Object System.Collections.Generic.List[object]); Stopped = $false }
    $i = 0
    try {
        foreach ($s in $Sites) {
            $i++
            if (& $ShouldStop) { $res.Stopped = $true; break }
            $prev = $sent[$s.Website]
            if ($SkipAlreadySent -and $prev -and [bool]$prev.allowed -eq [bool]$s.Allowed) { $res.Skipped++; & $OnProgress $i $Sites.Count $s.Website 'déjà envoyé'; continue }
            $err = $null
            foreach ($wait in 0, 2000, 6000) {
                if ($wait) { Start-Sleep -Milliseconds $wait }
                try { Add-FsWebException -UserId $UserId -Website $s.Website -Allowed ([bool]$s.Allowed) -Source 'ControleParental' | Out-Null; $err = $null; break }
                catch {
                    $err = $_.Exception.Message
                    if ($err -notmatch 'HTTP (0|429|5\d\d)|temporaire|délai|timed out|connexion') { break }   # erreur définitive : inutile de réessayer
                }
            }
            $mode = 'bloqué'; if ($s.Allowed) { $mode = 'autorisé' }
            if ($err) {
                $res.Failed.Add([pscustomobject]@{ Website = $s.Website; Error = $err })
                ('{0:s} ERREUR {1} ({2}) : {3}' -f (Get-Date), $s.Website, $mode, $err) | Add-Content -Path $log -Encoding UTF8
                & $OnProgress $i $Sites.Count $s.Website $err
                if ($err -match '401|reconnecte') { $res.Stopped = $true; break }   # session perdue : inutile de continuer
            } else {
                $res.Ok++
                $sent[$s.Website] = [pscustomobject]@{ website = $s.Website; allowed = [bool]$s.Allowed; at = (Get-Date).ToString('s') }
                ('{0:s} OK {1} ({2})' -f (Get-Date), $s.Website, $mode) | Add-Content -Path $log -Encoding UTF8
                & $OnProgress $i $Sites.Count $s.Website 'ok'
                if ($res.Ok % 20 -eq 0) { Save-FsSentSites $UserId $sent }
            }
            if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
        }
    } finally { Save-FsSentSites $UserId $sent }
    $res
}

# ====================================================================== exécution différée (tâches planifiées)
function Invoke-FsCommand {
    # Commandes simples, sérialisables en JSON, pour les tâches planifiées (réblocage automatique).
    param([Parameter(Mandatory)]$Cmd)
    switch ($Cmd.cmd) {
        'app-block'      { Set-FsAppBlock -UserId $Cmd.userId -AppId $Cmd.appId -Block $true }
        'app-unblock'    { Set-FsAppBlock -UserId $Cmd.userId -AppId $Cmd.appId -Block $false }
        'device-block'   { Set-FsDeviceBlock -UserId $Cmd.userId -Target $Cmd.target -Action Block -Minutes ([int]$Cmd.minutes) }
        'device-cancel'  { Set-FsDeviceBlock -UserId $Cmd.userId -Target $Cmd.target -Action Cancel }
        default          { throw "Commande Family Safety inconnue : $($Cmd.cmd)" }
    }
}

Export-ModuleMember -Function Get-FsLoginUrl, Connect-Fs, Connect-FsWithEdge,Disconnect-Fs, Test-FsConnected, Get-FsMembers, Get-FsDevices, Get-FsScreenTime, `
    Get-FsApps, Get-FsWebRestrictions, Get-FsContentRestrictions, Get-FsPendingRequests, Invoke-FsProbe, Get-FsWebExceptions, Find-FsWebsiteNodes,Get-FsActivity, Get-FsOverrides, Add-FsWebException, Update-FsWebSettings,Set-FsAppBlock, `
    Set-FsDeviceBlock, Set-FsDeviceLimits, ConvertFrom-FilterLines, ConvertTo-FsSiteList, Get-FsSentSites, Add-FsWebExceptionsBulk, Get-FsBlockedSites, ConvertFrom-FsActivityItems, Invoke-FsCommand, Invoke-FsApi, Update-FsToken
