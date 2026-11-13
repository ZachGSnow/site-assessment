function Get-HttpBanner {
    # One GET with certificate checks off; returns status, Server header, <title> and TLS cert subject/issuer.
    param([string]$Url, [int]$TimeoutMs = 4000)
    $r = [ordered]@{ Url = $Url; Status = $null; Server = $null; Title = $null; CertSubject = $null; CertIssuer = $null; Error = $null }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $TimeoutMs; $req.ReadWriteTimeout = $TimeoutMs; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $null
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { $r.Error = $_.Exception.Message } }
        if ($req.ServicePoint.Certificate) {
            $r.CertSubject = $req.ServicePoint.Certificate.Subject
            $r.CertIssuer = $req.ServicePoint.Certificate.Issuer
        }
        if ($resp) {
            $r.Status = [int]$resp.StatusCode
            $r.Server = $resp.Headers['Server']
            try {
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $buf = New-Object char[] 65536
                $n = $sr.Read($buf, 0, $buf.Length)
                $body = New-Object string($buf, 0, $n)
                if ($body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = $matches[1].Trim() }
                $sr.Close()
            } catch { }
            $resp.Close()
        }
    } catch { $r.Error = $_.Exception.Message }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb }
    return [pscustomobject]$r
}

function Get-TlsInfo {
    # One TLS handshake; returns who issued the certificate this PC is shown. A firewall or antivirus
    # that inspects HTTPS shows up here as the issuer. Nothing is sent beyond the handshake.
    param([string]$HostName, [string]$Address, [int]$Port = 443, [int]$TimeoutMs = 4000)
    $r = [ordered]@{ Host = $HostName; Address = $Address; Port = $Port; Subject = $null; Issuer = $null; NotAfter = $null; Protocol = $null; PolicyErrors = $null; Inspected = $false; Error = $null }
    $c = New-Object Net.Sockets.TcpClient
    $ssl = $null
    try {
        if (-not ($c.ConnectAsync($Address, $Port).Wait($TimeoutMs) -and $c.Connected)) { throw 'connect failed or timed out' }
        $c.ReceiveTimeout = $TimeoutMs; $c.SendTimeout = $TimeoutMs
        $script:TlsPolicyErrors = $null
        $cb = [Net.Security.RemoteCertificateValidationCallback] { param($s, $cert, $chain, $errs) $script:TlsPolicyErrors = "$errs"; $true }
        $ssl = New-Object Net.Security.SslStream($c.GetStream(), $false, $cb)
        $ssl.AuthenticateAsClient($HostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $r.Subject = $cert.Subject; $r.Issuer = $cert.Issuer; $r.NotAfter = Format-Date $cert.NotAfter
        $r.Protocol = "$($ssl.SslProtocol)"; $r.PolicyErrors = $script:TlsPolicyErrors
    } catch { $r.Error = $_.Exception.GetBaseException().Message }
    finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        try { $c.Close() } catch { }
    }
    return [pscustomobject]$r
}

function Initialize-CertTrust {
    # Web requests made in parallel check certificates on worker threads, where a PowerShell script block
    # cannot run. This compiles a two-line callback that accepts device certificates (they are self-signed).
    if ($null -ne $script:CertTrustReady) { return $script:CertTrustReady }
    $script:CertTrustReady = $false
    if (-not $script:FullLanguage) { return $false }
    try {
        if (-not ('SaCertTrust' -as [type])) {
            Add-Type -ErrorAction Stop -TypeDefinition 'using System.Net.Security; using System.Security.Cryptography.X509Certificates; public static class SaCertTrust { public static bool Accept(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; } public static RemoteCertificateValidationCallback Callback = new RemoteCertificateValidationCallback(Accept); }'
        }
        $script:CertTrustReady = $true
    } catch { $script:CertTrustReady = $false }
    return $script:CertTrustReady
}

function Get-HttpBannersBulk {
    # One GET per URL, many at a time: status, Server header, page title, a little page text and the
    # certificate names. Nothing is logged in to. Falls back to one at a time when parallel is not possible.
    param([string[]]$Urls, [int]$TimeoutMs = 5000, [int]$BatchSize = 32)
    $out = @()
    if (-not $Urls -or $Urls.Count -eq 0) { return $out }
    if (-not (Initialize-CertTrust)) {
        foreach ($u in ($Urls | Select-Object -First 60)) { $b = Get-HttpBanner $u 2500; $b | Add-Member -NotePropertyName BodySample -NotePropertyValue $null -Force; $b | Add-Member -NotePropertyName AuthRealm -NotePropertyValue $null -Force; $out += $b }
        return $out
    }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    $oldProto = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = [SaCertTrust]::Callback
        # Old phones and printers only speak TLS 1.0/1.1; allow them for this pass if Windows still can.
        try { [Net.ServicePointManager]::SecurityProtocol = $oldProto -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12 } catch { }
        for ($i = 0; $i -lt $Urls.Count; $i += $BatchSize) {
            $batch = @()
            foreach ($u in @($Urls[$i..([math]::Min($i + $BatchSize, $Urls.Count) - 1)])) {
                $req = $null; $task = $null
                try {
                    $req = [Net.HttpWebRequest]::Create($u)
                    $req.ReadWriteTimeout = 3000; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3; $req.KeepAlive = $false
                    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    $task = $req.GetResponseAsync()
                } catch { }
                $batch += , @($u, $req, $task)
            }
            $tasks = @($batch | Where-Object { $_[2] } | ForEach-Object { $_[2] })
            if ($tasks.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks, $TimeoutMs) } catch { } }
            foreach ($b in $batch) {
                $r = [ordered]@{ Url = $b[0]; Status = $null; Server = $null; Title = $null; BodySample = $null; AuthRealm = $null; CertSubject = $null; CertIssuer = $null; CertNotAfter = $null; Error = $null }
                $resp = $null
                if (-not $b[2]) { $r.Error = 'request could not be started' }
                elseif ("$($b[2].Status)" -eq 'RanToCompletion') { $resp = $b[2].Result }
                elseif ($b[2].IsFaulted) {
                    $ex = $b[2].Exception.GetBaseException()
                    if ($ex -is [Net.WebException] -and $ex.Response) { $resp = $ex.Response } else { $r.Error = $ex.Message }
                } else { $r.Error = 'timed out'; try { $b[1].Abort() } catch { } }
                try { if ($b[1] -and $b[1].ServicePoint -and $b[1].ServicePoint.Certificate) { $r.CertSubject = $b[1].ServicePoint.Certificate.Subject; $r.CertIssuer = $b[1].ServicePoint.Certificate.Issuer; $r.CertNotAfter = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $b[1].ServicePoint.Certificate).NotAfter.ToString('s') } } catch { }
                if ($resp) {
                    try {
                        $r.Status = [int]$resp.StatusCode
                        $r.Server = $resp.Headers['Server']
                        $wa = $resp.Headers['WWW-Authenticate']
                        if ($wa -and $wa -match 'realm="?([^",]{1,80})') { $r.AuthRealm = $matches[1] }
                        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                        $buf = New-Object char[] 32768
                        $n = $sr.Read($buf, 0, $buf.Length)
                        if ($n -gt 0) {
                            $body = New-Object string($buf, 0, $n)
                            if ($body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = (($matches[1] -replace '&nbsp;', ' ' -replace '[^\x20-\x7E]', '') -replace '\s+', ' ').Trim() }
                            $text = ((($body -replace '(?s)<script.*?</script>|<style.*?</style>|<!--.*?-->', ' ') -replace '<[^>]+>', ' ') -replace '&nbsp;', ' ' -replace '[^\x20-\x7E]', ' ') -replace '\s+', ' '
                            $r.BodySample = $text.Trim()
                            if ($r.BodySample.Length -gt 200) { $r.BodySample = $r.BodySample.Substring(0, 200) }
                        }
                        $sr.Close()
                    } catch { if (-not $r.Error) { $r.Error = $_.Exception.Message } }
                    try { $resp.Close() } catch { }
                }
                $out += [pscustomobject]$r
            }
        }
    } finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb
        try { [Net.ServicePointManager]::SecurityProtocol = $oldProto } catch { }
    }
    return $out
}

function Get-TcpBannersBulk {
    # Connects to one port on many addresses and keeps what each service says first (SSH, FTP, Telnet).
    param([string[]]$Ips, [int]$Port, [int]$TimeoutMs = 2000)
    $out = @{}
    if (-not $Ips -or $Ips.Count -eq 0) { return $out }
    $items = @()
    foreach ($ip in $Ips) {
        $c = New-Object Net.Sockets.TcpClient; $t = $null
        try { $t = $c.ConnectAsync([string]$ip, $Port) } catch { }
        $items += , @([string]$ip, $c, $t, $null, $null)
    }
    $ct = @($items | Where-Object { $_[2] } | ForEach-Object { $_[2] })
    if ($ct.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$ct, 1500) } catch { } }
    foreach ($it in $items) {
        if ($it[2] -and "$($it[2].Status)" -eq 'RanToCompletion' -and $it[1].Connected) {
            try { $buf = New-Object byte[] 256; $it[3] = $buf; $it[4] = $it[1].GetStream().ReadAsync($buf, 0, 256) } catch { }
        }
    }
    $rt = @($items | Where-Object { $_[4] } | ForEach-Object { $_[4] })
    if ($rt.Count) { try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$rt, $TimeoutMs) } catch { } }
    foreach ($it in $items) {
        try { if ($it[4] -and "$($it[4].Status)" -eq 'RanToCompletion' -and $it[4].Result -gt 0) { $s = ConvertTo-AsciiText $it[3] 0 ([int]$it[4].Result); if ($s) { $out[$it[0]] = $s } } } catch { }
        try { $it[1].Close() } catch { }
    }
    return $out
}

function Invoke-HttpText {
    # One HTTP(S) request with certificate checks off: Status, Server, Title, Body (first 64 KB), Error.
    param([string]$Url, [string]$Method = 'GET', [string]$Body, [string]$ContentType = 'text/xml', [hashtable]$Headers = @{}, [int]$TimeoutMs = 5000)
    $r = [ordered]@{ Url = $Url; Status = $null; Server = $null; Title = $null; Body = $null; Error = $null }
    $oldCb = [Net.ServicePointManager]::ServerCertificateValidationCallback
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = $TimeoutMs; $req.ReadWriteTimeout = $TimeoutMs; $req.AllowAutoRedirect = $true; $req.MaximumAutomaticRedirections = 3
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        foreach ($k in $Headers.Keys) { $req.Headers[$k] = $Headers[$k] }
        if ($Body) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentType = $ContentType; $req.ContentLength = $bytes.Length
            $st = $req.GetRequestStream(); $st.Write($bytes, 0, $bytes.Length); $st.Close()
        }
        $resp = $null
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { $r.Error = $_.Exception.Message } }
        if ($resp) {
            $r.Status = [int]$resp.StatusCode; $r.Server = $resp.Headers['Server']
            try {
                $sr = New-Object IO.StreamReader($resp.GetResponseStream())
                $buf = New-Object char[] 65536
                $n = $sr.Read($buf, 0, $buf.Length)
                $r.Body = New-Object string($buf, 0, [math]::Max(0, $n))
                if ($r.Body -match '<title[^>]*>\s*([^<]{1,120})</title>') { $r.Title = $matches[1].Trim() }
                $sr.Close()
            } catch { }
            $resp.Close()
        }
    } catch { $r.Error = $_.Exception.Message }
    finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCb }
    return [pscustomobject]$r
}
