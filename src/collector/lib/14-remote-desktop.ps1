# ---------------------------------------------------------------------
# Remote desktop transport: can sessions here use UDP, or are they stuck on TCP? RDP over TCP feels
# slower and stalls on loss. Read from what the run already collected: the RDP client's own record of
# UDP attempts, the client UDP policy, the STUN test (UDP 3478 out and how the NAT maps ports), and
# Microsoft's list of things that break RDP Shortpath (double NAT, carrier-grade NAT, a full-tunnel
# VPN, packet inspection). Sends nothing.
# ---------------------------------------------------------------------
function Get-RdpTransportCheck {
    param($R)
    $udp = Get-Prop $R 'EventLogs', 'RdpClient', 'Udp'
    $est = [int](Get-Prop $udp 'Established'); $att = [int](Get-Prop $udp 'Attempted'); $fail = [int](Get-Prop $udp 'Failed')
    $pol = Get-Prop $R 'Session', 'UdpPolicy'
    $stun = @(@(Get-Prop $R 'Cloud', 'Stun') | Where-Object { $_ })
    $answered = @($stun | Where-Object { Get-Prop $_ 'Answered' })
    $ports = @($answered | ForEach-Object { Get-Prop $_ 'MappedPort' } | Where-Object { $_ } | Select-Object -Unique)
    $profile = "$(Get-Prop $R 'Meta', 'HostedDesktop', 'Profile')"
    $shortpath = $profile -in @('AzureVirtualDesktop', 'Windows365')
    $inet = @(@(Get-Prop $R 'Traceroutes') | Where-Object { $_ -and "$(Get-Prop $_ 'Target')" -eq '1.1.1.1' }) | Select-Object -First 1

    $evidence = @()
    if ($att -or $est -or $fail) { $evidence += "RDP client log: UDP attempted $att, established $est, failed $fail" }
    if (Get-Prop $pol 'UdpDisabled') { $evidence += "UDP is turned off for the RDP client ($(Get-Prop $pol 'Source'))" }
    if ($stun.Count) { $evidence += "STUN on UDP: $($answered.Count) of $($stun.Count) servers answered$(if ($ports.Count -gt 1) { ', with a different public port for each (symmetric NAT)' } elseif ($ports.Count -eq 1) { ', with the same public port for each' })" }

    $verdict = if ($est -gt 0) { 'UDP in use' }
               elseif (Get-Prop $pol 'UdpDisabled') { 'TCP only: UDP turned off on this PC' }
               elseif ($stun.Count -and -not $answered.Count) { 'TCP only: outbound UDP blocked' }
               elseif ($ports.Count -gt 1) { $(if ($shortpath) { 'Relayed UDP only (symmetric NAT)' } else { 'UDP may fail (symmetric NAT)' }) }
               elseif ($answered.Count) { 'UDP possible' }
               else { 'Not known' }

    # What Microsoft says gets in the way of a direct UDP path (RDP Shortpath, public networks)
    $caveats = @()
    if (Get-Prop $inet 'Analysis', 'DoubleNatLikely') { $caveats += 'double NAT (an ISP router doing NAT in front of the firewall)' }
    if ([int](Get-Prop $inet 'Analysis', 'CgnatHops') -gt 0) { $caveats += 'carrier-grade NAT at the ISP' }
    if (Get-Prop $R 'Network', 'VpnHoldsDefaultRoute') { $caveats += 'a full-tunnel VPN carries all traffic' }
    if (Get-Prop $R 'Tls', 'InspectionSuspected') { $caveats += 'HTTPS inspection, so packet inspection is likely in the path' }
    return [pscustomobject]@{ Verdict = $verdict; Shortpath = $shortpath; Caveats = $caveats; Evidence = $evidence }
}

function Get-RdpTransportFlags {
    param($C, [bool]$UsesRemoteDesktop = $true)
    if (-not $C -or -not $UsesRemoteDesktop) { return @() }
    $f = { param($sev, $msg) [pscustomobject]@{ Severity = $sev; Category = 'RDP'; Message = $msg } }
    switch -Wildcard ("$($C.Verdict)") {
        'TCP only: outbound UDP blocked' { return @(& $f 'Medium' 'Remote desktop sessions can only use TCP here: outbound UDP is blocked. Allow UDP 3478 out (and, for Azure Virtual Desktop or Windows 365, UDP to 51.5.0.0/16 port 3478) so sessions can use the faster UDP transport') }
        'TCP only: UDP turned off*' { return @(& $f 'Medium' 'Remote desktop sessions can only use TCP: UDP is turned off for the RDP client on this PC (policy "Turn Off UDP On Client" or the client setting)') }
        'Relayed UDP only*' { return @(& $f 'Low' 'Symmetric NAT here: Azure Virtual Desktop can only use UDP through the TURN relay, so UDP 3478 to 51.5.0.0/16 must stay open') }
        default { return @() }
    }
}
