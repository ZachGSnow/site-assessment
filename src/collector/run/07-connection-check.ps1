# ---------------------------------------------------------------------
# Connection check: printed before anything is measured, so a wrong starting point is seen now.
# Link speed is only reported here (the findings at the end say whether the port or the circuit
# set the limit). The one question asked is whether to go on when this looks like a hosted desktop.
# ---------------------------------------------------------------------
$script:Preflight = [ordered]@{ Model = $null; IsVirtualMachine = $false; LooksLikeHostedDesktop = $false; Notes = @(); Answer = $null }
try {
    $pcs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
    $script:Preflight['Model'] = ('{0} {1}' -f $pcs.Manufacturer, $pcs.Model).Trim()
    $script:Preflight['IsVirtualMachine'] = [bool]($script:Preflight['Model'] -match 'VMware|Virtual Machine|VirtualBox|KVM|QEMU|Xen|Parallels|Amazon EC2|Google Compute')
} catch { }
try {
    $pfAd = $null
    if ($Net -is [System.Collections.IDictionary] -and $Net.Contains('Adapters')) { $pfAd = @($Net['Adapters'] | Where-Object { $_.Name -eq $Net['PhysicalAdapter'] }) | Select-Object -First 1 }
    $pfWired = ($pfAd -and "$($Net['PhysicalClass'])" -like 'Wired*')
    Write-Host ''
    Write-Host 'CONNECTION CHECK' -ForegroundColor White
    if ($pfAd) {
        Write-Host ('  Adapter   {0} ({1})' -f $pfAd.Description, $Net['PhysicalClass'])
        Write-Host ('  Link      {0} Mbps{1}' -f $Net['PhysicalLinkMbps'], $(if ($pfWired) { '' } else { ' (radio rate, changes with signal)' }))
        Write-Host ('  Address   {0}  mask {1}  gateway {2}' -f (@($pfAd.IPv4) -join ', '), @($pfAd.SubnetMask)[0], $Gateway)
        Write-Host ('  DHCP      {0}' -f $(if ($pfAd.DhcpEnabled) { "from $($pfAd.DhcpServer)" } else { 'off (static address)' }))
        Write-Host ('  DNS       {0}' -f (@($pfAd.DnsServers) -join ', '))
    } else {
        Write-Host '  No active adapter with a route to the internet was found.' -ForegroundColor Yellow
    }
    Write-Host ('  Machine   {0}{1}' -f $script:Preflight['Model'], $(if ($script:Preflight['IsVirtualMachine']) { '  (virtual machine)' } else { '' }))
    $pfNotes = @()
    if ($pfWired -and $Net['PhysicalLinkMbps'] -and $Net['PhysicalLinkMbps'] -lt 1000) { $pfNotes += "Link is $($Net['PhysicalLinkMbps']) Mbps, so the speed test cannot read above that on this port. The findings at the end say whether the port or the circuit set the limit." }
    if ($pfWired -and -not $script:AdminActive) { $pfNotes += 'ISE is not elevated: the switch cannot be identified and the wire capture will not run.' }
    if ($pfAd -and @($pfAd.IPv4 | Where-Object { $_ -like '169.254.*' }).Count) { $pfNotes += 'The adapter has a 169.254 address: no DHCP server answered.' }
    if ($Net -is [System.Collections.IDictionary] -and $Net['VpnHoldsDefaultRoute']) { $pfNotes += "A VPN adapter holds the default route ($($Net['PrimaryAdapter'])): results would describe the VPN, not this site. Disconnect it and run again." }
    if ($Net -is [System.Collections.IDictionary] -and $Net['MultipleConnected']) { $pfNotes += "More than one adapter is connected ($(@($Net['ConnectedPhysical']) -join '; ')). Turn off the one you are not testing." }
    $pfIp = if ($pfAd) { "$(@($pfAd.IPv4)[0])" } else { '' }
    $pfHosted = ($script:Preflight['IsVirtualMachine'])
    $script:Preflight['LooksLikeHostedDesktop'] = [bool]$pfHosted
    foreach ($nt in $pfNotes) { Write-Host "  NOTE      $nt" -ForegroundColor Yellow }
    $script:Preflight['Notes'] = $pfNotes
    if ($pfHosted) {
        Write-Host '  WARNING   This looks like a hosted desktop or virtual machine, not a PC at the site.' -ForegroundColor Red
        Write-Host '            A run here measures the data center or cloud, not the office network.' -ForegroundColor Red
        if (-not $NoPrompt) {
            $script:Preflight['Answer'] = Read-Host '  Type Y to run here anyway, anything else to stop'
            if ("$($script:Preflight['Answer'])".Trim() -notmatch '^(y|yes)$') {
                Write-Host 'Stopped. Nothing was measured. Run the script on a PC or laptop plugged into the site network.' -ForegroundColor Yellow
                if ($script:Transcript) { try { Stop-Transcript | Out-Null } catch { } }
                return
            }
        }
    }
    Write-Host ''
} catch { $script:Errors += [pscustomobject]@{ Collector = 'Connection check'; Error = $_.Exception.Message } }
$Result['Preflight'] = $script:Preflight
