# Per-job settings for Collect-SiteAssessment.ps1. Copy this file, edit it, and pass it with
#   .\Collect-SiteAssessment.ps1 -ConfigPath .\contoso.psd1
# Every key overrides the CONFIG value of the same name in the script; unknown keys are ignored
# with a warning. Leave out anything you do not need. All values below are examples.
@{
    # Numbered site menu, so every machine at a site uses the same name
    SiteList          = @('Main office', 'Warehouse')

    # Which built-in hosted desktop profile to use: RDP, AzureVirtualDesktop, Windows365, CitrixCloud
    HostedDesktopName = 'RDP'

    # Or describe your own provider (used instead of HostedDesktopName):
    # HostedDesktopProfile = @{
    #     Name        = 'Contoso Cloud'
    #     HostPattern = 'contosocloud\.com'           # host names in the DNS cache / reverse DNS
    #     AppPattern  = 'ContosoConnect'              # the client app's file, folder and process names
    #     Targets     = @('connect.contosocloud.com:443')
    #     ProviderAsn = 'Contoso Cloud|AS64500'       # internet that exits here is backhauled
    # }

    # Hosts tested on every machine in addition to the profile's own targets (host or host:port)
    ExtraTargets      = @('rdgw.contoso.com', '203.0.113.10:7765')

    # Office subnets (first 3 octets, one /24 each): reverse DNS and reachability, with -Discovery
    SiteSubnets       = @('10.10.1', '10.10.2')

    # Other subnets to sweep with -Discovery, without asking at the prompt: 'a.b.c' (a /24) or
    # 'a.b.c.d/22' to '/30'. SiteSubnets are swept too. At most 8 per run.
    ScanSubnets       = @('10.10.8.0/23')

    # Servers across a site tunnel to test from an office port, with -Discovery
    TunnelServers     = @('10.10.0.10', '10.10.0.11')

    # Call-pace sample targets: the phone system, then the internet
    VoiceTargets      = @('10.10.0.20', '1.1.1.1')

    # Leave one discovery check out even when -Discovery is on
    EnableSnmp        = $false
}
