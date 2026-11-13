<#
.SYNOPSIS
    Site assessment collector: measures this PC, its path to the internet and (with -Discovery)
    the network around it, then writes one zip per run for Merge-SiteAssessment.ps1.

.DESCRIPTION
    Built for Windows PowerShell 5.1 in PowerShell ISE (also runs in PowerShell 7), as a
    standard user. Open in ISE and press F5, or paste into a new Untitled tab and press F5.
    Run ISE as administrator to add TPM, BitLocker, disk health, sign-ins and a passive
    listen on the wire (switch and port from LLDP/CDP, VLANs, DHCP servers); without it
    those checks are skipped on their own. Nothing is installed.

    A plain run looks at this PC and its path to the internet:
    - inventory, Wi-Fi, event logs, patching, the remote desktop footprint and session health
    - bandwidth (Cloudflare, then M-Lab, then Vultr), bufferbloat, a 3-minute loss and
      jitter series, traceroutes, path MTU, carrier-grade NAT and double NAT
    - a traffic-design verdict (local breakout, split tunnel or full backhaul)
    - whether remote desktop sessions can use UDP or are stuck on TCP
    - IPv6 (offered, and whether it reaches the internet; /64 prefixes only are kept)
    - the client's email domain in public DNS (MX, SPF, DMARC, DKIM)
    - on a domain PC, Active Directory's sites and subnets, checked against where the PC is
    - Microsoft 365 reachability, outbound port filtering, DNS filtering and call quality

    Active discovery of other devices is OFF unless you pass -Discovery (or set
    $EnableDiscovery below). It adds: a sweep of this subnet and of the other subnets you
    list or pick at a prompt (inferred subnets are never swept on their own), names, open
    ports, web pages and banners, Windows builds, SIP phone models, vendor and multicast
    discovery, read-only SNMP (switch ports, printers, and from routers their ARP table,
    routes and WAN address; UPS battery and runtime), IPP and RTSP questions to printers and
    cameras, the ISP modem page, the gateway's admin ports and UPnP/NAT-PMP mappings, and
    follow-up checks chosen by what was found (the firewall's own VPN and admin pages,
    server management controllers, VMware hosts, QNAP and Synology, RD Web and RD Gateway).
    No logon is attempted anywhere and no passwords are tried. SNMP reads do use a community
    string: one only, 'public' unless you set $SnmpCommunity, which is the read-only default
    many devices ship with. Set $EnableSnmp = $false to leave it out. Only run discovery on
    networks you are authorised to assess.

    Nothing sensitive is collected: no passwords, saved credentials, Wi-Fi keys, BitLocker
    recovery keys, browser data or file contents. What leaves the PC, when enabled: the
    public IP to Cloudflare (trace, speed test), ipinfo.io and rdap.org; MAC vendor prefixes
    to api.macvendors.com; the email domain to public DNS (1.1.1.1, or this PC's own DNS
    server when 1.1.1.1 cannot be reached); connection tests to Microsoft 365, public STUN
    and NTP servers and portquiz.net. M-Lab and Vultr are used only when the Cloudflare
    speed test fails. M-Lab publishes every test, including the public IP, in its open
    dataset: remove 'MLab' from $BandwidthProviders if the client would object. Vultr only
    tests download, so without M-Lab a failed Cloudflare upload test leaves no upload figure.

.PARAMETER SiteName
    Site/office name. Prompted for when omitted.

.PARAMETER Notes
    Optional free-text notes (desk location, etc). Prompted for when omitted.

.PARAMETER OutputPath
    Overrides $OutputRoot for this run.

.PARAMETER NoPrompt
    Do not prompt or open Explorer; use SiteName/Notes as given (SiteName defaults to UNSPECIFIED).
    With -Discovery, only the subnets listed in CONFIG are swept (no prompt).

.PARAMETER Discovery
    Turns on active discovery of other devices on the network (see DESCRIPTION).

.PARAMETER HostedDesktop
    Name of a built-in hosted desktop profile: RDP (default), AzureVirtualDesktop,
    Windows365 or CitrixCloud. Set $HostedDesktopProfile below to describe your own.

.PARAMETER ConfigPath
    A .psd1 file whose keys override the CONFIG values below for this run (see
    site-assessment.config.example.psd1).

.EXAMPLE
    .\Collect-SiteAssessment.ps1 -SiteName 'Main office'

.EXAMPLE
    .\Collect-SiteAssessment.ps1 -SiteName 'Main office' -HostedDesktop AzureVirtualDesktop -Discovery
#>
param(
    [string]$SiteName,
    [string]$Notes,
    [string]$OutputPath,
    [switch]$NoPrompt,
    [switch]$Discovery,
    [string]$HostedDesktop,
    [string]$ConfigPath
)
