<#
.SYNOPSIS
    Site assessment collector: endpoint inventory, connection type, remote desktop footprint,
    path and traffic-design tests and a bandwidth test. Writes one zip per run.

.DESCRIPTION
    Built for Windows PowerShell 5.1 in PowerShell ISE, runnable as a standard user.
    Open in ISE and press F5 (or paste into a new Untitled tab and press F5).
    Run ISE as administrator to add TPM, BitLocker, disk health, sign-ins and the
    switch / wire capture; without it those checks are skipped on their own.

    Nothing is installed. Nothing sensitive is collected: no passwords, saved
    credentials, Wi-Fi keys, BitLocker recovery keys, browser data or file contents.
    The public IP is sent to Cloudflare (trace/meta/speed test), ipinfo.io, rdap.org
    (whois for the address block) and api.macvendors.com (MAC vendor prefix only) when
    those options are enabled.

    A plain run looks only at this PC and its path to the internet: inventory, Wi-Fi,
    event logs, the remote desktop footprint, bandwidth, traceroutes, latency and loss,
    and a traffic-design verdict (local breakout, split tunnel or full backhaul).

    Active discovery of other devices on the network is OFF unless you pass -Discovery
    (or set $EnableDiscovery below). It adds: a subnet sweep with a few TCP ports per
    device, vendor discovery (Ubiquiti, MikroTik, Netgear), mDNS, WS-Discovery and SSDP,
    web page titles and SSH/FTP banners, SIP phone models, Windows names and builds,
    read-only SNMP with the default community, IPP and RTSP questions to printers and
    cameras, the ISP modem page, the gateway's admin ports and UPnP/NAT-PMP mappings,
    reverse DNS for the office subnets you list, and reachability of servers you list.
    No logon is attempted anywhere and no default passwords are tried. Only run
    discovery on networks you are authorised to assess.

.PARAMETER SiteName
    Site/office name. Prompted for when omitted.

.PARAMETER Notes
    Optional free-text notes (desk location, etc). Prompted for when omitted.

.PARAMETER OutputPath
    Overrides $OutputRoot for this run.

.PARAMETER NoPrompt
    Do not prompt or open Explorer; use SiteName/Notes as given (SiteName defaults to UNSPECIFIED).

.PARAMETER Discovery
    Turns on active discovery of other devices on the network (see DESCRIPTION).

.PARAMETER HostedDesktop
    Name of a built-in hosted desktop profile: RDP (default), AzureVirtualDesktop,
    Windows365 or CitrixCloud. See $HostedDesktopProfiles below to add your own.

.PARAMETER ConfigPath
    A .psd1 file whose keys override the CONFIG values below for this run (see
    site-assessment.config.example.psd1).
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
