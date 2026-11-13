# Site Assessment Field Checklist

One page per site. The collector covers the endpoint and its path to the internet; this covers
what a script cannot see.

## Before the visit

### Ask the client
- [ ] ISP bill for each office: carrier, circuit speed (down/up), contract term and end date, monthly cost, static IPs
- [ ] Which office is "main" and whether any office connects through another
- [ ] Who holds firewall / switch / Wi-Fi admin credentials (the client, a hosting provider, another MSP, the ISP)
- [ ] User list per office, shared PCs, and anyone who also works from home
- [ ] Phone system: VoIP on the same circuit? Vendor?
- [ ] Written approval for active discovery (`-Discovery`) if you plan to use it, and any device or subnet to leave alone

### Ask the hosted desktop provider (if the users work in one)
- [ ] Do they manage the on-site firewalls? Model and serial per site
- [ ] Any site-to-site VPN tunnels? Where do they terminate?
- [ ] Gateway hostnames, ports and egress IPs, and whether UDP transport (RD Gateway UDP 3391, RDP Shortpath) is on. Put them in the profile's `Targets` or in `$ExtraTargets`, e.g. `@('rdgw.example.com', '203.0.113.10:7765')`
- [ ] Their network name or ASN, for the profile's `ProviderAsn` (internet that exits there is backhauled)
- [ ] Do they publish full desktops, RemoteApps, or both? Which client do they support?

## Running the collector (per endpoint: about 5 minutes, 10 to 15 with discovery)

- [ ] Join the user's own logged-in Windows session through your remote support tool. If you sign in to an empty console as an admin instead, the script records that admin's profile and misses the user's remote desktop shortcuts, mapped drives and printers
- [ ] Open PowerShell ISE. If you have admin rights, use "Run as administrator": the script detects it and adds TPM, BitLocker, disk health, sign-ins and (on a wired PC) switch identification. Without admin those checks are skipped on their own
- [ ] Paste `Collect-SiteAssessment.ps1` into a new Untitled tab and press F5 (this also gets around execution policy). If the paste was cut short, the script says "STOP: this copy of the script is incomplete" and runs nothing: paste again, or transfer the .ps1 file and open it
- [ ] Set the hosted desktop profile in CONFIG (`$HostedDesktopName`) or pass `-HostedDesktop`. Prefer a PC whose user works in the hosted desktop: the script reads the client app's files, the RDP history and the DNS cache, no sign-in needed
- [ ] Expect a quiet wait of about 2 minutes in the middle ("Waiting for traceroutes and the 180-sample ping and TCP series"). That is the 3-minute loss and latency measurement
- [ ] Bandwidth, traceroutes and latency run first and are saved. With discovery on, the gateway probes and the subnet sweep run last, so if security software reacts to them the main results are already on disk
- [ ] Discovery is off by default. Turn it on with `-Discovery` (or `$EnableDiscovery = $true`) only with the client's approval. Each discovery check has its own `$Enable...` switch to leave one out
- [ ] If the session drops during discovery, the run folder still holds `assessment.json` with the bandwidth and traceroutes. Retrieve the folder; the merge marks it INCOMPLETE
- [ ] Use the same site name on every machine at a site. A `$SiteList` in CONFIG gives a numbered menu
- [ ] Cloudflare rate-limits the speed test per public IP. Two runs per site is fine; if a run shows "Download FAILED ... HTTP 429", wait about 10 minutes before re-running that machine
- [ ] One machine gives a complete answer for that machine. Two or more per site (one wired, one Wi-Fi) let the merge confirm the site's traffic design and compare
- [ ] Leave the user's normal programs open while it runs: the script samples CPU and memory in use and lists the largest programs, which shows whether the PC itself is the slow part
- [ ] Do not run two machines at one site at the same moment: their bandwidth tests share the circuit and both read low. Start the second about 5 minutes after the first (the merge warns if two tests overlapped)
- [ ] At the end the console shows a DATA CHECK block. The script has already read its own output back and retried any failed bandwidth, traceroute, ping or public IP test once
  - PASS or WARN: the data is usable (WARN names the gaps a second machine could fill)
  - FAIL: something critical is still missing (the ACTION line names it). Re-run that machine, or run another machine at the site
  - "OUTPUT PROBLEM": the zip did not verify, so retrieve the whole run folder instead
- [ ] Output lands in `C:\Users\Public\Documents\SiteAssessment\` (local, not synced to OneDrive). The folder opens with the zip selected
- [ ] Pull `SITE_HOST_yyyyMMdd-HHmm.zip` back with your remote support tool's file transfer. The data check and summary are also on the clipboard, so you can paste them on your side if file transfer is blocked

## Using one laptop at every site

A laptop carried from site to site measures each site's network (bandwidth, traceroute, latency and, with discovery, the sweep). It says nothing about the client's PCs. The merge spots it by its serial number appearing at two or more sites and leaves its own hardware, software, printers and history out of the report.

- [ ] Wired run first, at every site: plug into a wall jack a user's PC normally uses (not a guest or conference-room port)
- [ ] Run ISE as administrator on the wired run: it also captures the switch model and port (LLDP/CDP)
- [ ] Wi-Fi run only if the laptop can join the staff SSID. Guest Wi-Fi is often throttled or on a separate network
- [ ] One adapter at a time: turn Wi-Fi off for the wired run, unplug the cable for the Wi-Fi run
- [ ] No VPN connected on the laptop (an always-on VPN makes every site look like full backhaul). The laptop must take its address and DNS from the site (DHCP)
- [ ] If at all possible, also run one real user's PC per site: that is the only source for desk hardware, printers, peripherals, the hosted desktop app and real session history
- [ ] If only one site has been visited so far, name the laptop when merging: `-TestDevice <its host name>`

## Closet / network walk (photograph every label)

- [ ] ISP modem / ONT: carrier, model, circuit ID, account number sticker
- [ ] Firewall: make, model, serial, license/subscription sticker, port count, which ports are in use
- [ ] Switch(es): make, model, port count, PoE (yes/no), managed (console port / web UI / cloud LED)
- [ ] Access points: make/model, count, where mounted, how powered (PoE vs. injector)
- [ ] UPS: present? model, battery age, what is plugged in
- [ ] Cabling: patch panel labeled? cable category printed on the jacket, condition
- [ ] Rack / shelf / closet condition, ventilation, locked
- [ ] Anything else on the network: printers/copiers (model + IP), cameras, door access, VoIP phones

## At each desk (no user needed)

- [ ] Photo of the desk setup: monitors, dock, peripherals (scanner, label printer, signature pad, headset)
- [ ] Wall jack labeled? Cable from wall to PC in good condition?

## After the visit

- [ ] Put all zips for all sites in one folder
- [ ] Run: `.\Merge-SiteAssessment.ps1 -Path <folder or one zip> -ClientName '<Client name>'`
- [ ] Run the merge on a PC with internet. It looks up who owns each public IP address (network, whois record, reverse DNS), the maker of any MAC address that was not identified on site, and what Shodan's InternetDB lists as visible on each site's public address. Only public IP addresses are sent; the MAC list is downloaded from IEEE once. Lookups are kept in `%LOCALAPPDATA%\SiteAssessment\cache`, so merging again is quick. Add `-NoEnrich` to make no requests at all
- [ ] Review `_merged\Report.html` (overview cards, then one section per site that opens with bandwidth and the traceroute path). The merge prints any machine whose data check FAILED, and the Data check column shows each machine's result
- [ ] The CSVs in `_merged\` hold the same data for spreadsheets: Sites, Endpoints, Printers, Peripherals, NetworkGear, Flags, Findings, Devices, Software, Traceroutes, PingSeries, RdpTargets, Subnets, IpOwners
