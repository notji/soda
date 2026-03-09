# soda

A tiny (<50KB) selective DNS proxy for Windows to point configurable TLDs like `.test` to localhost. Uses NRPT rules so Windows routes only matching queries to it, leaving other queries unaffected. Runs as a console app or a Windows service.

Can be used to resolve `example.test` domains to an nginx server running on WSL.

- [Installation](#installation)
- [Usage](#usage)
- [Windows service](#windows-service)
- [Building](#building)
- [Compatibility](#compatibility)
- [How it works](#how-it-works)

## Installation

Download `soda.exe` from the [releases page](https://github.com/notji/soda/releases) and place it somewhere on your system (e.g. `C:\bin\soda.exe`).

## Usage

```
soda.exe [options]

Options:
  -t, --tld <tld>   TLD to resolve (default: test, repeatable: max 16)
  -v, --verbose     Verbose logging
  -s, --service     Run as Windows service
```

Requires admin privileges (binds port 53, writes NRPT registry keys).

### Example usage

```
// Defaults to .test
soda.exe

// Single tld with logging enabled
soda.exe --tld dev --verbose

// Multiple tlds
soda.exe --tld test --tld local --tld dev
```

## Windows service

Create and start the service with `sc.exe`:

> [!NOTE]
> The spaces in `binPath= ` and `start= auto` are required. The `--service` flag is also required to run soda as a Windows service.

```
sc.exe create soda binPath= "C:\path\to\soda.exe --tld test --service" start= auto
sc.exe start soda
```

Stop and remove:

```
sc.exe stop soda
sc.exe delete soda
```

## Building

Cross-compiled from WSL2 targeting Windows x86_64.

### Prerequisites

```bash
sudo apt install gcc-mingw-w64-x86-64
```

### Build

```bash
make          # outputs build/soda.exe
make clean
```

## Compatibility

Soda creates local NRPT (Name Resolution Policy Table) rules to route matching DNS queries to itself. If any Group Policy NRPT rules exist on the machine, Windows ignores all local NRPT rules entirely. This means soda won't work on systems with Group managed DNS policies.

Soda binds on `127.0.0.1` and `::1` but only resolves domains matching configured TLDs, everything else gets NXDOMAIN. If your network adapter has `::1` or `127.0.0.1` set as a DNS server, all DNS queries will be routed to soda through normal DNS resolution (bypassing NRPT entirely), and non-matching queries will fail. Make sure your adapter DNS servers point to real upstream resolvers (e.g. `1.1.1.1`, `2606:4700:4700::1111`), not loopback addresses.

## How it works

On startup, soda creates one NRPT registry key per TLD (e.g. `soda-test`, `soda-local`) that tells Windows to route DNS queries for that TLD to `127.0.0.1`, then signals the DNS Client service to reload. Soda binds UDP port 53 on both IPv4 (`127.0.0.1`) and IPv6 (`::1`) and waits for queries.

When a query arrives, soda checks if the domain matches any configured TLD. Matches get an A record (`127.0.0.1`) or AAAA record (`::1`). Everything else gets NXDOMAIN.

A network change listener monitors for interface changes (e.g. switching Wi-Fi networks, VPN connect/disconnect) that can cause Windows to drop NRPT rules, and reapplies any that disappeared.

On shutdown (Ctrl+C or service stop), soda removes all NRPT keys and signals the DNS Client service to reload, leaving the system clean. If cleanup fails, NRPT keys are not persistent and clear after reboot.
