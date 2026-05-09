> [!NOTE]
> This manual is mostly AI translated from russian

# Contents

- [Contents](#contents)
- [Introduction](#introduction)
- [Project structure](#project-structure)
- [Traffic processing scheme](#traffic-processing-scheme)
- [Traffic interception from the OS Kernel](#traffic-interception-from-the-os-kernel)
  - [Traffic interception in the Linux kernel](#traffic-interception-in-the-linux-kernel)
    - [Traffic interception using nftables](#traffic-interception-using-nftables)
    - [Traffic interception using iptables](#traffic-interception-using-iptables)
  - [Traffic interception in the FreeBSD kernel](#traffic-interception-in-the-freebsd-kernel)
  - [Traffic interception in the OpenBSD kernel](#traffic-interception-in-the-openbsd-kernel)
  - [Traffic interception in the Windows kernel](#traffic-interception-in-the-windows-kernel)
- [nfqws2](#nfqws2)
  - [General principles for setting parameters](#general-principles-for-setting-parameters)
  - [Full list of options](#full-list-of-options)
  - [Protocol detection](#protocol-detection)
  - [Using multiple profiles](#using-multiple-profiles)
    - [Profile templates](#profile-templates)
    - [Filtering by ipsets](#filtering-by-ipsets)
    - [Filtering by lists](#filtering-by-lists)
    - [Autohostlist failure detector](#autohostlist-failure-detector)
    - [Network presence filter](#network-presence-filter)
  - [Server mode](#server-mode)
  - [IP cache](#ip-cache)
  - [Signals](#signals)
  - [Debugging](#debugging)
  - [Virtual machines](#virtual-machines)
  - [Sandbox](#sandbox)
  - [Calling Lua code](#calling-lua-code)
    - [Passing blobs](#passing-blobs)
    - [In-profile filters](#in-profile-filters)
    - [Typical instance invocation scheme within a profile](#typical-instance-invocation-scheme-within-a-profile)
  - [Lua desync function prototype](#lua-desync-function-prototype)
    - [Structure of the desync table](#structure-of-the-desync-table)
    - [Dissect structure](#dissect-structure)
    - [Handling multi-packet payloads](#handling-multi-packet-payloads)
    - [The track table structure](#the-track-table-structure)
      - [ICMP processing](#icmp-processing)
      - [raw IP processing](#raw-ip-processing)
  - [Timers](#timers)
    - [Timer function prototype](#timer-function-prototype)
- [nfqws2 C interface](#nfqws2-c-interface)
  - [Base constants](#base-constants)
  - [Standard blobs](#standard-blobs)
  - [Environment variables](#environment-variables)
  - [C functions](#c-functions)
    - [Logging](#logging)
    - [IP conversion](#ip-conversion)
    - [Bitwise operations](#bitwise-operations)
    - [Unsigned number operations](#unsigned-number-operations)
      - [uX](#ux)
      - [buX](#bux)
      - [swapX](#swapx)
      - [uXadd](#uxadd)
    - [Integer division](#integer-division)
      - [divint](#divint)
    - [Random Data Generation](#random-data-generation)
      - [brandom](#brandom)
    - [Parsing](#parsing)
      - [parse_hex](#parse_hex)
    - [Cryptography](#cryptography)
      - [bcryptorandom](#bcryptorandom)
      - [bxor,bor,band](#bxorborband)
      - [hash](#hash)
      - [aes](#aes)
      - [aes_gcm](#aes_gcm)
      - [aes_ctr](#aes_ctr)
      - [hkdf](#hkdf)
    - [Compression](#compression)
      - [gunzip](#gunzip)
      - [gzip](#gzip)
    - [System functions](#system-functions)
      - [uname](#uname)
      - [clock_gettime](#clock_gettime)
      - [getpid](#getpid)
      - [stat](#stat)
      - [time](#time)
    - [Packet handling options](#packet-handling-options)
      - [standard reconstruct](#standard-reconstruct)
      - [standard rawsend](#standard-rawsend)
    - [Dissection and reconstruction](#dissection-and-reconstruction)
      - [dissect](#dissect)
      - [reconstruct_dissect](#reconstruct_dissect)
      - [reconstruct_hdr](#reconstruct_hdr)
      - [csum_fix](#csum_fix)
    - [conntrack](#conntrack)
    - [Obtaining IP addresses](#obtaining-ip-addresses)
    - [Receiving and sending Packets](#receiving-and-sending-packets)
      - [rawsend](#rawsend)
      - [raw_packet](#raw_packet)
    - [Working with payloads](#working-with-payloads)
      - [Markers](#markers)
      - [resolve_pos](#resolve_pos)
      - [tls_mod](#tls_mod)
    - [Instance execution management](#instance-execution-management)
      - [instance_cutoff](#instance_cutoff)
      - [lua_cutoff](#lua_cutoff)
      - [execution_plan](#execution_plan)
      - [execution_plan_cancel](#execution_plan_cancel)
    - [Timer control](#timer-control)
      - [timer_set](#timer_set)
      - [timer_del](#timer_del)
      - [timer_info](#timer_info)
      - [timer_enum](#timer_enum)
- [zapret-lib.lua base function library](#zapret-liblua-base-function-library)
  - [Base desync functions](#base-desync-functions)
    - [luaexec](#luaexec)
    - [pass](#pass)
    - [pktdebug](#pktdebug)
    - [argdebug](#argdebug)
    - [posdebug](#posdebug)
    - [detect_payload_str](#detect_payload_str)
    - [desync_orchestrator_example](#desync_orchestrator_example)
  - [Utility functions](#utility-functions)
    - [var_debug](#var_debug)
    - [deepcopy](#deepcopy)
    - [logical_xor](#logical_xor)
    - [array_search](#array_search)
  - [String operations](#string-operations)
    - [in_list](#in_list)
    - [find_next_line](#find_next_line)
  - [Raw string handling](#raw-string-handling)
    - [hex](#hex)
    - [pattern](#pattern)
    - [blob](#blob)
  - [TCP sequence number handling](#tcp-sequence-number-handling)
  - [Position handling](#position-handling)
  - [Dissection](#dissection)
    - [dissect_url](#dissect_url)
    - [dissect_nld](#dissect_nld)
    - [dissect_http](#dissect_http)
    - [dissect_tls](#dissect_tls)
  - [Working with L3 and L4 protocol elements](#working-with-l3-and-l4-protocol-elements)
    - [find_tcp_options](#find_tcp_options)
    - [ip6hdr](#ip6hdr)
    - [ip protocol](#ip-protocol)
    - [packet_len](#packet_len)
  - [Working with hostnames](#working-with-hostnames)
    - [genhost](#genhost)
    - [host_ip](#host_ip)
  - [File name and path operations](#file-name-and-path-operations)
  - [Reading and writing Files](#reading-and-writing-files)
  - [Data compression](#data-compression)
  - [autottl](#autottl)
  - [Operations with dissects](#operations-with-dissects)
    - [standard ipid](#standard-ipid)
    - [standard fooling](#standard-fooling)
    - [standard ipfrag](#standard-ipfrag)
    - [apply_ip_id](#apply_ip_id)
    - [apply_fooling](#apply_fooling)
    - [ipfrag2](#ipfrag2)
    - [wssize_rewrite](#wssize_rewrite)
    - [dis_reverse](#dis_reverse)
  - [IP addresses and interfaces](#ip-addresses-and-interfaces)
  - [Sending](#sending)
    - [rawsend_dissect_ipfrag](#rawsend_dissect_ipfrag)
    - [rawsend_dissect_segmented](#rawsend_dissect_segmented)
    - [rawsend_payload_segmented](#rawsend_payload_segmented)
  - [Standard direction and payload filters](#standard-direction-and-payload-filters)
  - [Working with multi-packet payloads](#working-with-multi-packet-payloads)
  - [Timer helpers](#timer-helpers)
  - [Orchestration](#orchestration)
    - [instance_cutoff_shim](#instance_cutoff_shim)
    - [cutoff_shim_check](#cutoff_shim_check)
    - [apply_arg_prefix](#apply_arg_prefix)
    - [apply_execution_plan](#apply_execution_plan)
    - [verdict_aggregate](#verdict_aggregate)
    - [plan_instance_execute](#plan_instance_execute)
    - [plan_instance_pop](#plan_instance_pop)
    - [plan_clear](#plan_clear)
    - [orchestrate](#orchestrate)
    - [replay_execution_plan](#replay_execution_plan)
- [zapret-antidpi.lua DPI attack program library](#zapret-antidpilua-dpi-attack-program-library)
  - [Standard parameter sets](#standard-parameter-sets)
    - [standard direction](#standard-direction)
    - [standard payload](#standard-payload)
  - [Base functions](#base-functions)
    - [drop](#drop)
    - [send](#send)
    - [pktmod](#pktmod)
  - [HTTP fooling](#http-fooling)
    - [http_hostcase](#http_hostcase)
    - [http_domcase](#http_domcase)
    - [http_methodeol](#http_methodeol)
    - [http_unixeol](#http_unixeol)
  - [Window size replacement](#window-size-replacement)
    - [wsize](#wsize)
    - [wssize](#wssize)
  - [Fakes](#fakes)
    - [syndata](#syndata)
    - [tls_client_hello_clone](#tls_client_hello_clone)
    - [fake](#fake)
    - [rst](#rst)
  - [TCP segmentation](#tcp-segmentation)
    - [multisplit](#multisplit)
    - [multidisorder](#multidisorder)
    - [multidisorder_legacy](#multidisorder_legacy)
    - [fakedsplit](#fakedsplit)
    - [fakeddisorder](#fakeddisorder)
    - [hostfakesplit](#hostfakesplit)
    - [tcpseg](#tcpseg)
    - [oob](#oob)
  - [UDP Fooling](#udp-fooling)
    - [udplen](#udplen)
    - [dht_dn](#dht_dn)
  - [Other Functions](#other-functions)
    - [synack](#synack)
    - [synack_split](#synack_split)
- [zapret-auto.lua automation and orchestration library](#zapret-autolua-automation-and-orchestration-library)
  - [State storage](#state-storage)
    - [automate_conn_record](#automate_conn_record)
    - [standard_hostkey](#standard_hostkey)
    - [automate_host_record](#automate_host_record)
  - [Handling successes and failures](#handling-successes-and-failures)
    - [automate_failure_counter](#automate_failure_counter)
    - [automate_failure_counter_reset](#automate_failure_counter_reset)
  - [Success and failure detection](#success-and-failure-detection)
    - [automate_failure_check](#automate_failure_check)
    - [standard_success_detector](#standard_success_detector)
    - [standard_failure_detector](#standard_failure_detector)
  - [Orchestrators](#orchestrators)
    - [circular](#circular)
    - [repeater](#repeater)
    - [condition](#condition)
    - [per_instance_condition](#per_instance_condition)
    - [stopif](#stopif)
    - [iff functions](#iff-functions)
      - [cond_true](#cond_true)
      - [cond_false](#cond_false)
      - [cond_random](#cond_random)
      - [cond_payload_str](#cond_payload_str)
      - [cond_tcp_has_ts](#cond_tcp_has_ts)
      - [cond_lua](#cond_lua)
- [Auxiliary programs](#auxiliary-programs)
  - [ip2net](#ip2net)
  - [mdig](#mdig)
- [blockcheck2](#blockcheck2)
  - [DNS check](#dns-check)
  - [Main testing modes](#main-testing-modes)
    - [Multiple attempts](#multiple-attempts)
    - [Scanning levels](#scanning-levels)
    - [Supported protocols](#supported-protocols)
    - [IP block check](#ip-block-check)
      - [Examples of domain-only blocking without IP blocking](#examples-of-domain-only-blocking-without-ip-blocking)
      - [Example of full IP block or TCP port block in the absence of domain blocking](#example-of-full-ip-block-or-tcp-port-block-in-the-absence-of-domain-blocking)
    - [Standard tests](#standard-tests)
      - [standard test](#standard-test)
      - [custom test](#custom-test)
  - [Summary](#summary)
  - [Shell variables](#shell-variables)
  - [Why it won't open](#why-it-wont-open)
- [Startup scripts](#startup-scripts)
  - [config file](#config-file)
  - [List management system](#list-management-system)
    - [Standard list files](#standard-list-files)
    - [ipset scripts](#ipset-scripts)
      - [clear_lists.sh](#clear_listssh)
      - [create_ipset.sh](#create_ipsetsh)
      - [get_config.sh](#get_configsh)
      - [get_user.sh](#get_usersh)
      - [get_ipban.sh](#get_ipbansh)
      - [get_exclude.sh](#get_excludesh)
      - [get_antifilter_*.sh](#get_antifilter_sh)
      - [get_antizapret_domains.sh](#get_antizapret_domainssh)
      - [get_refilter_*.sh](#get_refilter_sh)
      - [get_reestr_*.sh](#get_reestr_sh)
    - [ipban system](#ipban-system)
  - [Init scripts](#init-scripts)
    - [Firewall integration](#firewall-integration)
      - [OpenWRT firewall integration](#openwrt-firewall-integration)
    - [Custom scripts](#custom-scripts)
      - [Custom helpers](#custom-helpers)
        - [Retrieving dynamic numbers](#retrieving-dynamic-numbers)
        - [Working with daemons](#working-with-daemons)
        - [Working with iptables](#working-with-iptables)
        - [Working with nftables](#working-with-nftables)
        - [Additional functions](#additional-functions)
  - [Installer](#installer)
    - [OpenWRT integration principles](#openwrt-integration-principles)
    - [OpenWRT cheat sheet](#openwrt-cheat-sheet)
    - [systemd integration principles](#systemd-integration-principles)
    - [systemd cheat sheet](#systemd-cheat-sheet)
    - [OpenRC integration principles](#openrc-integration-principles)
    - [OpenRC cheat sheet](#openrc-cheat-sheet)
  - [Alternative installation on systemd](#alternative-installation-on-systemd)
- [Other firmwares](#other-firmwares)
- [Windows](#windows)
  - [Windows 7](#windows-7)
  - [Windows Server](#windows-server)
  - [Windows ARM64](#windows-arm64)


# Introduction

zapret2 is a packet manipulator primarily designed to perform various autonomous real-time attacks on Deep Packet Inspection (DPI) systems. Its main objective is to bypass resource blocks or protocol restrictions. However, zapret2's capabilities are not limited to this; its architecture allows for other types of packet manipulation, such as bidirectional (client-server) protocol obfuscation to hide traffic from DPI, among other applications.

# Project structure

The core component of zapret2 is the **nfqws2** program (**dvtws2** on BSD, **winws2** on Windows). Written in C, it serves as the primary packet manipulator. It includes functions for packet interception, basic [filtering](#using-multiple-profiles), recognition of major protocols and payloads, support for host and IP [lists](#filtering-by-lists), [automated](#autohostlist-failure-detector) hostlists with block detection, a system of multiple [profiles](#using-multiple-profiles) (strategies), [raw packet transmission](#receiving-and-sending-packets), and other utility functions. However, it does not contain the logic for traffic modification itself; this is handled by Lua code called from [nfqws2](#nfqws2).

Consequently, the Lua code is the next most critical part of the project. The base package includes the [zapret-lib.lua](#zapret-liblua-base-function-library) helper library, the [zapret-antidpi.lua](#zapret-antidpilua-dpi-attack-program-library) DPI attack library, and the [zapret-auto.lua](#zapret-autolua-automation-and-orchestration-library) orchestration library for dynamic decision-making. Additionally, it features `zapret-tests.lua` for testing C functions, `zapret-obfs.lua` for protocol obfuscation, and `zapret-pcap.lua` for capturing traffic into .cap files.

The project requires LuaJIT-2.1+ or PUC Lua 5.3+. Older versions are not tested and not supported.

Traffic redirection from the kernel is handled by [iptables](#traffic-interception-using-iptables) and [nftables](#traffic-interception-using-nftables) in [Linux](#traffic-interception-in-the-linux-kernel), [ipfw](#traffic-interception-in-the-freebsd-kernel) in [FreeBSD](#traffic-interception-in-the-freebsd-kernel), and [pf](#traffic-interception-in-the-openbsd-kernel) in [OpenBSD](#traffic-interception-in-the-openbsd-kernel). On [Windows](#traffic-interception-in-the-windows-kernel), this functionality is built directly into the winws2 process via the WinDivert driver. The kernel interception scheme, nfqws2, and the Lua code constitute the project's minimal working core. Everything else is supplementary, secondary, or optional.

Secondary components include Linux [startup scripts](#startup-scripts) (`init.d`, `common`, `ipset`, `install_easy.sh`, `uninstall_easy.sh`) and [blockcheck2](#blockcheck2), a tool for automated strategy testing. The purpose of the startup scripts is to coordinate the initialization of tables and nfqws2 instances while accounting for the specifics of various distributions (OpenWrt, systemd, OpenRC). They also provide support for synchronized updates of various [lists](#list-management-system) and [loading](#create_ipsetsh) IP lists into kernel-space (ipset). Users can implement these tasks using their own tools if preferred or if the provided [startup scripts](#startup-scripts) do not meet their needs. These scripts store all settings in a [config](#config-file) file located in the project root; this config is specific to the scripts, and nfqws2 is unaware of it.

Two C-based programs are provided for list processing: [mdig](#mdig), a multi-threaded hostlist resolver capable of handling lists of any size, and [ip2net](#ip2net), a tool for aggregating individual IP addresses into subnets to reduce their footprint. These programs are used by the startup scripts and in [blockcheck2](#blockcheck2).

[Startup scripts](#startup-scripts) and the [installer](#installer) support installation on any classic Linux distribution with systemd or OpenRC, as well as OpenWrt firmware.
If a system does not meet these requirements, manual integration is possible.

macOS is not supported because it lacks a suitable packet interception and management tool. The standard BSD tool `ipdivert` was removed from the kernel by the manufacturer.

# Traffic processing scheme

Networks operate with IP packets, making them the fundamental unit of processing. The OS kernel's network subsystem handles the receiving and sending of packets.
`nfqws2` does not run in kernel mode; it is a user-mode process. Therefore, the first stage of processing involves passing packets from the OS kernel to the `nfqws2` process. All four interception methods provide some degree of packet filtering. Linux offers the most extensive capabilities.
The more unnecessary traffic is filtered out at this stage, the lower the CPU load, as passing packets between the kernel and user space involves significant overhead.

When a packet arrives at `nfqws2`, the first step is to parse it according to the OSI model layers - extracting IP, IPv6, TCP, and UDP headers, as well as the data field. This process is called dissection.
The result of this process is a [dissect](#dissect-structure) - a representation of the packet as structures where individual fields can be addressed.

Next, the `conntrack` subsystem built into `nfqws2` comes into play. This is a flow-tracking system built on top of individual packets.
It searches for an existing flow record based on the packet's L3/L4 data. If no record exists, one is created. Old records with no recent activity are deleted.
`conntrack` tracks the logical direction of packets within a flow (inbound/outbound), counts the number of packets and bytes passed in both directions, and monitors TCP sequence numbers. It is also used, when necessary, to reassemble messages transmitted across multiple packets.

The payload type - the content of an individual packet or a group of packets - is identified via signatures. Based on the payload type, the protocol type for the entire flow is determined and maintained until the flow terminates. Different types of payloads can pass through a single flow.
For example, the XMPP protocol usually carries several types of XMPP-specific messages as well as TLS-related messages.
The flow protocol remains "xmpp," but subsequent packets are assigned various payload types - both known and unknown. Unknown payloads are identified as "unknown."

If a specific payload and flow protocol type require the reconstruction of a message from multiple packets, `nfqws2` begins buffering them in association with the `conntrack` record and prevents their immediate transmission. Once all packets of the message are received, the composite payload is reconstructed and, if necessary, decrypted.
Further decisions are then made based on the fully assembled payload - [reasm](#handling-multi-packet-payloads) or the result of assembly and decryption - [decrypt](#handling-multi-packet-payloads).

Once the necessary information about the payload is obtained, the [profile](#using-multiple-profiles) classification system takes over.
Profiles contain a set of filters and action commands.
Profiles are filtered by L3 (IP protocol version, IP protocol number, ipsets - IP address lists), L4 (TCP, UDP ports, ICMP type/code), and L6/L7 (flow protocol type, hostlists).
Profiles are scanned strictly in order from first to last. Upon the first filter match, that profile is selected, and the scanning stops.
If none of the conditions are met, a default profile with no actions is selected.

All subsequent actions are performed within the scope of the selected profile. The chosen profile is cached in the conntrack entry, so a fresh lookup is not required for every packet.

A re-lookup occurs if the source data changes - specifically, upon the detection of an L7 protocol or a hostname. In these instances, a new search is performed, and the profile is switched if necessary. A stream may undergo up to two such switches throughout its lifetime, as there are only two mutable parameters.

Once a profile is selected, what constitutes its action-oriented logic? Actions are handled by Lua functions, and a profile can contain any number of them. Each call to a Lua function within a profile is referred to as an *instance*. A single function may be called multiple times with different parameters. Thus, the term "instance" describes a specific execution of a function, uniquely identified by the profile number and its sequential position within that profile. Instances are invoked using the `--lua-desync` parameters. Each instance receives an arbitrary set of arguments defined within `--lua-desync`. The execution order is critical to the strategy's logic and follows the exact sequence in which the `--lua-desync` parameters are specified.

[in-profile filters](#in-profile-filters) are also available. There are three types: the `--payload` filter (a list of payloads accepted by the instance) and two range filters, `--in-range` and `--out-range`, which define the specific byte range within the stream that the instance should process. Once defined, in-profile filters apply to all subsequent instances until they are redefined. The primary purpose of these filters is to minimize relatively slow Lua calls by offloading as much decision-making as possible to the C-side code.

When a packet reaches a Lua instance, the function receives two [parameters](#lua-desync-function-prototype): `ctx` and `desync`. `ctx` provides a context for interacting with specific C-side functions. The [`desync`](#structure-of-the-desync-table) parameter is a table containing various attributes of the packet being processed. Most notably, it includes the [dissect](#dissect-structure) (the `dis` subtable) and information from the conntrack entry (the [track subtable](#the-track-table-structure)). Numerous other parameters can be inspected by executing [`var_debug(desync)`](#var_debug) or by using the pre-built [`pktdebug`](#pktdebug) instance.

During the [replay](#handling-multi-packet-payloads) of delayed packets, the Lua instance receives details such as the part number, the total number of parts in the original message, the current part's position, and [reasm](#handling-multi-packet-payloads) or [decrypt](#handling-multi-packet-payloads) data if available.

Lua code can utilize the global variable space to store data that isn't specific to a single packet. It also has access to the [`desync.track.lua_state`](#the-track-table-structure) table, where it can store any information tied to the conntrack entry; this table remains consistent across every packet in the stream. Conversely, the `desync` table can be used to generate and store temporary data relevant only to the current packet's processing chain. Subsequent Lua instances receive the same `desync` table, allowing them to inherit data from previous instances.

A Lua instance can clone the current dissect, modify it, generate its own dissects, and [send](#receiving-and-sending-packets) them via C-side calls. The output of each instance is a verdict: `VERDICT_PASS` (do nothing with the current dissect), `VERDICT_MODIFY` (send the modified dissect content at the end of the processing chain), or `VERDICT_DROP` (drop the current dissect). Verdicts from all instances are aggregated: `MODIFY` overrides `PASS`, and `DROP` overrides both `PASS` and `MODIFY`.

A Lua instance can opt out of receiving further packets for a flow in the in/out direction - this is known as [instance cutoff](#instance_cutoff).
It can also disconnect the in/out direction of the current flow from all Lua processing - [lua cutoff](#lua_cutoff).
An instance can request the [cancellation](#execution_plan_cancel) of the entire subsequent chain of Lua instance calls for the current dissect. The instance making this decision takes on the role of coordinating further actions.
Such an instance is called an **orchestrator**. It receives an [execution plan](#execution_plan) from the C code, which includes all profile filters and call parameters for all remaining instances. It then decides when and under what conditions to invoke them (or not) and whether to modify their parameters. This enables dynamic scenarios without modifying the core strategy code.
Examples include [detecting](#success-and-failure-detection) resource blocking and [switching strategies](#circular) if the previous one failed.

If all instances in the current profile have entered a cutoff state for the current flow, or if the current flow position is beyond the upper bound of the range filters, no further Lua calls will be made for this flow. The C code marks such flows with a special "lua cutoff" flag, which is checked as efficiently as possible without invoking Lua code, thereby saving CPU resources.

After the entire chain of profile instances has been executed, the C code receives a final verdict on what to do with the current dissect: send it as is, send a modified version, or drop it.

Finally, nfqws2 returns to waiting for the next packet, and the cycle repeats.

# Traffic interception from the OS Kernel

## Traffic interception in the Linux kernel

This is achieved using `iptables` or `nftables` via the NFQUEUE mechanism.
`nftables` is preferred because it allows working with traffic after NAT, whereas `iptables` does not. This is critical when processing forwarded traffic. With `iptables`, post-NAT interception is impossible; therefore, certain techniques that break NAT cannot be implemented on forwarded traffic using `iptables`.
`nftables` has one significant drawback: excessive memory requirements when loading large sets. For example, loading 100K IP addresses requires 256–320 MB, which often exceeds the capacity of many routers. `ipset` (used with `iptables`) can handle this even with 64 MB of RAM.

If you have to choose between `iptables` and `nftables`, you should definitely choose `nftables`. Support for `nftables` in the [startup scripts](#startup-scripts) is more robust, and the technology itself is much more "neighbor-friendly" toward rules from other programs because it uses separate tables. In `iptables`, everything is mixed together, and one program's rules might break another's. `iptables` should be considered a legacy option for compatibility when no other choice exists. In a modern Linux distribution, you should definitely avoid `iptables`. However, if you are using an older Linux version (kernel older than 5.15 or `nft` older than 1.0.1) and cannot upgrade, `iptables` is better, as older kernels and `nft` versions will have issues.

The following test examples are intended for custom startup systems or manual execution.
The `zapret` startup scripts generate the necessary rules automatically; you do not need to write iptables/nftables rules yourself.

### Traffic interception using nftables

A test table for a POSTNAT scheme.
It ensures the interception of the first incoming and outgoing packets of a flow after NAT (if present).
Due to NAT, client IP addresses are lost and replaced by the WAN interface IP.
The number of initial packets intercepted is adjusted according to your strategy. Excessive interception creates additional CPU load.
Intercepting RST and FIN packets is recommended for optimal `conntrack` performance.

Filtering by `mark` is necessary to prevent loops. Without this, the system may hang or malfunction.

`notrack` is required to prevent NAT from interfering with techniques that are incompatible with it.
Packets generated by `nfqws2` should not undergo NAT validity checks, as this could cause them to be dropped by standard table rules.
NAT IP substitution is unnecessary because packets reaching `nfqws2` have already passed through NAT and possess the correct source address and port for the WAN.

```
IFACE_WAN=wan
MAX_PKT_IN=15
MAX_PKT_OUT=15
FWMARK=0x40000000
PORTS_TCP=80,443
PORTS_UDP=443
QNUM=200

nft create table inet ztest

nft add chain inet ztest postnat "{type filter hook postrouting priority srcnat+1;}"
nft add rule inet ztest postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 udp dport "{$PORTS_UDP}" ct original packets 1-$MAX_PKT_OUT queue num $QNUM bypass
nft add rule inet ztest postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 tcp dport "{$PORTS_TCP}" ct original packets 1-$MAX_PKT_OUT queue num $QNUM bypass
nft add rule inet ztest postnat oifname $IFACE_WAN meta mark and $FWMARK == 0 tcp dport "{$PORTS_TCP}" tcp flags fin,rst queue num $QNUM bypass

nft add chain inet ztest pre "{type filter hook prerouting priority filter;}"
nft add rule inet ztest pre iifname $IFACE_WAN udp sport "{$PORTS_UDP}" ct reply packets 1-$MAX_PKT_IN queue num $QNUM bypass
nft add rule inet ztest pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" ct reply packets 1-$MAX_PKT_IN queue num $QNUM bypass
nft add rule inet ztest pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" "tcp flags & (syn | ack) == (syn | ack)" queue num $QNUM bypass
nft add rule inet ztest pre iifname $IFACE_WAN tcp sport "{$PORTS_TCP}" tcp flags fin,rst queue num $QNUM bypass

nft add chain inet ztest predefrag "{type filter hook output priority -401;}"
nft add rule inet ztest predefrag "mark & $FWMARK != 0x00000000 notrack"
```

Deleting the test table:

```
nft delete table inet ztest
```

### Traffic interception using iptables

> [!CAUTION]
> Starting with Linux kernel 6.17, there is a kernel configuration parameter `CONFIG_NETFILTER_XTABLES_LEGACY`, which may be "not set" by default in some distributions. Disabling this setting turns off `iptables-legacy`. This is part of the ongoing iptables deprecation process. However, `iptables-nft` will continue to function as it utilizes the `nftables` backend.

Test rules for the PRENAT scheme.
These ensure the interception of the initial incoming and outgoing packets of a stream before NAT is applied, if NAT is present.
Internal network source addresses and ports are preserved. Attacks on passing traffic that break NAT are impossible, though they remain possible from the system itself.

```
IFACE_WAN=wan
MAX_PKT_IN=15
MAX_PKT_OUT=15
FWMARK=0x40000000
PORTS_TCP=80,443
PORTS_UDP=443
QNUM=200

JNFQ="-j NFQUEUE --queue-num $QNUM --queue-bypass"
CHECKMARK="-m mark ! --mark $FWMARK/$FWMARK"
CB_ORIG="-m connbytes --connbytes-dir=original --connbytes-mode=packets"
CB_REPLY="-m connbytes --connbytes-dir=reply --connbytes-mode=packets"
for tables in iptables ip6tables; do
	$tables -t mangle -N ztest_post 2>/dev/null
	$tables -t mangle -F ztest_post
	$tables -t mangle -C POSTROUTING -j ztest_post 2>/dev/null || $tables -t mangle -A POSTROUTING -j ztest_post
	$tables -t mangle -N ztest_pre 2>/dev/null
	$tables -t mangle -F ztest_pre
	$tables -t mangle -C PREROUTING -j ztest_pre 2>/dev/null || $tables -t mangle -A PREROUTING -j ztest_pre
	$tables -t mangle -I ztest_post -o $IFACE_WAN $CHECKMARK -p udp -m multiport --dports $PORTS_UDP $CB_ORIG --connbytes 1:$MAX_PKT_OUT $JNFQ
	$tables -t mangle -I ztest_post -o $IFACE_WAN $CHECKMARK -p tcp -m multiport --dports $PORTS_TCP $CB_ORIG --connbytes 1:$MAX_PKT_OUT $JNFQ
	$tables -t mangle -I ztest_post -o $IFACE_WAN $CHECKMARK -p tcp -m multiport --dports $PORTS_TCP --tcp-flags fin fin $JNFQ
	$tables -t mangle -I ztest_post -o $IFACE_WAN $CHECKMARK -p tcp -m multiport --dports $PORTS_TCP --tcp-flags rst rst $JNFQ
	$tables -t mangle -I ztest_pre -i $IFACE_WAN -p udp -m multiport --sports $PORTS_UDP $CB_REPLY --connbytes 1:$MAX_PKT_IN $JNFQ
	$tables -t mangle -I ztest_pre -i $IFACE_WAN -p tcp -m multiport --sports $PORTS_TCP $CB_REPLY --connbytes 1:$MAX_PKT_IN $JNFQ
	$tables -t mangle -I ztest_pre -i $IFACE_WAN -p tcp -m multiport --sports $PORTS_TCP --tcp-flags syn,ack syn,ack $JNFQ
	$tables -t mangle -I ztest_pre -i $IFACE_WAN -p tcp -m multiport --sports $PORTS_TCP --tcp-flags fin fin $JNFQ
	$tables -t mangle -I ztest_pre -i $IFACE_WAN -p tcp -m multiport --sports $PORTS_TCP --tcp-flags rst rst $JNFQ
done
```

Removing zapret test rules:

```
for tables in iptables ip6tables; do
	$tables -t mangle -D POSTROUTING -j ztest_post
	$tables -t mangle -D PREROUTING -j ztest_pre
	$tables -t mangle -F ztest_post
	$tables -t mangle -X ztest_post
	$tables -t mangle -F ztest_pre
	$tables -t mangle -X ztest_pre
done
```

Flushing all rules from the mangle table, including any other existing rules:

```
iptables -F -t mangle
ip6tables -F -t mangle
```

## Traffic interception in the FreeBSD kernel

The primary challenge when intercepting traffic on non-Linux systems is the inability to intercept only the initial packets of a stream. You can only intercept the entire stream in a specific direction.
FreeBSD is particularly limited in this regard, as it lacks raw payload filtering capabilities (filtering based on packet content).
Consequently, the first set of rules intercepts all outgoing traffic on specific ports, but only SYN+ACK, FIN, and RST packets for incoming TCP traffic. This allows the use of `autottl` mode and ensures `conntrack` functions correctly without excessive CPU load.
However, this configuration will break any functionality that requires other types of incoming traffic.

```
RULE=100
IFACE_WAN=vmx0
PORTS_TCP=80,443
PORTS_UDP=443
PORT_DIVERT=989

ipfw delete $RULE
ipfw add $RULE divert $PORT_DIVERT tcp from any to any $PORTS_TCP out not diverted xmit $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT udp from any to any $PORTS_UDP out not diverted xmit $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT tcp from any $PORTS_TCP to any tcpflags syn,ack in not diverted recv $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT tcp from any $PORTS_TCP to any tcpflags fin in not diverted recv $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT tcp from any $PORTS_TCP to any tcpflags rst in not diverted recv $IFACE_WAN
```

Alternative: Bidirectional stream interception. This puts a significant load on the CPU.
Every gigabyte downloaded will pass through `dvtws2`. Usually, only 1 or 2 packets are actually needed; everything else is a waste of CPU cycles, but `ipfw` offers no other alternatives.

```
RULE=100
IFACE_WAN=vmx0
PORTS_TCP=80,443
PORTS_UDP=443
PORT_DIVERT=989

ipfw delete $RULE
ipfw add $RULE divert $PORT_DIVERT tcp from any to any $PORTS_TCP out not diverted xmit $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT udp from any to any $PORTS_UDP out not diverted xmit $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT tcp from any $PORTS_TCP to any in not diverted recv $IFACE_WAN
ipfw add $RULE divert $PORT_DIVERT udp from any $PORTS_UDP to any in not diverted recv $IFACE_WAN
```

While traffic interception via `pf divert-to` is theoretically possible, the loop prevention mechanism is broken in practice, making `pf` unusable for this purpose.
On pfSense and OPNsense, additional steps are required to enable both `pf` and `ipfw` simultaneously. This frequently leads to issues, conflicts, and glitches.

## Traffic interception in the OpenBSD kernel

OpenBSD relies solely on `pf`. Its `divert` loop prevention mechanism works correctly.

The first approach involves intercepting all outbound traffic by port, while intercepting only SYN+ACK, FIN, and RST for inbound TCP. This allows for the use of `autottl` mode and ensures `conntrack` functions correctly without putting heavy load on the CPU. However, this method will break anything that requires other types of incoming traffic.

`pf` requires configuration files. You write a `pf` file (typically `/etc/pf.conf`) and then apply it using `pfctl -f /etc/pf.conf`. Use `pfctl -e` to enable `pf` and `pfctl -d` to disable it.
You can also use anchors with separate rule files; refer to the `pf` documentation for details.

The `no state` tricks are necessary to prevent the automatic interception of incoming packets within an established flow.

```
IFACE_WAN = "em0"
PORTS_TCP = "80,443"
PORTS_UDP = "443"
PORT_DIVERT = "989"

pass in quick on $IFACE_WAN proto tcp from port { $PORTS_TCP } flags SA/SA divert-packet port $PORT_DIVERT no state
pass in quick on $IFACE_WAN proto tcp from port { $PORTS_TCP } flags R/R divert-packet port $PORT_DIVERT no state
pass in quick on $IFACE_WAN proto tcp from port { $PORTS_TCP } flags F/F divert-packet port $PORT_DIVERT no state
pass in quick on $IFACE_WAN proto tcp from port { $PORTS_TCP } no state
pass out quick on $IFACE_WAN proto tcp to port { $PORTS_TCP } divert-packet port $PORT_DIVERT no state
pass out quick on $IFACE_WAN proto udp to port { $PORTS_UDP } divert-packet port $PORT_DIVERT no state
```

The second approach involves intercepting the flow in both directions. This is particularly CPU-intensive.
Every gigabyte downloaded will pass through `dvtws2`. Usually, only 1 or 2 packets are actually needed, while the rest simply wastes CPU cycles; however, `pf` does not provide any other way to handle this.

Inbound interception for the same ports is handled automatically via state tracking.

```
IFACE_WAN = "em0"
PORTS_TCP = "80,443"
PORTS_UDP = "443"
PORT_DIVERT = "989"

pass out quick on $IFACE_WAN proto tcp to port { $PORTS_TCP } divert-packet port $PORT_DIVERT
pass out quick on $IFACE_WAN proto udp to port { $PORTS_UDP } divert-packet port $PORT_DIVERT
```

> [!CAUTION]
> FreeBSD uses a different version of `pf` with slightly different syntax. Furthermore, `pf` in FreeBSD is effectively broken for this use case because loop prevention does not work. While macOS also uses `pf`, `ipdivert` has been removed from its kernel, so these rules will not function.

## Traffic interception in the Windows kernel

Windows lacks native tools for traffic interception. Instead, a third-party solution is used: the `WinDivert` driver.
Control is integrated directly into the `winws2` process.

`WinDivert` accepts [text-based filters](https://reqrypt.org/windivert-doc.html#filter_language) similar to those used by Wireshark and tcpdump.
These filters support filtering by IP (without ipset), ports, and raw payloads. However, they do not support bitwise logical operations, bit shifts, flow tracking, or limiting interception to the first few packets of a connection.

The WinDivert driver is no longer under active development. However, signed versions of the driver are available that are compatible with all modern Windows releases, though only for the x86_64 architecture. For ARM64, there is an unsigned driver that requires enabling Test Signing mode.

When using `winws2` on Windows 11 ARM64, you must use the x86_64 version because `winws2` is built for Cygwin, which does not support ARM. In this configuration, the `.sys` driver must be replaced with the unsigned ARM64 version. Running on Windows 10 ARM64 is theoretically possible, but only with the 32-bit `winws2` x86 version, as Windows 10 does not support x64 emulation.

WinDivert is a frequent target for antivirus software. While it is a "hacker tool," it is not a virus. It is best understood as a Windows equivalent to `iptables`. Conflicts with third-party kernel-mode software - primarily antiviruses and firewalls - can occur, occasionally resulting in Blue Screens of Death (BSOD). Fixing these issues is practically impossible, largely due to driver signing requirements; obtaining a signature is prohibitively difficult and expensive for individuals without corporate backing.

WinDivert cannot reliably intercept forwarded traffic when using Windows' built-in network sharing or NAT. Consequently, features for handling forwarded traffic are not implemented. The only available workaround is to set up a proxy server.

`winws2` can accept full raw filters-you can write the filter yourself and specify it using the `--wf-raw=<filter>` or `--wf-raw=@<filter_file>` parameters. Since this is often cumbersome, a built-in filter constructor is provided.

`--wf-tcp-out`, `--wf-tcp-in`, `--wf-udp-out`, and `--wf-udp-in` take a list of ports (`80,443`) or port ranges (`80,443,500-1000`) and enable full port interception for the specified direction.

`--wf-icmp-out`, `--wf-icmp-in` take a list of icmp types or icmp types+codes.

`--wf-ipp-in`, `--wf-ipp-out` take a list of raw ip protocol numbers (extracting end protocol from ipv6 extension headers is not supported).

`--wf-raw-part` accepts partial WinDivert filters. The syntax is identical to `--wf-raw`. Multiple `--wf-raw-part` instances can be used. These partial filters are integrated by the constructor into the final filter using OR logic: [specified ports] OR [filter1] OR [filter2].

`--wf-raw-filter` - partial WinDivert filter combined with resulting full WinDivert filter by AND. Only one is allowed.
Typical use - filtering by small list of IP addresses. For example, if your task is icmp tunnel to the server, intercepting all icmp type is a waste of CPU.
Much better to add `--wf-raw-filter="ip.SrcAddr==1.2.3.4"` to `--wf-icmp-in=0`.

`--wf-save=<filter_file>` writes the filter created by the constructor to a file for subsequent analysis and modification.

The filter constructor automatically intercepts incoming TCP packets with SYN+ACK, FIN, and RST flags. There is no need to write specific rules for these.

`--wf-filter-lan` (enabled by default) filters out packets destined for non-global IP addresses, such as `192.168.0.0/16`.

`--wf-tcp-empty` (disabled by default) enables the interception of empty TCP packets that do not carry SYN, FIN, or RST flags. If this parameter is disabled, empty ACK packets are not intercepted, which significantly reduces CPU overhead. However, certain strategies may require these packets. Only you can determine if they are necessary for your use case.

If any TCP port interception is active, HTTP redirect interception is automatically enabled to allow `autohostlist` to function. HTTP redirect interception works via payload signatures, meaning it inspects bytes at specific positions within the packet content.

For UDP protocols-especially those where the port is not fixed-it is preferable to use custom `--wf-raw-part` filters to save on CPU cycles. Filters can also be used for TCP, but you must account for the requirements of `conntrack`. It requires at least the SYN packet, and ideally FIN and RST as well. If you need to filter based on messages that span more than one TCP segment, this cannot be achieved using WinDivert filters alone; full port interception for that direction is required.

# nfqws2

## General principles for setting parameters

All `nfqws2` parameters are passed via the command line or loaded from a file using the same format.
`nfqws2` utilizes the standard `getopt_long_only` parser.
Options follow the `--name[=value]` format. Some options do not require parameters, others do, and some take them optionally.
The `getopt` parser allows specifying values using either an `=` sign or a space. However, extraneous values passed via spaces may be ignored, meaning seemingly erroneous parameters might not trigger an error. It is best practice to always use the `=` sign for values.

Reading parameters from a file is implemented via the single `@config_file` option.
If this is used, all other command-line parameters will be ignored.
Options will be read from the file as if its contents were entered directly into the command line.
This feature is not supported in the Android and OpenBSD versions.

## Full list of options

General parameters for all versions - nfqws2, dvtws2, winws2.

```
 @<config_file>                                         ; read command-line options from a file. all other command-line options are ignored.

 --debug=0|1|syslog|android|@<filename>                 ; write debug log. 0 - none, 1 - console, syslog - unix syslog, android - android system log, @<filename> - to file
 --version                                              ; display version and exit
 --dry-run                                              ; validate command-line parameters and file existence. does not check Lua script correctness!
 --comment=any_text                                     ; any text. ignored
 --intercept=0|1                                        ; allow interception. 0 - no, 1 - yes. If 0 lua-init scripts are executed then process exits. NFQUEUE is not initialized.
 --daemon                                               ; detach from the console (daemonize)
 --chdir[=path]                                         ; change current directory. if no path specified use the executable file directory - EXEDIR
 --pidfile=<filename>                                   ; write PID to a file
 --ctrack-timeouts=S:E:F[:U]                            ; conntrack timeouts for tcp stages (SYN, ESTABLISHED, FIN) and for udp
 --ctrack-disable=[0|1]                                 ; 1 disables conntrack
 --payload-disable=[type[,type]]                        ; do not discover these payload types. for available payload types see '--payload'. disable all if no argument.
 --server=[0|1]                                         ; server mode. modifies various aspects of direction selection and source/destination ip/port for handling listeners
 --ipcache-lifetime=<int>                               ; IP cache entry lifetime in seconds. 0 - unlimited.
 --ipcache-hostname=[0|1]                               ; 1 or no argument enables hostname caching for use in zero-phase strategies
 --reasm-disable=[type[,type]]                          ; disable fragment reassembly for a list of payloads: tls_client_hello quic_initial. without arguments - disable reasm for everything.

DESYNC ENGINE INIT:
 --writeable[=<dir_name>]                               ; create a directory for Lua with write permissions and store its path in the "WRITEABLE" env variable (only one directory)
 --blob=<item_name>:[+ofs]@<filename>|0xHEX             ; load a binary file or hex string into the Lua variable <item_name>. +ofs specifies the offset from the start of the file
 --lua-init=@<filename>|<lua_text>                      ; execute Lua code from a string or file once at startup. supports gzipped files. automatically checks for "<filename>.gz"
 --lua-gc=<int>                                         ; Lua garbage collector invocation interval in seconds. 0 disables periodic calls.

MULTI-STRATEGY:
 --new[=name]                                           ; start a new profile. optionally assign a name
 --skip                                                 ; ignore the profile
 --name=<name>                                          ; set the profile name
 --template[=<name>]                                    ; use the profile as a template and optionally assign a name
 --cookie[=<string>]                                    ; set the value of the "desync.cookie" Lua variable passed to each instance of this profile
 --import=<name>                                        ; copy settings from a template into the current profile, overwriting all existing settings
 --filter-l3=ipv4|ipv6                                  ; profile filter: IP protocol version
 --filter-tcp=[~]port1[-port2]|*                        ; profile filter: TCP ports or port ranges (comma-separated)
 --filter-udp=[~]port1[-port2]|*                        ; profile filter: UDP ports or port ranges (comma-separated)
 --filter-icmp=type[:code]|*                            ; profile filter: ICMP type and codes (comma-separated)
 --filter-ipp=proto|*                                   ; profile filter: raw IP protocol numbers (comma-separated)
 --filter-l7=proto[,proto]                              ; profile filter: list of application-layer protocols
 --ipset=<filename>                                     ; profile filter: inclusion list of IP addresses or subnets from a file (supports mixed IPv4/IPv6)
 --ipset-ip=<ip_list>                                   ; profile filter: fixed inclusion list of IP addresses or subnets (comma-separated)
 --ipset-exclude=<filename>                             ; profile filter: exclusion list of IP addresses or subnets from a file (supports mixed IPv4/IPv6)
 --ipset-exclude-ip=<ip_list>                           ; profile filter: fixed exclusion list of IP addresses or subnets (comma-separated)
 --hostlist=<filename>                                  ; profile filter: inclusion list of domains from a file
 --hostlist-domains=<domain_list>                       ; profile filter: fixed inclusion list of domains (comma-separated)
 --hostlist-exclude=<filename>                          ; profile filter: exclusion list of domains from a file
 --hostlist-exclude-domains=<domain_list>               ; profile filter: fixed exclusion list of domains (comma-separated)
 --hostlist-auto=<filename>                             ; profile filter: auto-populating domain inclusion filter based on feedback
 --hostlist-auto-fail-threshold=<int>                   ; auto-list parameter: number of consecutive failures before adding to the list. Default: 3
 --hostlist-auto-fail-time=<int>                        ; auto-list parameter: maximum time between failures without resetting the counter. Default: 60 seconds
 --hostlist-auto-retrans-threshold=<int>                ; auto-list parameter: number of TCP retransmissions in a single session to trigger a failure. Default: 3
 --hostlist-auto-retrans-reset=[0|1]                    ; auto-list parameter: send an RST to the retransmitter to terminate long waits. Default: 1
 --hostlist-auto-retrans-maxseq=<int>                   ; auto-list parameter: outgoing relative sequence number after which failure detection stops. Default: 32768
 --hostlist-auto-incoming-maxseq=<int>                  ; auto-list parameter: incoming relative sequence number after which failure detection stops and the counter resets. Default: 4096
 --hostlist-auto-udp-out=<int>                          ; auto-list parameter: UDP failure condition: number of outgoing packets is greater than or equal to this value. Default: 4
 --hostlist-auto-udp-in=<int>                           ; auto-list parameter: UDP failure condition: number of incoming packets is less than or equal to this value. Default: 1
 --hostlist-auto-debug=<logfile>                        ; auto-list debug log

LUA PACKET PASS MODE:
 --payload=type[,type]                                  ; in-profile filter: payload filter for subsequent instances within the profile
 --out-range=[(n|a|d|s|p)<int>](-|<)[(n|a|d|s|p)<int>]  ; in-profile filter: conntrack counter range for subsequent instances within the profile - outgoing direction
 --in-range=[(n|a|d|s|p)<int>](-|<)[(n|a|d|s|p)<int>]   ; in-profile filter: conntrack counter range for subsequent instances within the profile - incoming direction

LUA DESYNC ACTION:
 --lua-desync=<function>[:param1=val1[:param2=val2]]    ; call a LUA instance with the specified parameters during profile processing if in-profile filter conditions are met
```

Specific parameters for nfqws2:

```
 --qnum=<nfqueue_number>                ; NFQUEUE number in Linux
 --user=<username>                      ; change uid/gid to those associated with the specified username
 --uid=uid[:gid1,gid2,...]              ; change uid/gid to the specified numeric values
 --bind-fix4                            ; fix for the issue where generated packets on Linux exit from the wrong interface when using PBR (IPv4)
 --bind-fix6                            ; same as above for IPv6
 --fwmark=<int|0xHEX>                   ; mark bit to prevent looping. default = 0x40000000
 --filter-ssid=ssid1[,ssid2,ssid3,...]  ; profile filter: WiFi network name (SSID)
```

Specific parameters for dvtws2:

```
 --port=<port>                          ; divert port number
 --user=<username>                      ; change uid/gid to those associated with the specified username
 --uid=uid[:gid1,gid2,...]              ; change uid/gid to the specified numeric values
```

Specific parameters for winws2:

```
 --wf-iface=<int>[.<int>]               ; WinDivert constructor: network interface number
 --wf-l3=ipv4|ipv6                      ; WinDivert constructor: IP version
 --wf-tcp-in=[~]port1[-port2]           ; WinDivert constructor: TCP ports or port ranges for interception in the incoming direction. Comma-separated list.
 --wf-tcp-out=[~]port1[-port2]          ; WinDivert constructor: TCP ports or port ranges for interception in the outgoing direction. Comma-separated list.
 --wf-udp-in=[~]port1[-port2]           ; WinDivert constructor: UDP ports or port ranges for interception in the incoming direction. Comma-separated list.
 --wf-udp-out=[~]port1[-port2]          ; WinDivert constructor: UDP ports or port ranges for interception in the outgoing direction. Comma-separated list.
 --wf-icmp-in=type[:code]               ; WinDivert constructor: ICMP types and codes for interception in the incoming direction. Comma-separated list.
 --wf-icmp-out=[~]port1[-port2]         ; WinDivert constructor: ICMP types and codes for interception in the outgoing direction. Comma-separated list.
 --wf-ipp-in=type[:code]                ; WinDivert constructor: raw IP protocols for interception in the incoming direction. Comma-separated list.
 --wf-ipp-out=type[:code]               ; WinDivert constructor: raw IP protocols for interception in the outgoing direction. Comma-separated list.
 --wf-tcp-empty=[~]port1[-port2]        ; WinDivert constructor: intercept empty TCP ACK packets. Default is no.
 --wf-raw-part=<filter>|@<filename>     ; WinDivert constructor: partial WinDivert raw filter. Combined using OR principle. Multiple allowed.
 --wf-raw-filter=<filter>|@<filename>   ; WinDivert constructor: partial WinDivert raw filter. Combined using AND principle. Only one is allowed.
 --wf-filter-lan=0|1                    ; WinDivert constructor: filter out non-global IP addresses. Default is yes.
 --wf-raw=<filter>|@<filename>          ; full WinDivert filter. Overrides the constructor.
 --wf-dup-check[=0|1]                   ; 1 (default) = do not allow duplicate winws2 instances with the same wf filter
 --wf-save=<filename>                   ; save the final complete WinDivert filter to a file
LOGICAL NETWORK FILTER:
 --ssid-filter=ssid1[,ssid2,ssid3,...]  ; list of WiFi networks; interception is enabled only when connected to these, otherwise it is disabled.
 --nlm-filter=net1[,net2,net3,...]      ; list of Network List Manager networks; interception is enabled only when connected to these, otherwise it is disabled.
 --nlm-list[=all]                       ; display a list of connected NLM networks. "all" shows all NLM networks.
```

## Protocol detection

nfqws2 signatures the payload types of individual packets or packet groups.
All packets without data have payload type "empty", undetermined payloads - type "unknown".
The flow protocol is assigned after receiving the first known payload and remains with the flow for the rest of its existence.
In this case, subsequent payloads can have both a known type and an unknown one.
In payload and flow protocol filters special values are available - "all" and "known". "all" means any, "known" - not "empty" and not "unknown".

Table of recognizable payload types and flow protocols

| flow protocol   | L4  | payloads |
| :-------------- | :-- | :------- |
| http            | tcp | http_req<br>http_reply |
| tls             | tcp | tls_client_hello<br>tls_server_hello |
| xmpp            | tcp | xmpp_stream<br>xmpp_starttls<br>xmpp_proceed<br>xmpp_features |
| mtproto         | tcp | mtproto_initial |
| bt              | tcp | bt_handshake |
| quic            | udp | quic_initial |
| wireguard       | udp | wireguard_initiation<br>wireguard_response<br>wireguard_cookie<br>wireguard_keepalive |
| dht             | udp | dht |
| utp_bt          | udp | utp_bt_handshake |
| discord         | udp | discord_ip_discovery |
| stun            | udp | stun |
| dns             | udp | dns_query dns_response |
| dtls            | udp | dtls_client_hello<br>dtls_server_hello |
| <any>           | icmp | ipv4<br>ipv6<br>icmp|

Special payload types are "ipv4", "ipv6", "icmp".  "ipv4" and "ipv6" are generated for icmp with attached IP packet.
Other icmp have "icmp" payload type.

## Using multiple profiles

Profiles exist to select a specific traffic manipulation strategy based on the specified filter conditions.
The general scheme for using profiles is as follows:

```
nfqws2 <global_parameters>
<filter 1> <strategy 1> --new
<filter 2> <strategy 2> --new
...............
<filter N> <strategy N>
```

When a packet arrives and there is no existing conntrack entry for it, a profile is selected.
Profile filters are checked sequentially - from start to finish, left to right - and in no other way.
Only one profile ever wins: the first one to match the filter conditions. All others are ignored.
If no filter matches, an empty profile (ID 0) is selected, which performs no actions on the traffic.

All conditions, except for `--filter-l7` and hostlists, are definitive and known from the moment flow processing begins (at the start of the connection).
Initially, the flow protocol and the hostname (extracted from the flow's messages) are usually unknown.
Once these values are identified, the profile search is performed again. If a different profile is selected, a "jump" occurs.
Up to two such jumps can occur, as there are only two variables affecting selection that are unknown at the start.
For TLS, HTTP, and QUIC protocols, there is typically only one jump because the protocol and hostname are determined within a single packet or group of packets. For XMPP, there are two jumps: first, XMPP itself is identified; then, the transition to TLS is detected, and only then is the hostname extracted.
When writing strategies, they should be designed with this jump logic in mind.
If a strategy needs to start from the very first packet and continue working after a profile change, you must duplicate the calls across all profiles the flow might pass through.

Four filter groups - tcp, udp, icmp, ipp are OR combined. If there're no filters in these groups - everything is allowed.
If any filters are defined - all undefined groups are blocked.

ipp filter does not work with tcp, udp and icmp. They are checked by their specific filters. For example, `--filter-ipp=6` does not work. What is meant could be achieved with `--filter-tcp=*`.

icmp filter matches both icmp and icmpv6 - they are processed the same they.
However, icmp types differ between [icmp](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) and [icmpv6](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml).

### Profile templates

When there are many complex and repetitive strategies or groups of the same parameters, it may be convenient to use templates.
A template is also a profile but it doesn't go to the working profile list but to a separate list of templates.
The profile becomes a template by setting the `--template = <name>` parameter.
It can then be imported (`--import = <name>`) into another profile or template.
Simple parameters - number, string, bool - are imported only if they were specified in the imported template. When you import a template into a template in the destination template, they are also considered specified.
List parameters are added to the end of the corresponding list. Such parameters are anything that can take a list of values. For example, hostlists or `--filter-tcp`.
The template number and name are not copied.

The `--import` directives can be anywhere. Previous simple specified parameters are overwritten by new imported or specified in the current profile parameters.

A special prohibition is the replacement of autohostlist. The template may have an autohostlist, but importing somewhere that already has an autohostlist will fail.


```
nfqws2 <global_parameters>
--template=tpl1 <base_parameters_1> --new
--template=tpl2 <base_parameters_2> --new
--template --import tpl2 --name tpl3 <base_parameters_3> --new
--import tpl1 --name prof1 <additional_parameters_1> --new
--import tpl3 --name prof2 <additional_parameters_2> --new
--name prof3 <parameters_3>
```

In this example, there are 3 active profiles and 3 templates, one of which imports settings from another.

- Profile **prof1** receives a combination of `<base_parameters_1>` and `<additional_parameters_1>`.
- Profile **prof2** receives a combination of `<base_parameters_2>`, `<base_parameters_3>`, and `<additional_parameters_2>`.
- Profile **prof3** receives `<parameters_3>`. It does not import any templates.

Any parameters applicable to profiles, including filters, are allowed within templates. Global parameters are not a part of templates or profiles.

### Filtering by ipsets

- For TCP and UDP the server address is matched in client mode and the client address in [server mode](#server-mode).
- Related ICMP use the cached profile from the original packet.
- Unrelated ICMP and и raw IP are matched by either source or destination ip. To match an ipset either IP must match.

### Filtering by lists

If hostlist filters are used - meaning there is at least one domain in any hostlist or an autohostlist is specified - the profile will never be selected if the hostname is missing.
The case where there is no autohostlist and all list files are empty is treated as if no hostlist filter exists.

If there is no autohostlist but there are entries in standard hostlists, the profile is selected only if the current host matches any of the include lists and does not match any of the exclude lists.

If an autohostlist is present, the profile is always selected as long as a hostname is available, regardless of whether it appears in any of that profile's lists. The specific actions then depend on whether the host is found in the lists.

- If a host is in the exclusion lists, no action is taken, and no attempt is made to determine if the resource is reachable.
- If a host is not in the exclusion lists but is in the inclusion lists, the strategy is applied without attempting to verify resource reachability.
- If a host is in neither the exclusion nor the inclusion lists, no strategy is applied, and access failure detection begins. If a failure occurs, the failure counter increments. If a success occurs or the time interval between failures exceeds `--hostlist-auto-fail-time`, the counter resets.
When the counter reaches `--hostlist-auto-fail-threshold`, the host is added to the auto-list.
On the next request, the host will be treated as if it were in the inclusion list.
- Hostlist and ipset files are reloaded automatically when modified - restarting `nfqws2` is not required.
- The SIGHUP signal marks all lists for a forced reload during the processing of the next packet.
- Each entry for a domain, IP address, or subnet must be on a new line.
- Hostlists and ipsets support comments. Empty lines and lines starting with `#` are ignored.
- In hostlists, subdomains are handled automatically. Wildcards (`*`) are not supported. If a domain begins with the `^` symbol, automatic subdomain matching is disabled for that specific entry.
- ipsets can include both IPv4 and IPv6 addresses and subnets.
- In the static versions of `--ipset-ip` and `--hostlist-domains`, domains are separated by commas. The `#` and `^` symbols are also supported in static hostlists.
- Gzip compression is supported for all list files.

### Autohostlist failure detector

The detector only triggers when a hostname is present. A failure is defined as:

- **tcp**: At least `--hostlist-auto-retrans-threshold` retransmissions occur within the outgoing relative sequence `--hostlist-auto-retrans-maxseq`. If `--hostlist-auto-retrans-reset=1`, an RST is sent to the retransmitter to stop its attempts (which could otherwise last a very long time).
- **tcp**: An RST is received within an incoming relative sequence of 1 to `--hostlist-auto-incoming-maxseq`.
- **tcp**: An `http_reply` payload is received, and the HTTP response is a 302 or 307 redirect to an absolute URL with a second-level domain that does not match the host's second-level domain.
- **udp**: At least `--hostlist-auto-udp-out` packets are sent, but no more than `--hostlist-auto-udp-in` packets are received. This situation indicates that the client is sending requests, but the server is either not responding or responding less than the protocol requires.

A success is defined as:

- **tcp**: The outgoing relative sequence exceeds `--hostlist-auto-retrans-maxseq`. The client managed to send enough data that DPI interference is unlikely.
- **tcp**: The incoming relative sequence exceeds `--hostlist-auto-incoming-maxseq`. The server sent enough data that it does not resemble a DPI-generated response.
- **udp**: The number of received packets exceeds `--hostlist-auto-udp-in`. The server has responded sufficiently.

In the event of a failure, if no more than `--hostlist-auto-fail-time` seconds have passed since the previous failure, the failure counter increments.
If more time has passed, the counter resets and starts over.

In the event of a success, the counter is reset. The resource is considered functional, and the previous failure is treated as temporary and unrelated to blocking.

When the counter reaches `--hostlist-auto-fail-threshold`, the host is added to the list.

Most success and failure criteria require analyzing both incoming and outgoing traffic; therefore, sufficient traffic interception is necessary for these criteria to trigger.

### Network presence filter

If, for example, you need to apply one strategy for Wi-Fi and another for Ethernet, this is done via a filter based on the interface name.
But what if you connect to different Wi-Fi networks or plug your Ethernet cable into different locations?
For Ethernet, a solution exists only on Windows; there is none for other systems. For Wi-Fi, solutions are available for Linux and Windows, but not for BSD.

The Wi-Fi filter accepts a comma-separated list of SSIDs; however, its implementation differs between Linux and Windows.

In Linux, the `--filter-ssid` profile filter is used. When specified, `nfqws2` attempts to resolve the SSID on the interface where the packet is being sent or received. If successful, it checks the SSID against the list; if not, the filter condition is not met, and the profile is not selected. This approach allows the software to function correctly even if you are connected to multiple Wi-Fi networks via different adapters.

The approach in Windows is different. It monitors the presence of the specified Wi-Fi networks across all Wi-Fi adapters. If any of them match an SSID in the list, WinDivert interception is enabled; otherwise, it is disabled. To handle different Wi-Fi networks with different strategies, you must run multiple instances of `winws2`. One instance will activate while others deactivate. The SSID list is specified using the `--ssid-filter` parameter.

Another way to address this-and not just for Wi-Fi-is by using the Network List Manager (NLM) filter.
`--nlm-list[=all]` returns a list of GUIDs for connected networks (or all networks if the "all" value is specified). You then enter the comma-separated list of GUIDs into `--nlm-filter`.

An NLM network is the result of the system detecting a connection to a specific network. You might connect to a router via Wi-Fi or Ethernet, but it will be recognized as the same network. To distinguish between networks, the system typically looks at the gateway's MAC address. NLM technology is interesting and useful, but unfortunately, adequate management tools were only available in Windows 7. In newer systems, you have to dig into PowerShell or the Registry to manually assign connections to the correct GUIDs if the system categorizes them incorrectly. Alternatively, you can simply use the list of GUIDs automatically assigned by the system.

## Server mode

Certain types of manipulations can be performed not only from the client side but also from the server side. `nfqws2` was designed to fully support both inbound and outbound traffic, on both the client and server sides.

The concept of "direction" in a network is largely relative. For the endpoints of a packet, everything is clear: something is sent, something is received. But for a router, it is not clear at all. There is only an incoming interface and an outgoing interface. Essentially, the two directions are equivalent if we only consider the L3 level - the level of individual IP packets.

Therefore, direction in `nfqws2` is handled by tracking flows. A flow is either a TCP connection or a sequence of UDP packets. Since UDP does not have the concept of a connection, the general term "flow" is used.

A flow is characterized by a 4-tuple: ip1:port1-ip2:port2. This set of values determines which flow a packet belongs to.

In `nfqws2`, flows are tracked by `conntrack`. The party that sends the first SYN (TCP) or the first UDP packet is considered the client, and the opposite end is the server. If a flow entry in `conntrack` was created by a SYN,ACK packet (TCP), that end is considered the server and the opposite end the client. In this way, `conntrack` determines the roles in establishing the connection and maintains a separate set of [counters](#the-track-table-structure) for each role-how many packets have passed, how many data packets, how many bytes transferred, etc.

In client mode, the "outgoing" direction is considered the direction from the client; in server mode (`--server`), it is the direction from the server. The "inbound" direction is the opposite.

When `--server` is specified, the directions are inverted. [`--in-range`, `--out-range`](#in-profile-filters), as well as the `desync.outgoing` flag in Lua functions, are swapped to correspond to the data actually being sent or received from the server's perspective. The client sends requests (http_req) and receives replies (http_reply). The server sends replies (http_reply) and receives requests (http_req).

In both client and server modes, ipset lookups are performed using the destination IP address for the outgoing direction and the source IP address for the inbound direction.

In client mode, port filters check the destination port for the outgoing direction and the source port for the inbound direction.

In server mode, port filters check the destination port for inbound traffic and the source port for outbound traffic.

This is because, in the context of filtering, only the server port is truly meaningful. Client ports are typically selected randomly from a specific range and are unsuitable for effective filtering.

Consequently, the server filters client IPs via ipsets, while the client filters server IPs. However, both the server and the client filter based on the server port.

Linux conntrack uses a similar method for determining direction. For a client, outbound packets are marked as `original` and inbound as `reply`. For a server, it is the opposite. This must be taken into account when writing interception rules that rely on conntrack direction.

Direction can also be determined by interface names. In a standard LAN-WAN configuration, packets received from the WAN are considered inbound, while those sent via the WAN are considered outbound. Using the WAN interface is crucial because NAT is typically involved; for `nfqws2`, it is essential to intercept outbound packets after NAT and inbound packets before NAT.

If the router operates without NAT (typical for IPv6), the stage at which packets are intercepted does not matter. All IP addresses are equivalent. You can connect to the internet, and the internet can connect to you; you are an integral part of it with direct IP addressing. In practice, however, inbound connections are unlikely, as you will likely protect yourself with a firewall. Therefore, direction can still be clearly defined by the interface. Nevertheless, if you do host an internal server, you can run a separate `nfqws2` instance in server mode for it, while using standard mode for client traffic.

In BSD, `ipfw` or `pf` rules are typically written this way - "xmit wan", "recv wan" - supplemented by filters for destination ports on `xmit` and source ports on `recv` (or vice versa for server mode). This reliably identifies the traffic intended for interception based on its direction.

## IP cache

The `ipcache` is an in-memory data structure that allows the process to store information using an IP address and interface name as a key. This data can later be retrieved and used to fill in missing information. Currently, it is used in the following scenarios:

1. **IP, interface => incoming ttl**. The TTL/HL of the first inbound packet is cached. This allows Lua functions (`autottl`) to use it immediately starting from the very first packet, even before a response has been received.

2. **IP => hostname**. The hostname is cached (independent of the interface) to facilitate profile lookups via hostlists and to provide the name to Lua functions when the hostname is not yet known. This mode is disabled by default and can be enabled using the `ipcache-hostname` parameter. This technique is experimental. Its main drawback is the lack of a one-to-one correspondence between domains and IP addresses; multiple domains can point to the same IP. In the event of a collision, the hostname is overwritten by the most recent entry. Furthermore, a domain may cycle through different IPs on a CDN-one address now, another an hour later. This issue is addressed via the cache entry lifetime: `--ipcache-lifetime` (defaulting to 2 hours). Nevertheless, you may find that in your specific case, the benefits of this technique outweigh the drawbacks. Be prepared for behavior that may seem confusing at first; such issues can be investigated using the `--debug` log.

Hostnames for caching are retrieved from L7 protocol analysis and DNS responses (excluding DoH).
DNS extraction works only via the UDP protocol and requires redirecting packets from port 53. Only DNS responses with source port 53 are processed.
On Windows, this is configured using `--wf-udp-in=53`. Since DNS queries will likely be directed to the local network, the `--wf-filter-lan=0` parameter is required.
If a DNS proxy is running on Windows and DNS is configured to use localhost, `--wf-filter-loopback=0` will also be necessary.
On a router, if encrypted DNS is used, you must capture requests from the client before they are encrypted on the LAN interface.
If encryption is not used, they can be captured on the WAN interface as well.
For the LAN interface, these will be outgoing; for the WAN interface, they will be incoming, following the conntrack "reply" direction.

When using [startup scripts](#startup-scripts) in Linux, there is a [custom script](#custom-scripts) called `80-dns-intercept` designed to intercept DNS responses. Simply copy it into the "custom.d" directory.

## Signals

- **SIGHUP**: Forcefully reloads all host list files and ipsets.
- **SIGUSR1**: Outputs the current contents of the conntrack pool.
- **SIGUSR2**: Outputs autohostlist counters and the contents of the ipcache pool.

## Debugging

The `--debug` parameter enables the output of debugging messages.

- `--debug=0`: Disables output.
- `--debug`, `--debug=1`: Output to the console.
- `--debug=@<filename>`: Output to a file. There is no limit on file size, but the file may be deleted at any time, and recording will resume from a clean slate.
- `--debug=syslog`: Output to syslog. Reading methods depend on the syslog daemon. `rsyslog` writes files to `/var/log`, while `busybox logd` is read via `logread`.
- `--debug=android`: Output to the Android log. Read via `logcat`. This is only available in versions built with the Android NDK.

The ability to use the `--debug` log is essential for troubleshooting settings and is absolutely necessary for writing your own Lua code.

All error messages (DLOG_ERR) and critical status messages (DLOG_CONDUP) are mirrored to the console regardless of the chosen log target.
Error messages are sent to `stderr`.

The `--dry-run` parameter allows you to test the validity of command-line options and the accessibility of used files under dropped privileges.
`--dry-run` does not initialize the Lua engine and therefore cannot detect Lua syntax errors.

## Virtual machines

Most desktop hypervisors break bypass techniques when the network is connected via the hypervisor's built-in NAT. This is the default setting. A bridged connection is required. This issue is confirmed to exist in both VMware and VirtualBox.

## Sandbox

For security purposes, nfqws2 drops its privileges after initialization.
All Lua code is executed only after privileges have been dropped; it never receives the original permissions.

BSD:

- Changes UID/GID to those specified in the `--user` and `--uid` parameters. Defaults to `0x7FFFFFFF`.

Linux:

- Changes UID/GID to those specified in the `--user` and `--uid` parameters. Defaults to `0x7FFFFFFF`.
- Drops capabilities to `cap_net_raw` and `cap_net_admin` (required for NFQUEUE). The bounding set is cleared to zero.
- Sets the `NO_NEW_PRIVS` flag to prevent SUID bits and file capabilities from functioning. If the kernel is older than 3.5 and `NO_NEW_PRIVS` is not supported, a warning is displayed, but execution continues.
- Enables a seccomp filter that prohibits `exec` and several file operations - reading directory contents, creating/deleting directories, creating special files (links, devices), `chmod`, `chown`, sending signals (`kill`), and `ptrace`.
In the event of a violation, the process is terminated. If the kernel does not support seccomp, a warning is displayed, but execution continues.

Windows:

- While the `WinDivert` driver requires administrator privileges, the `winws2` process sets its own integrity level to Low Mandatory Level after initialization. This prevents write access to almost all files and objects protected by a security descriptor. The process can no longer manage services or perform privileged actions. However, the Administrators group remains in the process token, so nothing prevents reading most files if they are accessible to Administrators. Lua lacks built-in tools for reading directory contents, making it difficult for an attacker to discover files of interest.
- All `Se*` privileges are irrevocably removed from the token, except for `SeChangeNotifyPrivilege`.
- A Job object is used to prohibit the creation of child processes and restrict desktop interaction - clipboard access, changing desktop settings, changing display settings, etc.

There is a simple way to pass a writable directory to the Lua code using the `--writeable[=<dirname>]` parameter. `nfqws2` creates the directory and assigns permissions so that the Lua code can write files there, then passes the directory name in the `WRITEABLE` environment variable. If `dirname` is not specified, a directory is created within `%USERPROFILE%/AppData/LocalLow` on Windows.

On the Lua side, dangerous functions are removed: `os.execute`, `io.popen`, `package.loadlib`, and the `debug` module. On GitHub, `nfqws2` executables are built with a version of LuaJIT that excludes FFI.

## Calling Lua code

Lua code is invoked in two stages:

1. Once at program startup via `--lua-init=code|@file`. If the parameter value starts with `@`, a file is executed; otherwise, the value is treated as Lua code. Gzip file compression is supported. The program first checks for "file", then "file.gz".
2. During profile processing via `--lua-desync=function_name:arg1[=val1]:arg2[=val2]:argN[=valN]`.
This starts with the function name, followed by arguments and their values separated by colons. All values are strings. If a value is not specified, it defaults to an empty string.
Two types of automatic substitutions are implemented on the C side:
`%var` substitutes the value of the variable `desync.var` or `var` if the former is missing.
`#var` substitutes the length of the variable `desync.var` or `var` if the former is missing.
Colons and the `%`, `#` symbols at the beginning can be escaped with a backslash `\`.

Both `--lua-init` and `--lua-desync` can be used multiple times. Execution follows the exact order in which they are specified.

### Passing blobs

A blob is a binary data block of any size that can be loaded into a Lua variable by the C code at program startup.

`--blob=<item_name>:[+ofs]@<filename>|0xHEX`

- `item_name` – the name of the Lua variable.
- `[+ofs]@<filename>` – loading from a file starting at offset `ofs`.
- `0xHEX` – loading from a HEX string.

Direct file operations from Lua code are not recommended unless absolutely necessary. Lua code runs with restricted privileges; intended operations might fail or behave inconsistently across different operating systems and environments. Blob loading occurs before entering the sandbox, providing a higher chance of success.

### In-profile filters

These come in three types: `--payload`, `--in-range`, and `--out-range`. Filter values remain active from the moment they are specified until the next override.

- `--payload=type1[,type2][,type3]...` accepts a comma-separated list of known [payloads](#protocol-detection), "all", or "known". The default is `--payload=all`.
- `--(in-range|out-range)=[(n|a|d|s|p)<int>](-|<)[(n|a|d|s|p)<int>]` sets conntrack counter ranges for inbound and outbound directions. The default is `--in-range=x`, `--out-range=a`.

Ranges are specified in the following formats: `mX-mY`, `mX<mY`, `-mY`, `<mY`, `mX-`, where `m` is the counter mode, `X` is the lower bound, and `Y` is the upper bound. Modes `x` and `a` are specified as a single letter without a range or counter value. The `-` sign indicates an inclusive upper bound, while `<` indicates an exclusive one.

The following counter modes are available:

- 'a' - always
- 'x' - never
- 'n' - packet number
- 'd' - data packet number
- 'b' - byte position of transmitted data
- 's' - tcp: relative sequence of the start of the current packet (works within a 2 GB range)
- 'p' - tcp: relative sequence of the upper bound of the current packet (s + payload length; works within a 2 GB range)

> [!CAUTION]
> In winws2, the `--wf-tcp-empty=0` parameter is enabled by default. This blocks the interception of empty ACK packets, which can reduce CPU usage by approximately 50% during intensive downloads. Empty ACKs are unnecessary for most strategies. However, this also breaks the "n" counter-it will not reflect the actual number of packets in the connection. If you require an accurate count, specify the `--wf-tcp-empty=1` parameter. On other systems, counter accuracy depends directly on the capture filters. A counter cannot and will not track what is not intercepted.

nfqws2 monitors the upper bounds of counters for all Lua instances.
If the upper bound for a direction is exceeded in all instances, or if the instances voluntarily enter a "cutoff" state for that direction, a "lua cutoff" occurs disabling Lua processing for the current thread. This is designed to conserve CPU resources, as checking a single boolean flag requires virtually no processing power.

### Typical instance invocation scheme within a profile

The following example demonstrates a setup where we attempt to use specific "fakes" for `tls_client_hello` and `http_req` payloads. If these fail, the system switches to `multidisorder` for TLS and `multisplit` for HTTP. If those also fail, it cycles through the strategies.

```
--filter-tcp=80,443 --filter-l7=http,tls
--out-range=-s34228
--in-range=-s5556 --lua-desync=circular
--in-range=x
--payload=tls_client_hello
--lua-desync=fake:blob=fake_default_tls:badsum:strategy=1
--lua-desync=multidisorder:strategy=2
--payload=http_req
--lua-desync=fake:blob=fake_default_http:badsum:strategy=1
--lua-desync=multisplit:strategy=2
```

The specific mechanics of these functions are less important here; the focus is on understanding how in-profile filters operate and how parameters are passed to Lua instances.

- The profile filter for TCP ports and protocol types prevents Lua from being called for irrelevant traffic. The profile will not be engaged at all if the filter conditions are not met.
- `--out-range` is specified to cut off the outbound flow from Lua after a relative sequence of (32768 + 1460) to save CPU. This value is chosen due to the specifics of the `circular` function: the `s32768` value is used as the default trigger threshold in the success detector, and `1460` is the maximum possible data length in a TCP packet. This may be unnecessary on Linux if the `connbytes` filter is used.
- `circular` requires the initial incoming packets of a stream to function, but these are disabled by default. Therefore, we enable them up to the relative sequence position `5556`. By default, the success detector reacts at `s4096`. We add one additional maximum-sized packet of 1460 bytes for safety.
- The remaining instances do not require incoming traffic, so we disable it again. The effect of `--in-range=x` extends to the end of the profile.
- The `--payload` directive applies to the two instances following it.
- The line `--lua-desync=fake:blob=fake_default_tls:badsum:strategy=1` calls the `fake` function with three arguments: `blob`, `badsum`, and `strategy`. The value for the `badsum` argument is an empty string.

## Lua desync function prototype

A standard Lua function uses the following prototype:

`function desync_f(ctx, desync)`

- `ctx`: Context for calling certain C functions.
- `desync`: A table containing all passed values, including arguments, the dissection of the current packet, etc.

The function returns a verdict for the current packet: `VERDICT_PASS`, `VERDICT_MODIFY`, or `VERDICT_DROP`. If nothing is returned, the result defaults to `VERDICT_PASS`.

- `VERDICT_PASS`: Passes the packet as-is, ignoring any changes to the dissection.
- `VERDICT_MODIFY`: Reconstructs and sends the current dissection.
- `VERDICT_DROP`: Drops the current packet.
- `VERDICT_PRESERVE_NEXT` - special bit to be added to the main verdict. During reconstruction of modified packet use next protocol fields in ipv6 header and ipv6 extension headers. If not set they are autogenerated by dissect content.

The results of all lua-desync instances are aggregated: VERDICT_MODIFY overrides VERDICT_PASS, and VERDICT_DROP overrides them both. VERDICT_PRESERVE_NEXT is applied if any instance set it.

### Structure of the desync table

The best way to study the desync structure is by examining its actual content while running the `pktdebug` test desync function from `zapret-lib.lua`.

<details>
  <summary><b>http-req packet from an IPv6 request to http://one.one.one.one</b></summary>
<pre>
desync:
.target
  .port
    number 80
  .ip6
    string 26 06 47 00 47 00 00 00 00 00 00 00 00 00 10 01
.func
  string pktdebug
.func_n
  number 1
.profile_n
  number 1
.l7payload
  string http_req
.dis
  .tcp
    .th_dport
      number 80
    .th_x2
      number 0
    .th_off
      number 8
    .th_sum
      number 18781
    .th_win
      number 64
    .options
      .1
        .kind
          number 1
      .2
        .kind
          number 1
      .3
        .data
          string 30 40 18 9A 6F A5 3E 89
        .kind
          number 8
    .th_seq
      number 19930989
    .th_ack
      number 1489231977
    .th_flags
      number 24
    .th_urp
      number 0
    .th_sport
      number 48118
  .ip6
    .ip6_flow
      number 1871905881
    .ip6_hlim
      number 64
    .ip6_dst
      string 26 06 47 00 47 00 00 00 00 00 00 00 00 00 10 01
    .exthdr
    .ip6_plen
      number 110
    .ip6_src
      string 1A E5 18 81 E1 CD E8 24 BA 16 39 FF FE 8A DE 12
    .ip6_nxt
      number 6
  .payload
    string 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6F 6E 65 2E 6F 6E 65 2E 6F 6E 65 2E 6F 6E 65 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20 63 75 72 6C 2F 38 2E 38 2E 30 0D 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A 0D 0A
  .l4proto
    number 6
  .transport_len
    number 110
  .l3_len
    number 40
  .l4_len
    number 32
.reasm_offset
  number 0
.reasm_data
  string 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6F 6E 65 2E 6F 6E 65 2E 6F 6E 65 2E 6F 6E 65 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20 63 75 72 6C 2F 38 2E 38 2E 30 0D 0A 41 63 63 65 70 74 3A 20 2A 2F 2A 0D 0A 0D 0A
.ifout
  string eth0
.fwmark
  number 0
.func_instance
  string pktdebug_1_1
.replay
  boolean false
.track
  .pos
    .dt
      number 0.013066192
    .server
      .tcp
        .pos
          number 1
        .rseq
          number 1
        .scale
          number 13
        .mss
          number 1360
        .winsize_calc
          number 65535
        .uppos
          number 0
        .seq0
          number 1489231976
        .seq
          number 1489231977
        .uppos_prev
          number 0
        .winsize
          number 65535
      .pcounter
        number 1
      .pdcounter
        number 0
      .pbcounter
        number 0
    .client
      .tcp
        .pos
          number 79
        .rseq
          number 1
        .scale
          number 10
        .mss
          number 1380
        .winsize_calc
          number 65536
        .uppos
          number 79
        .seq0
          number 19930988
        .seq
          number 19930989
        .uppos_prev
          number 0
        .winsize
          number 64
      .pcounter
        number 3
      .pdcounter
        number 1
      .pbcounter
        number 78
    .reverse
      .tcp
        .pos
          number 1
        .rseq
          number 1
        .scale
          number 13
        .mss
          number 1360
        .winsize_calc
          number 65535
        .uppos
          number 0
        .seq0
          number 1489231976
        .seq
          number 1489231977
        .uppos_prev
          number 0
        .winsize
          number 65535
      .pcounter
        number 1
      .pdcounter
        number 0
      .pbcounter
        number 0
    .direct
      .tcp
        .pos
          number 79
        .rseq
          number 1
        .scale
          number 10
        .mss
          number 1380
        .winsize_calc
          number 65536
        .uppos
          number 79
        .seq0
          number 19930988
        .seq
          number 19930989
        .uppos_prev
          number 0
        .winsize
          number 64
      .pcounter
        number 3
      .pdcounter
        number 1
      .pbcounter
        number 78
  .lua_state
  .hostname
    string one.one.one.one
  .hostname_is_ip
    boolean false
  .lua_in_cutoff
    boolean true
  .lua_out_cutoff
    boolean false
  .t_start
    number 1700000000
  .incoming_ttl
    number 51
  .l7proto
    string http
.arg
  .testarg1
    string val1
  .testarg2
    string val2
.tcp_mss
  number 1360
.l7proto
  string http
.outgoing
  boolean true
</pre>
</details>

desync

| Field | Type | Description | Notes |
| :----------------- | :----- | :------------------------------------------------------------------------------------------- | :---------------------------------------------------------- |
| func | string | name of the desync function | |
| func_n | number | instance number within the profile | |
| func_instance | string | instance name | derived from the function name, instance number, and profile number |
| profile_n | number | profile number | |
| profile_name | string | profile name | optional |
| cookie | string | value of the nfqws2 --cookie parameter for the profile | optional |
| outgoing | bool | true if the direction is outgoing | |
| ifin | string | incoming interface name | optional |
| ifout | string | outgoing interface name | optional |
| fwmark | number | fwmark of the current packet | Linux only |
| target | table | table containing the IP address and port used for checking ipsets and port filters | |
| replay | bool | delayed packet replay | |
| replay_piece | number | index of the part being replayed | 1-based indexing |
| replay_piece_count | number | total number of parts being replayed | |
| replay_piece_last | bool | indicates the last part being replayed | |
| l7payload | string | [payload type](#protocol-detection) of the current packet or packet group | defaults to "unknown" if undetermined |
| l7proto   | string | [flow protocol](#protocol-detection) | defaults to "unknown" if undetermined |
| reasm_data         | string | result of reassembling a multi-packet message, or the payload itself if no reassembly occurred | currently applied only to TCP                             |
| reasm_offset       | number | offset of the current replayed packet within the reassembled data                            | currently applied only to TCP                             |
| decrypt_data       | string | result of reassembling and decrypting the payload or payloads of multiple packets            | used for QUIC                                             |
| tcp_mss            | number | MSS of the remote end of the TCP connection                                                  | always present, only for TCP                              |
| track              | table  | data bound to the conntrack entry                                                            | only if conntrack is present; may be absent               |
| arg                | table  | all instance arguments and their values                                                      | % and # substitutions have already been resolved          |
| dis                | table  | dissection of the current packet                                                             |                                                           |

### Dissect structure

The dissection includes the fields `ip`, `ip6`, `tcp`, and `udp`.
`ip` is present in the case of IPv4, while `ip6` is present for IPv6.
The IP protocol version can be determined by the presence of the `ip` or `ip6` field.
The L4 protocol can be determined by the presence of `tcp` or `udp`.

The header tables mirror the field names of C structures from `netinet/{ip,ip6,tcp,udp}.h`.
IP addresses and IPv4 options are passed as raw strings.
To convert a raw IP address to text format, the `ntop` C function can be used. It automatically determines the IP version based on the buffer size.
IPv6 extension headers and TCP options are represented as tables.

All multi-byte numeric values are automatically converted from network byte order to host byte order.

**dissect**

| Field         | Type   | Description                                                      |
| :------------ | :----- | :--------------------------------------------------------------- |
| ip            | table  | IPv4 header                                                      |
| ip6           | table  | IPv6 header                                                      |
| frag_off      | number | IP fragment offset. present only in IP fragments.                |
| tcp           | table  | TCP header                                                       |
| udp           | table  | UDP header                                                       |
| icmp          | table  | ICMP header                                                      |
| l4proto       | number | IPPROTO_TCP or IPPROTO_UDP                                       |
| transport_len | number | packet length excluding L3 headers                                |
| l3_len        | number | length of L3 headers, including IP options and IPv6 extension headers |
| l4_len        | number | length of the L4 header, including TCP options                   |
| payload       | string | L4 payload or everything after L3 headers in case of raw IP      |

**ip**

| Field | Description |
| :------ | :-------------------------------------------------------------------------------------------------------------------------------------- |
| ip_v    | IP version - 4                                                                                                                          |
| ip_hl   | IP header length in 4-byte blocks. 5 if no IP options are present.                                                                      |
| ip_tos  | Type of Service. Contains the DSCP (Differentiated Services Code Point).                                                                |
| ip_len  | Total IP packet length, including all headers and payload.                                                                              |
| ip_id   | Packet identification for reassembling fragments.                                                                                       |
| ip_off  | Fragment offset, including MF (More Fragments) and DF (Don't Fragment) flags.                                                           |
| ip_ttl  | Time to Live - maximum number of hops.                                                                                                  |
| ip_p    | [IP protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Typically IPPROTO_TCP or IPPROTO_UDP.   |
| ip_sum  | IP header checksum.                                                                                                                     |
| ip_src  | Source IP address.                                                                                                                      |
| ip_dst  | Destination IP address.                                                                                                                 |
| options | Binary IP options block (rarely used, typically dropped by most network devices).                                                       |

**ip6**

| Field    | Description                                                                                                                                            |
| :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| ip6_flow | First 4 bytes of the IPv6 header: version (6), traffic class, and flow label.                                                                          |
| ip6_plen | Payload length: the length of the packet excluding the base 40-byte IPv6 header (IP6_BASE_LEN).                                                        |
| ip6_nxt  | [Next header/protocol](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). If no exthdr: IPPROTO_TCP (6) or IPPROTO_UDP (17).   |
| ip6_hlim | Hop limit. Serves the same purpose as TTL in IPv4.                                                                                                     |
| ip6_src  | Source IPv6 address.                                                                                                                                   |
| ip6_dst  | Destination IPv6 address.                                                                                                                              |
| exthdr   | Array of extension header tables (1-indexed).                                                                                                          |

**ip6 exthdr**

| Field | Description |
| :--- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| type | [header type](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml): IPPROTO_HOPOPTS, IPPROTO_ROUTING, IPPROTO_DSTOPTS, IPPROTO_MH, IPPROTO_HIP, IPPROTO_SHIM6, IPPROTO_FRAGMENT, IPPROTO_AH |
| next | type of the next header. Similar to `type`. For the final header, this may be IPPROTO_TCP or IPPROTO_UDP. |
| data | data excluding the first two bytes (type and length) |

**udp**

| Field    | Description                                          |
| :------- | :--------------------------------------------------- |
| uh_sport | source port                                          |
| uh_dport | destination port                                     |
| uh_ulen  | UDP length - UDP_BASE_LEN (8) header + payload length |
| uh_sum   | UDP checksum                                         |

**tcp**

| Field    | Description                                                                                                   |
| :------- | :------------------------------------------------------------------------------------------------------------ |
| th_sport | source port                                                                                                   |
| th_dport | destination port                                                                                              |
| th_x2    | reserved field; used for extended TCP flags                                                                   |
| th_off   | TCP header size in 4-byte blocks                                                                              |
| th_flags | TCP flags: TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR                                    |
| th_seq   | sequence number                                                                                               |
| th_ack   | acknowledgement number                                                                                        |
| th_win   | TCP window size                                                                                               |
| th_sum   | TCP checksum                                                                                                  |
| th_urp   | urgent pointer                                                                                                |
| options  | array of tables for [TCP options](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml) (1-indexed) |

**tcp options**

| Field | Description |
| :--- | :--- |
| kind | [option type](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml): TCP_KIND_END, TCP_KIND_NOOP, TCP_KIND_MSS, TCP_KIND_SCALE, TCP_KIND_SACK_PERM, TCP_KIND_SACK, TCP_KIND_TS, TCP_KIND_MD5, TCP_KIND_AO, TCP_KIND_FASTOPEN |
| data | the option data block excluding kind and length; absent for TCP_KIND_END and TCP_KIND_NOOP |

**icmp**

icmp header is the first 8 bytes of ICMP. This part is mandatory for all icmp types - both ipv4 and ipv6.
Following data including optional headers or attached IP packet goes to payload.

| Field      | Description |
| :--------- | :---------- |
| icmp_type  | [icmp type](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) |
| icmp_code  | [icmp code](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) |
| icmp_cksum | ICMP checksum |
| icmp_data  | 32-bit field at 4-byte offset |


### Handling multi-packet payloads

The assembly of a multi-packet payload is referred to as [reasm](#handling-multi-packet-payloads) (short for reassemble).
It is performed automatically by the C code if a payload requiring assembly is encountered, conntrack is available, and assembly has not been disabled via `--reasm-disable`.
Currently, two such payloads are supported: `tls_client_hello` and `quic_initial`. Both may contain Kyber post-quantum cryptography, which is too large to fit into a single packet.

For `tls_client_hello`, standard payload assembly of sequential TCP segments is performed, merging them into a single `reasm_data` block.

For `quic_initial`, individual packets are accumulated in an internal buffer, after which they are decrypted, merged, and defragmented. This handles payload parts scattered across packets and different offsets (a technique used by Chrome to prevent others from oversimplifying their algorithms, ensuring they follow standards and can correctly reassemble payloads from parts).

Until assembly is finalized, packets are accumulated in the internal buffer without calling Lua. Once finalized, the individual parts are replayed ([replay](#handling-multi-packet-payloads)). The Lua instances receive a dissection of each delayed packet, but with the fields `desync.replay=true`, `desync.replay_piece`, `desync.replay_count`, and `desync.replay_piece_last` set.

In the case of standard TCP reassembly, the `desync.reasm_data` field is populated, containing the full block of assembled data. `desync.dis.payload` continues to return the payloads of individual replayed packets. For TCP, if no [replay](#handling-multi-packet-payloads) occurs, `desync.reasm_data` contains a copy of `desync.dis.payload`.

During QUIC reassembly, `desync.reasm_data` is absent. Instead, the `desync.decrypt_data` field is provided, containing the result of decryption and defragmentation of all payloads within the assembly. For QUIC, `reasm_data` contains the `tls_client_hello` without the record layer.

### The track table structure

The `track` table is present in `desync` only if a conntrack entry was found for the current packet.
It may not be found if the `nfqws2` process did not receive the SYN or SYN-ACK packet.
For instance, the connection might have been established before `nfqws2` was started, you might not have intercepted SYN and SYN-ACK from the kernel, or you might have explicitly disabled conntrack via `--ctrack-disable`.
Your code must always check for the existence of `track` before accessing it; otherwise, the script will crash.
The same applies to optional `track` fields. Test your code with `--ctrack-disable` and across different protocols-TCP and UDP.

**track**

| Field          | Type   | Description                                                     | Note                                             |
| :------------- | :----- | :-------------------------------------------------------------- | :----------------------------------------------- |
| incoming_ttl   | number | TTL/HL of the first incoming packet in the stream               | May be absent if not determined                  |
| l7proto        | string | [flow protocol](#protocol-detection)                            | Always present; defaults to "unknown"            |
| hostname       | string | Hostname, determined through L6/L7 protocol analysis            | Appears only after identification               |
| hostname_is_ip | bool   | Whether the hostname is an IP address                           | Only present if a hostname exists                |
| lua_state      | table  | A table for storing state associated with the stream            | Always present; passed with every packet         |
| lua_in_cutoff  | bool   | Lua cutoff for the incoming direction                           | Read-only                                        |
| lua_out_cutoff | bool   | Lua cutoff for the outgoing direction                           | Read-only                                        |
| t_start        | number | Unix time of the first packet in the stream                     | Includes a high-precision fractional part        |
| pos            | table  | Counters for various directions                                 | Contains the tables: client, server, direct, and reverse |

The `track.pos` table contains sub-tables with sets of counters for two directions: `client` and `server`.
`client` refers to packets from the client, while `server` refers to packets from the server.
`direct` and `reverse` are simply references to `client` and `server`. Which one `direct` and `reverse` point to depends on the current direction (`desync.outgoing`) and the server mode (`b_server`).
`direct` always points to the current direction, while `reverse` points to the opposite one.

`track.pos` contains an additional field: `dt`. This is the packet arrival time in seconds relative to `t_start`.
It includes a high-precision fractional part.

The list of counter table fields is provided below. The `tcp` sub-table is present only for the TCP protocol.

| Field             | Description                                       | Note                                                   |
| :--------------- | :------------------------------------------------ | :----------------------------------------------------- |
| pcounter         | packet counter                                    |                                                        |
| pdcounter        | data packet counter                               | packets where the L4 payload size is not 0             |
| pbcounter        | transmitted bytes counter                         | only L4 payload sizes are counted; headers are ignored |
| ip6_flow         | last ip6.ip6_flow field                           | absent if unknown or if the IP protocol is not IPv6    |
| tcp.seq0         | initial connection sequence                       |                                                        |
| tcp.seq          | current packet sequence                           |                                                        |
| tcp.rseq         | relative sequence of the current packet           | calculated as seq - seq0                               |
| tcp.rseq_over_2G | rseq has crossed the 2 GB boundary                | s and p positions can no longer be relied upon         |
| tcp.pos          | relative sequence of the current packet's upper boundary | calculated as rseq + payload_size                      |
| tcp.uppos        | maximum pos in the connection                     |                                                        |
| tcp.uppos_prev   | uppos in the previous data packet                 | useful for detecting retransmissions                   |
| tcp.winsize      | last th_win field                                 | without scale correction                               |
| tcp.scale        | last value of the TCP scale option                |                                                        |
| tcp.winsize_calc | winsize corrected for scale                       | effective TCP window size                              |
| tcp.mss          | last value of the TCP MSS option                  |                                                        |

mss, winsize, and scale are transmitted from one side of the connection to the other so that each side knows the acceptable parameters of its peer.
When using these fields, it is critical not to confuse the sides.
If you need to know what packet size can be sent, you must look at the opposite side - what it is capable of receiving.
The mss is duplicated in the `desync.tcp_mss` field regardless of whether conntrack is present. The value there is already calculated for use in determining the size of the packet to be sent.
If conntrack is unavailable or if mss was not negotiated by the parties, a default value is set - DEFAULT_MSS (1220).

When working with sequences, you must account for their 32-bit unsigned nature.
If you add 100 to 4,294,967,280 (0xFFFFFFF0), the result will not be 4,294,967,380 (0x100000054), but 84 (0x54).
If you add these numbers in Lua, you will get 4,294,967,380 because Lua represents numbers with more than 32 bits of precision and uses signed values.
For sequence operations and comparisons, it is recommended to use the C functions `u32add` and `bitand`.
For example, the expression `0==bitand(u32add(seq1, -seq2), 0x80000000)` is equivalent to `seq1 >= seq2`.
However, the latter simple comparison will not work correctly, whereas the former will-provided that `seq1` has not drifted from `seq2` by more than 2 GB.
It is impossible to track anything beyond that using sequences. Always keep in mind that when transferring large volumes of data, sequences cannot serve as a counter.
The `p*counter` fields are 64-bit counters, so they do not suffer from this issue.

#### ICMP processing

Some icmp types may contain an attached source packet to which icmp was generated. They are called "related."
Such payloads are recognized, they are used to search the original conntrack record.
If it is found, the cached profile (the one to which the attached packet belongs) is selected.
The direction is chosen as the reverse of the found record.
The payload type is set to "ipv4" or "ipv6," the session protocol type is set from the source packet profile.
Then icmp goes through the profile in the usual way. Desync function must be aware of this possibility.

If icmp does not contain an attached packet, it is invalid or conntrack record is not found, icmp passes on its own
without track.

conntrack works only with tcp and udp, it does not keep records of pings or other icmp types.
No counters change when icmp traverses the conntrack entry.

#### raw IP processing

If the ip protocol is not recognized as tcp, udp, icmp, icmpv6, it is considered raw ip.
Dissect has ip/ip6 field and payload. Payload contains all data after L3 headers.
desync.track is always missing.

## Timers

Lua code can be called independently of received network data.
The event source is time.
A timer is an nfqws2 object, identified by a unique name, that allows you to call a specified Lua function at a specified frequency or once after a certain period of time.
The timer is set by the [timer_set](#timer_set) function, and deleted by the [timer_del](#timer_del) function.

nfqws2 is a single-threaded program, like the Lua engine. Timers are called in the same thread that processes network data.
In Linux and Windows, packets are received in blocks, not one at a time. A block is processed until all remaining packets are exhausted.
Timers are called between block processing. If processing takes a significant amount of time, the timer call may not be perfectly timed.

Timers can be useful for handling unreplied packets.
For example, you need to send something somewhere and read the response. But the other party might not respond or the response might not arrive.
To prevent your system from hanging in an undefined state and leaving garbage in memory, a timer can help.
Using timers, desync functions, and send functions, you can build a full-fledged state machine - even your own implementation of TCP or another guaranteed delivery system.
The system should be designed asynchronously, using a state machine. Direct sleep delays is not the option, as they break the queue-based traffic processing scheme.
While you're waiting, everything else will hang.

In the `--intercept=0` mode, if there are timers, nfqws2 doesn't exit immediately, but calls the timers until there are none left.
After this, the process terminates.


### Timer function prototype

```
function timer(name, data)
```

The timer function can be passed any Lua variable of any type.
A table can be used to store state associated with the timer.
Simple type variables can be used to pass read-only values ​​one-way.
data is set when the timer is started via [timer_set](#timer_set).
When the timer is deleted, the variable is automatically deallocated if there are no other references to it.

If a timer function fails with an error, the timer is forcibly deleted.
Therefore, when developing timer functions, it is especially important to avoid error conditions.

A one-shot timer is automatically deleted after the timer function is called. Manual deletion is not required, although it is permitted.


# nfqws2 C interface

Before executing `--lua-init`, the C code sets up base constants, blobs, and C functions.

## Base constants

| Field | Type | Description | Note |
| :--- | :--- | :--- | :--- |
| qnum | number | NFQUEUE queue number | Linux only |
| divert_port | number | divert port number | BSD only |
| desync_fwmark | number | fwmark for Linux, sockarg for BSD, 0 for Windows | |
| NFQWS2_VER | string | nfqws2 version | string returned by `--version` |
| NFQWS2_COMPAT_VER | number | sequence number of incompatible interface changes with nfqws2 | incremented by 1 for each change |
| b_debug | bool | --debug enabled | debug message output |
| b_daemon | bool | --daemon enabled | daemonize process, detach from tty |
| b_server  | bool   | --server enabled | Server mode  |
| b_ipcache_hostname  | bool   | --ipcache-hostname enabled | Caching of hostnames corresponding to IP addresses |
| b_ctrack_disable  | bool   | --ctrack-disable enabled     | Conntrack disabled |
| VERDICT_PASS<br>VERDICT_MODIFY<br>VERDICT_DROP<br>VERDICT_PRESERVE_NEXT | number | Desync function verdict code<br>VERDICT_PRESERVE_NEXT is the bit addition to the main verdict|  |
| DEFAULT_MSS  | number | Default MSS value      | 1220 |
| IP_BASE_LEN  | number | Base IPv4 header size  | 20  |
| IP6_BASE_LEN | number | Base IPv6 header size  | 40  |
| TCP_BASE_LEN | number | Base TCP header size   | 20  |
| UDP_BASE_LEN | number | UDP header size        | 8   |
| TCP_KIND_END<br>TCP_KIND_NOOP<br>TCP_KIND_MSS<br>TCP_KIND_SCALE<br>TCP_KIND_SACK_PERM<br>TCP_KIND_SACK<br>TCP_KIND_TS<br>TCP_KIND_MD5<br>TCP_KIND_AO<br>TCP_KIND_FASTOPEN | number | TCP option type codes (kinds) | |
| TH_FIN<br>TH_SYN<br>TH_RST<br>TH_PUSH<br>TH_ACK<br>TH_URG<br>TH_ECE<br>TH_CWR | number | TCP flags | Can be combined using + |
| IP_MF | number | IP "more fragments" flag | 0x8000, part of the ip_off field |
| IP_DF | number | IP "don't fragment" flag | 0x4000, part of the ip_off field |
| IP_RF | number | IP "reserved" flag | 0x2000, part of the ip_off field |
| IP_OFFMASK | number | Bitmask for the ip_off field corresponding to the fragment offset | 0x1FFF |
| IP_FLAGMASK | number | Bitmask for the ip_off field corresponding to IP flags | 0xE000 |
| IPTOS_ECN_MASK | number | Bitmask for the ip_tos field corresponding to ECN | 0x03 |
| IPTOS_ECN_NOT_ECT | number | Not ECN-Capable Transport | 0x00 |
| IPTOS_ECN_ECT1 | number | ECN Capable Transport(1)     | 0x01 |
| IPTOS_ECN_ECT0 | number | ECN Capable Transport(0)     | 0x02 |
| IPTOS_ECN_CE  | number | Congestion Experienced        | 0x03 |
| IPTOS_DSCP_MASK | number | bitmask of the ip_tos field corresponding to DSCP | 0xFC |
| IP6F_MORE_FRAG  | number | "More fragments" bit of the ip6f_offlg field from the IPv6 fragment header | 0x0001 |
| IPV6_FLOWLABEL_MASK | number | flow label in ip6_flow | 0x000FFFFF |
| IPV6_FLOWINFO_MASK | number | flow label and traffic class in ip6_flow | 0x0FFFFFFF  |
| IPPROTO_IP<br>IPPROTO_IPV6<br>IPPROTO_ICMP<br>IPPROTO_ICMPV6<br>IPPROTO_TCP<br>IPPROTO_UDP<br>IPPROTO_SCTP<br>IPPROTO_HOPOPTS<br>IPPROTO_ROUTING<br>IPPROTO_FRAGMENT<br>IPPROTO_AH<br>IPPROTO_ESP<br>IPPROTO_DSTOPTS<br>IPPROTO_MH<br>IPPROTO_HIP<br>IPPROTO_SHIM6<br>IPPROTO_NONE | number | [IP protocol numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) | used in IPv4 and IPv6 |
| ICMP_ECHOREPLY<br>ICMP_DEST_UNREACH<br>ICMP_REDIRECT<br>ICMP_ECHO<br>ICMP_TIME_EXCEEDED<brICMP_PARAMETERPROB<br>ICMP_TIMESTAMP<br>ICMP_TIMESTAMPREPLY<br>ICMP_INFO_REQUEST<br>ICMP_INFO_REPLY | number | [icmp types](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) | ipv4 only |
| ICMP_UNREACH_NET<br>ICMP_UNREACH_HOST<br>ICMP_UNREACH_PROTOCOL<br>ICMP_UNREACH_PORT<br>ICMP_UNREACH_NEEDFRAG<br>ICMP_UNREACH_SRCFAIL<br>ICMP_UNREACH_NET_UNKNOWN<br>ICMP_UNREACH_HOST_UNKNOWN<br>ICMP_UNREACH_NET_PROHIB<br>ICMP_UNREACH_HOST_PROHIB<br>ICMP_UNREACH_TOSNET<br>ICMP_UNREACH_TOSHOST<br>ICMP_UNREACH_FILTER_PROHIB<br>ICMP_UNREACH_HOST_PRECEDENCE<br>ICMP_UNREACH_PRECEDENCE_CUTOFF | number | icmp codes for destination unreachable | ipv4 only |
| ICMP_REDIRECT_NET<br>ICMP_REDIRECT_HOST<br>ICMP_REDIRECT_TOSNET<br>ICMP_REDIRECT_TOSHOST | number | icmp codes for redirect | ipv4 only |
| ICMP_TIMXCEED_INTRANS<br>ICMP_TIMXCEED_REASS | number | icmp codes for time exceeded | ipv4 only |
| ICMP6_ECHO_REQUEST<br>ICMP6_ECHO_REPLY<br>ICMP6_DST_UNREACH<br>ICMP6_PACKET_TOO_BIG<br>ICMP6_TIME_EXCEEDED<br>ICMP6_PARAM_PROB<br>MLD_LISTENER_QUERY<br>MLD_LISTENER_REPORT<br>MLD_LISTENER_REDUCTION<br>ND_ROUTER_SOLICIT<br>ND_ROUTER_ADVERT<br>ND_NEIGHBOR_SOLICIT<br>ND_NEIGHBOR_ADVERT<br>ND_REDIRECT | number | [icmpv6 types](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml) | ipv6 only |
| ICMP6_DST_UNREACH_NOROUTE<br>ICMP6_DST_UNREACH_ADMIN<br>ICMP6_DST_UNREACH_BEYONDSCOPE<br>ICMP6_DST_UNREACH_ADDR<br>ICMP6_DST_UNREACH_NOPORT | number | icmpv6 code for destination unreachable | ipv6 only |
| ICMP6_TIME_EXCEED_TRANSIT<br>ICMP6_TIME_EXCEED_REASSEMBLY | number | icmpv6 codes for time exceeded | ipv6 only |
| ICMP6_PARAMPROB_HEADER<br>ICMP6_PARAMPROB_NEXTHEADER<br>ICMP6_PARAMPROB_OPTION | number | icmpv6 codes for parameter problem | ipv6 only |


## Standard blobs

- fake_default_tls - a fake Firefox TLS ClientHello without Kyber, SNI=www.microsoft.com
- fake_default_http - an HTTP request to <www.iana.org>
- fake_default_quic - 0x40 + 619*0x00

## Environment variables

| env       | Purpose |
| :-------- |:---------- |
| WRITEABLE | A directory writable by Lua. Corresponds to the `--writeable` option. |
| APPDATALOW | (Windows only) The AppData location for the low mandatory level. This is also writable, but using `--writeable` is preferred for cross-platform compatibility. |

## C functions

### Logging

```
function DLOG(string)
function DLOG_ERR(string)
function DLOG_CONDUP(string)
```

These functions output a string to the `--debug` log, appending an EOL (End of Line).

- DLOG - standard output.
- DLOG_CONDUP - standard output + console output if logging to a file or syslog is enabled.
- DLOG_ERR - similar to DLOG_CONDUP, but all console output is directed to stderr.

### IP conversion

```
function ntop(raw_ip)
function pton(string_ip)
```

- ntop converts a raw byte string containing an IPv4 or IPv6 address into a human-readable string representation. The IP version is determined by the size of `raw_ip` (4 or 16 bytes). If the size does not match, it returns `nil`.
- pton converts a string representation of an IPv4 or IPv6 address into a `raw_ip` byte string. If the string is not a valid IPv4 or IPv6 address, it returns `nil`.

### Bitwise operations

Lua 5.1, which LuaJIT is based on, lacks built-in bitwise operations. LuaJIT includes a built-in `bitop` module.
Lua 5.3 has built-in bitwise operators but lacks the `bitop` module. While it can be loaded, this is only possible if static compilation is not used and the module is installed. The nfqws2 version on GitHub is built statically.

When working with network packet fields, bitwise operations are essential.
Bitwise operations and shifts are typically implemented as a single machine instruction, making them native operations for the processor. Replacing them with constructs based on floating-point math (exponentiation, division, rounding, etc.) is inefficient, especially considering that many routers and other embedded devices lack an FPU.

To avoid this inconsistency, nfqws2 provides its own set of bitwise and shift functions that are independent of the Lua engine type or version. All bitwise operations work with unsigned numbers ranging from 8 to 48 bits.
If negative numbers are passed, they are interpreted using two's complement. For example, in 32-bit mode, -2 becomes 0xFFFFFFFE; in 8-bit mode, it becomes 0xFE.
Higher bit depths are not supported due to incompatibilities between Lua 5.3+ and older versions.
Only Lua 5.3 implements a 64-bit integer type. Older versions use the `double` floating-point format with a 52-bit mantissa, which allows for safe handling of up to 48-bit integers.

Standard shift and bitwise logical operations:

```
function bitlshift(u48, bits)
function bitrshift(u48, bits)
function bitand(u48_1, u48_2, ...., u48_N)
function bitor(u48_1, u48_2, ...., u48_N)
function bitxor(u48_1, u48_2, ...., u48_N)
function bitnot(u48)
function bitnot8(u8)
function bitnot16(u16)
function bitnot24(u24)
function bitnot32(u32)
function bitnot48(u48)
```

`bitand`, `bitor`, and `bitxor` support an arbitrary number of arguments.
`bitnot` has versions for different bit depths. The generic `bitnot` is an alias for `bitnot48`.

Functions for getting and setting individual bits:

```
function bitget(u48, bit_from, bit_to)
function bitset(u48, bit_from, bit_to, set)
```

- bitget extracts a number from a range of bits in `u48` from `bit_from` to `bit_to`. Bit numbering starts at 0.
- bitset writes the value `set` into the bit range of `u48` from `bit_from` to `bit_to`. Bit numbering starts at 0. Higher bits of `set` that exceed the range `(bit_to - bit_from)` are ignored.

### Unsigned number operations

Bit depth is always critical when performing unsigned number operations, as it determines the result.
Consequently, all functions include the bit depth in their name. If arguments exceeding the specified bit depth are passed, an error is triggered.

#### uX

```
function u8(raw_string[, offset])
function u16(raw_string[, offset])
function u24(raw_string[, offset])
function u32(raw_string[, offset])
function u48(raw_string[, offset])
```

These functions are used to extract numeric fields in big-endian format from a raw string.
The `offset` parameter is the byte position from the start of the raw string, starting at 1.
Similar built-in functionality (`string.unpack`) is only available in Lua 5.3 and later.

#### buX

```
function bu8(u8)
function bu16(u16)
function bu24(u24)
function bu32(u32)
function bu48(u48)
```

These functions convert a number into a big-endian raw string.
To assemble a structure from numeric fields, you can use the standard string concatenation operator `..`.

#### swapX

```
function swap16(u16)
function swap24(u24)
function swap32(u32)
function swap48(u48)
```

These functions invert the byte order of a u16, u24, u32, or u48 value. If your structure uses little-endian byte order, you can combine `uX`/`buX` with `swapX`.

#### uXadd

```
function u8add(u8_1, u8_2, ...., u8_N)
function u16add(u16_1, u16_2, ...., u16_N)
function u24add(u24_1, u24_2, ...., u24_N)
function u32add(u32_1, u32_2, ...., u32_N)
function u48add(u48_1, u48_2, ...., u48_N)
```

Functions for adding an arbitrary number of unsigned integers of a specified bit-depth.
Operands must fit within the specified bit-depth; otherwise, an error is raised.
Any carry-over beyond the bit-depth is ignored (modular arithmetic).

### Integer division

#### divint

Native integer division is only available in Lua 5.3+, which includes an explicit integer data type.
To avoid issues with rounding, integer division is implemented via a C function:

```
function divint(dividend, divisor)
```

This function has no bit-depth restrictions. Internally, it uses the `int64_t` type.
In Lua 5.3+, there is no loss of precision. In older versions, numbers may be distorted if the operands or the result exceed the size of a double's mantissa.

### Random Data Generation

#### brandom

These functions generate a raw string of a specified size consisting of random bytes.
The random data generated is not cryptographically secure.

```
function brandom(size)
function brandom_az(size)
function brandom_az09(size)
```

- `brandom` returns bytes from 0 to 255.
- `brandom_az` returns characters from 'a' to 'z'.
- `brandom_az09` returns characters from 'a' to 'z' and digits from '0' to '9'.

### Parsing

#### parse_hex

```
function parse_hex(hex_string)
```

Returns a raw string containing the bytes represented by a hex string. For example: `"1234ABCD" => "\x12\x34\xAB\xCD"`.
If the `hex_string` is invalid, it returns `nil`.

### Cryptography

Lua typically has a standard binding module for OpenSSL that provides a wide range of cryptographic functions.
However, relying on external modules is often not an option, as Lua is frequently linked statically without support for loading external modules.
To avoid unnecessary dependencies and extra files-especially since OpenSSL's multi-megabyte size is a concern for embedded systems - this implementation is self-contained.

`nfqws2` does not use any external crypto libraries, but it includes a minimal set of cryptographic operations required for certain protocols (such as QUIC).
These functions are exposed to Lua and can be used for any purpose.

#### bcryptorandom

```
function bcryptorandom(size)
```

Generates a raw string containing a cryptographically secure block of random data of the specified size. The source is `/dev/random`.

Random data source - getrandom() (Linux), getentropy() (BSD), `/dev/random`.
`/dev/urandom` is used as a fallback if the previous sources failed or block.
lack of entropy pool is typical Android problem.

#### bxor,bor,band

```
function bxor(data1, data2)
function band(data1, data2)
function bor(data1, data2)
```

Return per-byte xor,and,or between 2 equal sized raw string. Error is generated if string sizes are not equal.

#### hash

```
function hash(hash_type, data)
```

Returns a raw string representing the hash of a data block (the `data` raw string). `hash_type` can be `"sha256"` or `"sha224"`.

#### aes

```
function aes(encrypt, key, data)
```

Performs simple encryption or decryption of a single AES block.

- `encrypt`: `true` to encrypt, `false` to decrypt.
- `key`: A raw string. The size must be 16, 24, or 32 bytes, corresponding to AES-128, AES-192, or AES-256.
- `data`: A raw string. The size must be exactly 16 bytes.
- Returns a 16-byte raw string containing the result of the operation.
- An error is raised if the `key` or `data` sizes are incorrect.

#### aes_gcm

```
function aes_gcm(encrypt, key, iv, data[, associated_data])
```

AES encryption in GCM mode.

- `encrypt` - `true` to encrypt, `false` to decrypt.
- `key` - raw string. The key size must be 16, 24, or 32 bytes, corresponding to AES-128, AES-192, and AES-256.
- `iv` - 12-byte raw string. **IT IS MANDATORY TO GENERATE A RANDOM IV FOR EVERY ENCRYPTED DATA BLOCK AND TRANSMIT IT ALONGSIDE THE DATA.** If an **IV IS REUSED WITH THE SAME KEY, THE ENCRYPTION IS EASILY COMPROMISED.** Use `bcryptorandom` to generate the IV.
- `data` - raw string of arbitrary size. The cipher uses a keystream, so the source data is not tied to the AES block size.
- `associated_data` - unencrypted data transmitted with the encrypted message that is included in the ATAG calculation. Can be `nil`.
- Returns 2 values: a raw string (the encrypted data block) and a raw string (the ATAG or authentication tag). The ATAG can be transmitted with the encrypted message, IV, and associated data to verify their integrity.
- Throws an error if the key or IV sizes are incorrect.

#### aes_ctr

```
function aes_ctr(key, iv, data)
```

AES encryption in CTR mode.

- `key` - raw string. The key size must be 16, 24, or 32 bytes, corresponding to AES-128, AES-192, and AES-256.
- `iv` - 16-byte raw string. **IT IS MANDATORY TO GENERATE A RANDOM IV FOR EVERY ENCRYPTED DATA BLOCK AND TRANSMIT IT ALONGSIDE THE DATA.** If an **IV IS REUSED WITH THE SAME KEY, THE ENCRYPTION IS EASILY COMPROMISED.** Use `bcryptorandom` to generate the IV.
- `data` - raw string of arbitrary size. The cipher uses a keystream, so the source data is not tied to the AES block size.
- Encryption works via XOR with a keystream, making it symmetric. Encryption and decryption are the same operation.
- Returns a raw string: the encrypted data block.
- Throws an error if the key or IV sizes are incorrect.

#### hkdf

```
function hkdf(hash_type, salt, ikm, info, okm_len)
```

HKDF - HMAC-based Key Derivation Function. A key generator based on arbitrary input keying material (IKM).
The function includes both extraction and expansion phases.

- `hash_type` can be "sha256" or "sha224".
- `salt` - raw string of arbitrary size; can be `nil`. This is non-secret information that allows for different results from the same IKM. If `nil`, a block of zero bytes equal to the hash function's output size is used.
- `ikm` - raw string (input keying material). OKM (output keying material) is generated based on this data, the salt, and the info.
- `info` - raw string of arbitrary size; can be `nil`. Similar to salt, but salt is mixed in during the extraction phase, while info is used during expansion. If `nil`, a zero-length info string is used.
- `okm_len` - the required length of the OKM (output keying material).
- Returns a raw string: the OKM.

### Compression

#### gunzip

```
function gunzip_init([windowBits])
function gunzip_end(zstream)
function gunzip_inflate(zstream, compressed_data[, expected_uncompressed_chunk_size])
```

* `gunzip_init` creates and returns a gzip stream context for subsequent function calls. See the zlib documentation for `windowBits` values (default is 47).
* `gunzip_end` releases the gzip context. While it can be handled by the garbage collector, it is better to call it explicitly.
* instead of calling `gunzip_end` in Lua 5.5+ it's possible to use to-be-close variable for the context
* `gunzip_inflate` decompresses the next part of the gzipped data. Data can be fed into the function in chunks. Decompressed parts are concatenated to obtain the full data. Returns 2 arguments: the decompressed data and a boolean flag indicating the end of the gzip stream. Returns `nil` in case of corrupted data or memory allocation failure.
* `expected_uncompressed_chunk_size` - an optional parameter to optimize memory allocation for decompressed data. If the buffer is insufficient, `realloc` is called, which copies memory blocks and impacts performance. The size should be chosen based on the expected compression ratio with a small margin. The default is four times the size of `compressed_data`.

#### gzip

```
function gzip_init([windowBits[, level[, memlevel]]])
function gzip_end(zstream)
function gzip_deflate(zstream, uncompressed_data[, expected_compressed_chunk_size])
```

* `gzip_init` creates and returns a gzip stream context for subsequent function calls. For `windowBits` values, refer to the zlib documentation (default is 31). `level` specifies the compression level from 1 to 9 (default is 9), and `memlevel` defines the allowed memory usage level from 1 to 8 (default is 8).
* `gzip_end` releases the gzip context. While it can be released by the garbage collector, it is better to call this function explicitly.
* instead of calling `gzip_end` in Lua 5.5+ it's possible to use to-be-close variable for the context
* `gzip_deflate` compresses the next chunk of data. Data can be fed in parts. The compressed chunks are concatenated to form the complete data set. To finalize the stream after all data has been fed, the function must be called with `uncompressed_data=nil` or `uncompressed_data=""`. It returns two arguments: the compressed data and a boolean flag indicating the end of the gzip stream. If a gzip error occurs or memory is insufficient, it returns `nil`.
* `expected_compressed_chunk_size` is an optional parameter used to optimize memory allocation for compressed data. If the buffer is insufficient, `realloc` is called, which copies memory blocks and impacts performance. The size should be chosen based on the expected compression ratio with a small margin. The default is half the size of `uncompressed_data`.

### System functions

#### uname

```
function uname()
```

Returns the same value as the `uname` shell command-the OS kernel name (e.g., "Linux", "FreeBSD", "OpenBSD").
On Windows, it returns a string starting with "CYGWIN" followed by the version.

#### clock_gettime

```
function clock_gettime()
function clock_getfloattime()
```

clock_gettime retrieves the precise time. Returns two values: Unix time in seconds and the nanosecond component. The built-in `os.time()` function does not provide nanoseconds.
clock_getfloattime returns unixtime in the floating point format. Nanoseconds go to the fractional part.

#### getpid

```
function getpid()
function gettid()
```

- `getpid()` returns the current process identifier (PID).
- `gettid()` returns the current thread identifier (TID).

#### stat

```
function stat(filename)
```

If successful returns the following table :

| Field    | Type   | Description |
| :------- | :----- | :---------- |
| type     | string | file type : file, dir,  socket, blockdev, chardev, fifo, unknown |
| size     | number | file size |
| mtime    | number | modification unixtime in floating point format |
| inode    | number | inode. In Windows doesn't fit into number datatype of luajit but fits into integer datatype of Lua5.3+ |
| dev      | number | device id |

In case of error returns 3 values : nil, error string, error number (errno).

#### time

```
function localtime(unixtime)
function gmtime(unixtime)
function timelocal(tm)
function timegm(tm)
```

localtime and gmtime return dissected unixtime similar to C "struct tm". timelocal and timegm are reverse functions.

| Field    | Type   | Description |
| :------- | :----- | :---------- |
| sec*     | number | second      |
| min*     | number | minute      |
| hour*    | number | hour        |
| mon*     | number | month starting from 0 |
| mday*    | number | day of month starting from 1 |
| year*    | number | full year, not from 1900 |
| wday     | number | day of week. 0 = sunday |
| yday     | number | day of year starting from 0 |
| isdst*   | number | not zero if summer time in effect |
| zone     | string | time zone |
| str      | string | formatted string: "dd.mm.yyyy hh:mi:ss"  |

Fields marked with `*` are required for reverse translation.


### Packet handling options

The following functions use standard sets of options: `rawsend` and `reconstruct`.
These are tables with specific fields. If `nil` is passed, it is assumed that no fields are set.

#### standard reconstruct

Dissect reconstruction options-`reconstruct_opts`. Reconstruction is the process of assembling a raw packet from a dissect.

| Field             | Type   | Description                                                                                       |
| :---------------- | :----- | :------------------------------------------------------------------------------------------------ |
| keepsum           | bool   | Use checksum from the dissect as is. Do not calculate or corrupt. |
| badsum            | bool   | Corrupt the L4 checksum. Calculates the checksum and XORs it with a random value from 1 to 0xFFFF |
| ip6_preserve_next | bool   | Use the "next" values from `ip6.exthdr`                                                           |
| ip6_last_proto    | number | If `ip6_preserve_next=false`, specifies the IP protocol for the last `exthdr`                     |

When assembling IPv6 by default, the chain of IP protocols in the `exthdr` is built automatically.
Each `exthdr` has a `type` field, making it clear what to write into the previous `exthdr` or the main `ip6` header. The `next` protocol of the last `exthdr` is set to `IPPROTO_TCP` or `IPPROTO_UDP` depending on whether `tcp` or `udp` tables are present in the dissect.
In most cases, this is convenient because when inserting an `exthdr`, you do not need to reconstruct the entire chain of `next` protocols or fill in the `next` fields manually. The dissect reconstructor handles this for you.

Use ip6_preserve_next if you have a special task that requires manual crafting of the next protocol fields.
In this case, the next fields in exthdr and ip6.ip6_nxt are left as is.

If you are reconstructing an IPv6 header separately and are not using the `ip6_preserve_next` option, it is impossible to automatically determine what should be written into the last `exthdr`. In this case, `ip6_last_proto` is used, or `IPPROTO_NONE` if `ip6_last_proto` is not specified.

`badsum` has been moved to reconstruction because TCP and UDP checksums are calculated based on the entire IP packet.
The checksum includes elements from the IP/IPv6 header, the entire TCP header, and the payload itself.
Therefore, it is impossible to guarantee a corrupted checksum by looking at individual parts alone.
No matter what value you input, there is a small probability (1/65536) that it will happen to be valid.

The packet is formed based on the L3 header, then the L4 header (TCP,UDP,ICMP, if present) is appended, followed by the payload.
During reconstruction IP protocol fields are ignored. Therefore, it is possible to construct TCP,UDP,ICMP packets with a modified IP protocol.

#### standard rawsend

Raw packet sending options - `rawsend_opts`

| Field   | Type   | Description                                                                                               |
| :------ | :----- | :-------------------------------------------------------------------------------------------------------- |
| repeats | number | The number of times to repeat sending the exact same packet.                                              |
| fwmark  | number | The fwmark of the outgoing packet. Linux only. Defaults to 0. The `desync_mark` bit is forced.            |
| ifout   | string | The outgoing interface. May or may not be used depending on the situation.                                 |

`ifout` should always be passed exactly as it was received in the dissect.
A correct `ifout` is mandatory for Windows. It is not used on BSD.
On Linux, it is only used if the `--bind-fix4` or `--bind-fix6` options are enabled, depending on the IP version.

It is recommended to pass `fwmark` exactly as it was received in the dissect.
In special cases where your routing table rules rely on it, you can mix in your own bits.

`repeats` sends a binary-identical packet the specified number of times without inspecting its contents.
No changes are made, including to the `ip_id`.
If you need the `ip_id` to change, you can set it to 0; Windows will then automatically fill in incrementing values.
Other systems will not do this. If you need to manage the `ip_id` manually across all systems, `repeats` is not the right choice.

### Dissection and reconstruction

Dissection is the process of obtaining a structured representation of a raw IP packet.
Reconstruction is the reverse process-generating a raw IP packet from a dissect.

#### dissect

```
function dissect(raw_ip)
```

Returns a table representing the dissection of the `raw_ip` packet.
This is the same operation that occurs automatically before desync functions are called based on the profile.
Those functions receive an already prepared dissect.

#### reconstruct_dissect

```
function reconstruct_dissect(dissect[, reconstruct_opts])
```

Returns `raw_ip`. All checksums are calculated automatically. L4 checksums are intentionally corrupted if `badsum` is specified in [reconstruct_opts](#standard-reconstruct).

Reconstruction of fragmented IP packets involves special magic.

1. if the "frag_off" field is present, tcp/udp/icmp headers are ignored, payload contains raw ip payload. Incoming fragmented packets come in this form. nfqws2 does not defragment at the IP layer. But this is very persistently done by Linux systems - in order for a fragment to come to nfqws2, you need to try hard by inserting "notrack" into prerouting or output. Dissects in this form can be reconstructed as is. But preparing them in Lua is extremely inconvenient, since you will have to go through the black magic of working with a binary representation.
2. If the "frag_off" field is absent, fragment reconstruction is performed on the entire packet's dissect involving both Lua and C code. Lua code must prepare a dissect of the full packet intended for fragmentation, but fill certain fields as they should appear in the fragment:

- **ipv4**: `ip.ip_len` must be calculated as it should appear in the fragment.
The C code uses `ip.ip_len` to determine the size of the fragmented portion.
The `ip.ip_off` field must contain the fragment offset and the `IP_MF` flag if it is not the last fragment. `ip.ip_id` must not be 0.
- **ipv6**: You must insert a fragment header into `ip6.exthdr` and fill in the `ident`, `offset`, and the `IP6F_MORE_FRAG` bit if it is not the last fragment.
`ip6.ip6_len` must be calculated as it should appear in the fragment. The C code determines the fragment size based on this length.
The Lua code chooses the position of the fragment header. Everything following the fragment header is considered the fragmentable part.

If the C code detects that fragmentation is required, it validates the calculated lengths and offsets. If they are correct, it shifts the contents of the raw packet within the reconstruction buffer after reconstruction to produce a fragment with the required data.

#### reconstruct_hdr

```
function reconstruct_tcphdr(tcp)
function reconstruct_udphdr(udp)
function reconstruct_icmphdr(icmp)
function reconstruct_iphdr(ip)
function reconstruct_ip6hdr(ip6[, reconstruct_opts])
```

Reconstructs the corresponding raw headers from the dissect tables. Returns the raw version of the header.

- IPv6 reconstruction utilizes `reconstruct_opts`, specifically `ip6_preserve_next` and `ip6_last_proto`.
- The IP header checksum is calculated automatically since it does not depend on any other components.
- TCP, UDP and ICMP checksums are not calculated automatically because they depend on other components.

#### csum_fix

```
function csum_ip4_fix(raw_ipv4_header)
function csum_tcp_fix(raw_ip_header, raw_tcp_header, payload)
function csum_udp_fix(raw_ip_header, raw_udp_header, payload)
function csum_icmp_fix(raw_ip_header, raw_icmp_header, payload)
```

Functions for fixing checksums. Since strings in Lua are immutable, these functions return a copy of the respective header with the corrected checksum.

- `csum_ipv4_fix` is straightforward: it takes an IP header as input and returns an IP header with the corrected checksum.
- `csum_tcp_fix`, `csum_udp_fix` `csum_icmp_fix` take a raw IP header (IPv4 or IPv6), a TCP/UDP/ICMP header, and the payload. The IP version is detected automatically. The checksum is calculated based on the L3 and L4 headers and the payload.

Direct reconstruction of individual headers is rarely necessary. Typically, all tasks are handled by functions working with dissects.

### conntrack

```
function conntrack_feed(dissect/raw_packet[, reconstruct_opts])
```

"Feed" dissect or raw packet string to conntrack the way as if it was received from the network.
[reconstruct_opts](#standard-reconstruct) is meaningful only for dissects.
2 values are returned : [track](#the-track-table-structure) and bool value "outgoing".
outgoing is true if a new conntrack record was created and it was a SYN packet in case of tcp or any packet in case of udp.
If conntrack record already exists outgoing is true if the record was found by direct tuple - src_ip, src_port, dst_ip, dst_port.
If the record was found by reverse tuple - dst_ip, dst_port, src_ip, src_port - outgoing is false.

The function can come in handy if you are obfuscating and transmitting data in a distorted form. For example, tcp is converted to icmp or the SYN flag is corrupted.
The receiving end will issue the first corrupted packet without track, because it is either not tcp and not udp, or there was no valid tcp handshake.
After deobfuscation, you can correct the situation by executing conntrack_feed and assigning desync.track its result.

If conntrack is disabled or the packet is not valid tcp or udp, nil is returned.

### Obtaining IP addresses

```
function get_source_ip(target)
```

Get source IP (raw string) that would be used for connection the the target IP.
Returns nil if destination is unreachable.

```
function get_ifaddrs()
```

Get all interfaces and IPs on them (analog of "ip addr", "ifconfig", "ipconfig").
Returns table indexed by interface names. In Windows interface names are in the "number.number" form - IfxIdx.SubIfIdx.
This is WinDivert compatible.

Interface table contents :

| Field             | Type   | Description         |
| :---------------- | :----- | :------------------ |
| index             | number | interface index |
| mtu               | number | MTU. for loopback can be 64K or even 0xFFFFFFFF |
| flags             | number | os-specific bit flags |
| ssid              | string | wifi SSID if known. SSIDs are obtained only if `--filter-ssid` is used in any profile |
| guid<br>iftype<br>index6<br>speed_xmit<br>speed_recv<br>metric4<br>metric6<br>conntype<br> | number | (Windows only) additional fields from GetAdaptersAddresses() |
| addr              | table  | integer indexed array of addresses |

Address contents :

| Field        | Type   | Description         |
| :----------- | :----- | :------------------ |
| addr         | string | ipv4 or ipv6 address - raw string |
| netmask      | string | subnet mask - raw string |
| broadcast    | string | (ipv4 only) broadcast address - raw string |
| dst          | string | ifa_dstaddr from getifaddrs() - raw string |

Only "addr" field is always present. Others can be absent.


### Receiving and sending Packets

#### rawsend

```
function rawsend(raw_data[, rawsend_opts])
function rawsend_dissect(dissect[, rawsend_opts[, reconstruct_opts]])
```

- `rawsend` works with a raw string containing a fully assembled IPv4 or IPv6 packet.
- `rawsend_dissect` assembles a packet from a dissect and sends it.
- `dissect` refers to the table structure described in the corresponding section.

#### raw_packet

```
function raw_packet(ctx)
```

Upon invocation, Lua functions receive a ready-made dissect of the current packet. The raw representation is rarely required, so it is not provided to the desync engine by default to conserve resources.
It can be retrieved on demand using the `raw_packet` function.

### Working with payloads

#### Markers

- **Absolute positive marker** - a numeric offset within the payload.
- **Absolute negative marker** - a numeric offset within the payload relative to the byte following the end. -1 points to the last byte.
- **Relative marker** - a positive or negative offset relative to a logical position within the payload.

Relative positions:

- **method** - the start of the HTTP method ('GET', 'POST', 'HEAD', ...). The method is usually at position 0, but may shift due to `methodeol`, in which case the position may become 1 or 2.
- **host** - the start of the hostname.
- **endhost** - the byte following the last byte of the hostname.
- **sld** - the start of the second-level domain (SLD) in the hostname.
- **endsld** - the byte following the last byte of the second-level domain.
- **midsld** - the middle of the second-level domain.
- **sniext** - the start of the SNI extension data field in TLS. Any extension consists of 2-byte type and length fields, followed by the data field.
- **extlen** - the length field of TLS extensions.

Relative markers work with logical elements of specific known payloads and will not function with arbitrary data.

Example marker list: `100,midsld,sniext+1,endhost-2,-10`.

#### resolve_pos

The purpose of the following functions is to convert markers into absolute positions.

```
function resolve_pos(blob,l7payload_type,marker[,zero_based_pos])
function resolve_multi_pos(blob,l7payload_type,marker_list[,zero_based_pos])
function resolve_range(blob,l7payload_type,marker_list[,strict,zero_based_pos])
```

- `resolve_pos` works with a single marker. If the marker does not resolve, it returns `nil`.
- `resolve_multi_pos` works with a comma-separated list of markers. It returns an array of unique absolute positions. If some markers do not resolve, they will be omitted from the result.
- `resolve_range` resolves a list of exactly 2 markers representing a range within the payload. If `strict = true` and any marker fails to resolve, it returns `nil`. Otherwise, if the first marker fails to resolve, it is replaced with 0. If the second marker fails to resolve, it is replaced with the payload length. If both fail to resolve, it returns `nil`.
- If `zero_based_pos=true` is set, all positions start from 0; otherwise, they start from 1, as is standard in Lua.
- An `error` is raised for invalid values of `l7payload_type`, `marker`, `marker_list`, or if the number of markers for `resolve_range` is not equal to 2.

#### tls_mod

```
function tls_mod(blob, modlist[, payload])
```

- blob - the blob being acted upon
- payload - the content to which the blob is modified. For different mods payload can be arbitrary or a valid TLS is required.
- modlist - comma separated list of modifications
  
Mods :

- **rnd** - fill random and session id fields with random data
- **dupsid** - copy session id from payload. executaed after "rnd". requires valid TLS payload or not applied.
- **rndsni** - replace SNI with random domain. If length(original sni)>=7 chars, a random subdomain is generated from a random well known 3-letter TLD. Otherwise a random string matching regexp `[a-z][a-z0-9]*`
- **sni**=domain.com - replace SNI with specified domain
- **padencap** - Adjust the blob so that the payload becomes part of the padding extension. The payload can be arbitrary.


### Instance execution management

#### instance_cutoff

```
function instance_cutoff(ctx[, outgoing])
```

Voluntary self-cutoff of an instance for the specified direction.
The instance will no longer be called within the current flow.

- `outgoing = true` - outbound direction
- `outgoing = false` - inbound direction
- `outgoing = nil` - both directions

#### lua_cutoff

```
function lua_cutoff(ctx[, outgoing])
```

Similar to `instance_cutoff`, but the entire profile is cut off from the flow.
When the profile changes after obtaining a hostname or detecting the flow protocol, the `lua_cutoff` is reset, as the new profile contains a completely different set of instances that have not requested to be cut off.

A `lua_cutoff` state can also occur naturally if all instances have exceeded their upper range limit or have self-cutoff from the direction.

#### execution_plan

```
function execution_plan(ctx)
```

Returns an array of information about all subsequent, pending instances in the current profile, their in-profile filters, and arguments.

**Plan Element**

| Field          | Type   | Description                                                                                                                               |
| :------------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| func           | string | desync function name                                                                                                                      |
| func_n         | number | instance number within the profile                                                                                                        |
| func_instance  | string | instance name (derived from the function name, instance number, and profile number)                                                       |
| range          | table  | effective range of [counters](#in-profile-filters) `--in-range` or `--out-range` depending on the current direction                       |
| payload        | table  | effective payload filter : payload name indexed table.                                                                                |
| payload_filter | string | effective payload filter : a comma-separated list of payload names.                                                                    |
| arg            | table  | instance arguments |

**range**

| Field        | Type | Description                                               |
| :----------- | :--- | :-------------------------------------------------------- |
| from         | table| lower bound position                                      |
| to           | table| upper bound position                                      |
| upper_cutoff | bool | true = upper bound is exclusive, false = inclusive        |

**pos - from, to**

| Field | Type   | Description                         |
| :---  | :----- | :---------------------------------- |
| mode  | string | counter mode - a, x, n, d, b, s, p  |
| pos   | number | counter value                       |

#### execution_plan_cancel

```
function execution_plan_cancel(ctx)
```

A one-time cancellation of all subsequent instances within a profile.
The instance performing the cancellation takes over the coordination of further actions and is called the orchestrator.

### Timer control

Timer creation and deletion functions can be called from any Lua code.
This could be lua-init, lua-desync, or a timer function. A timer function can also act on itself, such as changing the period or terminating its own calls.

Timers are identified by a name. Multiple timers with different names can call the same timer function.
It will be passed the timer name and arbitrary data as parameters (#timer-function-prototype)

#### timer_set

Create or replace the timer.

```
function timer_set(name, func, period, oneshot, data)
```

* name - a unique timer name. If a timer with this name already exists, it is deleted and replaced with a new one. When replaced, the countdown restarts.
* func - the timer function name (string)
* period - the timer call frequency in milliseconds
* oneshot - a bool indicating whether the timer is single-shot (true) or periodic (false)
* data - an arbitrary variable passed to the [timer-function](#timer-function-prototype)

#### timer_del

Delete the timer.

```
function timer_del(name)
```

#### timer_info

Get information about the timer identified by name.

```
function timer_info(name)
```

Returns table in case of success, nil otherwise.


| Field   | Type   | Description  |
| :------ | :----- | :------------------ |
| name    | string | unique timer name |
| func    | string | timer function name |
| oneshot | bool   | true = single shot timer, false = periodic timer |
| period  | number | timer period in msec |
| fires   | number | number of timer calls made |


#### timer_enum

Get an array of unique names of all existing timers.

```
function timer_enum()
```



# zapret-lib.lua base function library

Nearly every function includes detailed comments regarding its purpose and parameters.
Reviewing the Lua code and comments will provide a better understanding of what a specific function does and how to call it.

## Base desync functions

These can be used directly in `--lua-desync`.

### luaexec

```
function luaexec(ctx, desync)
```

Executes arbitrary Lua code specified in the "code" argument.
The code can address the `desync` table-it is temporarily assigned to a global variable named `desync`, which is cleared once the code finishes executing.

Example: `--lua-desync=luaexec:code="desync.rnd=brandom(math.random(5,10))"`

### pass

```
function pass(ctx, desync)
```

Does nothing except output a "pass" message to the debug log.

### pktdebug

```
function pktdebug(ctx, desync)
```

Outputs the `desync` structure to the debug log.

### argdebug

```
function argdebug(ctx, desync)
```

Outputs the arguments table to the debug log.

### posdebug

```
function posdebug(ctx, desync)
```

Outputs information about the current conntrack positions for both outbound and inbound directions to the debug log.

### detect_payload_str

```
function detect_payload_str(ctx, desync)
```

- arg: `pattern` - the substring to search for within `desync.dis.payload`
- arg: `payload` - the value to assign to `desync.l7payload` if the substring is found
- arg: `undetected` - (optional) the value to assign to `desync.l7payload` if the substring is not found

Example of a basic protocol detector. It searches for a `pattern` in the payload; if found, it sets `desync.l7payload = desync.arg.payload`. Otherwise, if `desync.arg.undetected` is provided, it sets `desync.l7payload = desync.arg.undetected`.

Protocol detectors of this type have no effect on the underlying C code. The C implementation knows nothing about your custom protocol or payload type. Your value cannot be specified in the `--payload` parameter. However, it can be used with the [payload filters](#standard-payload) of many [desync functions](#zapret-antidpilua-dpi-attack-program-library).

### desync_orchestrator_example

```
function desync_orchestrator_example(ctx, desync)
```

A test orchestrator. It performs no special logic other than executing the original execution plan as-is.

## Utility functions

### var_debug

```
function var_debug(v)
```

Outputs information about the parameter `v` (type and value) to the debug log.
If the parameter is a table, the function recursively traverses nested values and tables, presenting the information as a tree structure.

### deepcopy

```
function deepcopy(orig)
```

Creates a copy of the `orig` variable.
Its primary purpose is to recursively create a copy of a table including all its sub-tables.
In Lua, tables are passed by reference. No matter which variable you use to modify a table, only one instance of that table exists; changes will be visible through all variables referencing it.
To create a true copy, you must initialize a new table and assign all fields from the source table to it, copying sub-tables recursively in the same manner. This is what the `deepcopy` function handles.

Simple types in Lua are assigned by value. All strings are stored in a single pool to prevent content duplication. String variables reference this pool. Strings are immutable; you can only assign a different string to a variable. If a new string has a unique value not present in the pool, a new pool entry is created; otherwise, a reference to the existing entry is assigned.

### logical_xor

```
function logical_xor(a,b)
```

Returns the result of a logical XOR between `a` and `b`. `result = a and not b or not a and b`

### array_search

```
function array_search(a, v)
function array_field_search(a, f, v)
```

Performs a linear search in table `a` for value `v`. `array_field_search` assumes that the elements of table `a` are themselves tables, and performs the search on field `f`.

## String operations

### in_list

```
function in_list(s, v)
```

### find_next_line

Checks whether string `v` is included in a comma-separated list of strings `s`. For example, `abc` is included in the list `xyz,abc,12345`.

```
function find_next_line(s, pos)
```

Works with multiline text `s`. Lines are separated by EOL characters - `\n` or `\r\n`.
Returns two values: the starting position of the current line and the starting position of the next line (or the end of the text `s` if no more lines remain).

## Raw string handling

### hex

```
function string2hex(s)
function has_nonprintable(s)
function make_readable(s)
function str_or_hex(s)
function hexdump(s, max)
function hexdump_dlog(s)
```

- `string2hex` converts a raw string into a character-based hex representation. Bytes are separated by spaces. `"\xAB\xCD\x01\x02"` => `"AB CD 01 02"`
- `has_nonprintable` returns `true` if string `s` contains characters other than 0x20–0x7F, `\n`, `\r`, or `\t`.
- `make_readable` replaces all characters except those in the 0x20–0x7F range with dots.
- `str_or_hex` returns the string itself if `has_nonprintable(s)` is `false`; otherwise, it returns `string2hex(s)`.
- `hexdump` converts the initial bytes of raw string `s` (up to `max` bytes) into a hex string plus the result of `make_readable`. This is a classic hex dump.
- `hexdump_dlog` performs a `hexdump` and outputs the result to the debug log.

### pattern

```
function pattern(pat, offset, len)
```

`pattern` represents a segment of an infinitely repeating raw string `pat`, starting at position `offset` (1-based indexing) with a length of `len`.

### blob

```
function blob(desync, name[, def])
function blob_or_def(desync, name[, def])
```

- `blob` is the standard function for retrieving a blob. If `name` starts with `0x`, the remainder is interpreted as a HEX string. Otherwise, the variable `name` is read first from `desync`. If not found there, it is taken from global variables. If it still cannot be found, the value `def` is used. If `name` is `nil` or an empty string, an error is raised.
- `blob_or_def` returns `def` if `name` is `nil`; otherwise, it behaves identically to `blob`.

```
function barray(a, packer)
function btable(a, packer)
```

- `barray` uses only numeric indices starting from 1. The order is preserved.
- `btable` uses all indices but does not guarantee order.

Packs elements of array `a` in ascending order of index from 1 to the last.
`packer` is a function that takes an element of `a` and returns a raw string.
For numeric arrays, [number packing functions](#bux) can be used as the `packer`.
Returns a raw string.

## TCP sequence number handling

```
function seq_ge(seq1, seq2)
function seq_gt(seq1, seq2)
function seq_lt(seq1, seq2)
function seq_le(seq1, seq2)
function seq_within(seq, seq_low, seq_hi)
function is_retransmission(desync)
```

- `seq_{ge|gt|lt|le}` performs a comparison of sequence numbers within a 2 GB range. If the difference is larger, the result will be incorrect. `ge` stands for `>=`, `gt` for `>`, `le` for `<=`, and `lt` for `<`.
- `seq_within` checks if `seq_low <= seq <= seq_hi`.
- `is_retransmission` checks if the current TCP dissection is a retransmission.

## Position handling

```
function pos_counter_overflow(desync, mode[, reverse])
function pos_get_pos(track_pos, mode)
function pos_get(desync, mode[, reverse])
function pos_check_from(desync, range)
function pos_check_to(desync, range)
function pos_check_range(desync, range)
function pos_range_str(range)
function pos_str(desync, pos)
```

The `mode` parameter contains a single-letter string representing the counter mode: 'a', 'x', 'n', 'd', 'b', 's', or 'p'.
By default, these functions operate on the current direction. If the `reverse` parameter is provided and set to `true`, the opposite direction is used.

- pos_counter_overflow - true if mode is 's' or 'p' and the relative TCP sequence has exceeded 2 GB. The counters can no longer be used.
- pos_get_pos - retrieve the value of the 'mode' counter from the `track_pos` table. `track_pos` can be `desync.track.pos.{direct,reverse,client,server}`.
- pos_get - retrieve the 'mode' counter value for the current or opposite direction.
- pos_check_from - check if the current position satisfies the lower bound of the range.
- pos_check_to - check if the current position satisfies the upper bound of the range.
- pos_range - check if the current position satisfies the range (both lower and upper bounds).
- pos_str - convert a position table `pos` into the standard string format `<mode><pos>`, for example, `s100`.
- pos_range_str - convert a range table into the standard string format `<mode_from><pos_from>(-|<)<mode_to><pos_to>`, for example, `d1-p5000`.

## Dissection

Dissection is the process of parsing a message to represent it in a structured format.

### dissect_url

```
function dissect_url(url)
```

Returns a table containing the parsed parts of a URL in the format `proto://creds@domain:port/uri`.
If any part is missing, the corresponding field will not be present in the table.

<details>
  <summary><b>Example of parsing `https://user:pass@domain.com:12345/my_uri/script.php?a=1&b=3`</b></summary>
<pre>
.proto
  string https
.creds
  string user:pass
.domain
  string domain.com
.port
  string 12345
.uri
  string /my_uri/script.php?a=1&b=3
</pre></details>

### dissect_nld

```
function dissect_nld(domain, level)
```

Retrieves a domain of a specific `level` from the `domain` string. For example, level=2 for 'www.microsoft.com' returns 'microsoft.com'.
If the specified level does not exist, it returns `nil`.

### dissect_http

```
function http_dissect_req(http)
function http_dissect_reply(http)
function http_reconstruct_req(hdis[, unixeol])
```

Parses an HTTP request or response. The `http` parameter is a multi-line string.
The parsed result is a table with nested sub-tables.
Headers provide the start and end positions for both the header name and the value itself.

To find a header by name use [array_field_search](#array_search) with field name "header_low" which contains header name in lower case.

The HTTP request reconstructor takes a parsed table and recreates the raw string. The `unixeol` parameter replaces the standard HTTP line ending (0D0A) with 0A. This is non-standard and will break almost all servers except for Nginx.

<details>
  <summary><b>Example of parsing an HTTP request `http://testhost.com/testuri`</b></summary>
<pre>
.uri
  string /test_uri
.headers
  .1
    .header
      string Content-Length
    .header_low
      string content-length
    .value
      string 330
    .pos_start
      number 43
    .pos_end
      number 61
    .pos_header_end
      number 56
    .pos_value_start
      number 59
  .2
    .header
      string Host
    .header_low
      string host
    .value
      string testhost.com
    .pos_start
      number 24
    .pos_end
      number 41
    .pos_header_end
      number 27
    .pos_value_start
      number 30
.method
  string GET
</pre></details>

<details>
  <summary><b>Example of parsing an HTTP response</b></summary>
<pre>
.code
  number 200
.headers
  .1
    .pos_header_end
      number 28
    .pos_value_start
      number 31
    .header
      string Content-Type
    .header_low
      string content-type
    .value
      string text/html
    .pos_start
      number 17
    .pos_end
      number 39
  .2
    .pos_header_end
      number 54
    .pos_value_start
      number 57
    .header
      string Content-Length
    .header_low
      string content-length
    .value
      string 650
    .pos_start
      number 41
    .pos_end
      number 59
</pre></details>

### dissect_tls

```
function tls_dissect(tls, offset, partialOK)
function tls_reconstruct(tdis)
```

Parsing and reconstruction of TLS. Capabilities of these functions:

1. Any TLS handshake without a TLS record (including Client/Server Hello). For example, data extracted from `desync.decrypt_data` in QUIC.
2. Any TLS records: Handshake, Certificate, Change Cipher Spec, and others.
3. Handshakes split across multiple TLS records (e.g., the result of `tpws --tlsrec`).
4. (Dissect only) Incomplete data blocks if `partialOK=true`. The system recovers as much as possible, though a full reassembly will not be feasible.
5. All handshakes are moved to a separate table. A dissection is performed for Client/Server Hello; others are kept as raw data fields.
6. TLS extensions from Client/Server Hello: server name, ALPN, supported versions, compress certificate, signature algorithms, delegated credentials, supported groups, EC point formats, PSK key exchange modes, key share, and QUIC transport parameters. Other extensions are not parsed and are kept as raw data fields.
7. If a record layer is present, reconstruction is performed according to the lengths of individual records. If the final segment does not fit, the TLS record is expanded to accommodate the remaining data.
8. If no changes are made, the dissect + reconstruct process yields binary-identical blobs.

The functions do not work with DTLS.

`tls_dissect` returns a table - a parsed raw TLS string starting from the specified `offset` (1-indexed). `reconstruct_dissect` returns the raw string of the assembled `tdis` parsing. In case of an error, `nil` is returned.

The simplest way to obtain a dissection sample is: `--payload=tls_client_hello --lua-desync=luaexec:code="var_debug(tls_dissect(desync.reasm_data))"`.
Then, initiate a TLS request.

<details>
  <summary><b>Example of a TLS dissection from a request to https://google.com</b></summary>
<pre>
.rec
  .1
    .ver
      number 769
    .type
      number 22
    .name
      string handshake
    .len
      number 512
    .encrypted
      boolean false
    .htype
      number 1
    .data
      string 01 00 01 FC 03 03 87 36 D1 0E 19 78 8F 8B 41 5E 05 74 92 EF E7 9D 3E 83 F3 9D F4 C4 C6 6C 3E DC 5A 8C EF FD BC B4 20 1C AF 31 7A EB D2 FD 8B 1F C6 E8 DB CF 02 28 93 C4 AE 13 E1 17 ED 62 D8 3D 2F DE 03 67 A1 1A 44 00 3C 13 02 13 03 13 01 C0 2C C0 30 00 9F CC A9 CC A8 CC AA C0 2B C0 2F 00 9E C0 24 C0 28 00 6B C0 23 C0 27 00 67 C0 0A C0 14 00 39 C0 09 C0 13 00 33 00 9D 00 9C 00 3D 00 3C 00 35 00 2F 01 00 01 77 FF 01 00 01 00 00 00 00 0F 00 0D 00 00 0A 67 6F 6F 67 6C 65 2E 63 6F 6D 00 0B 00 04 03 00 01 02 00 0A 00 16 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 10 00 0E 00 0C 02 68 32 08 68 74 74 70 2F 31 2E 31 00 16 00 00 00 17 00 00 00 31 00 00 00 0D 00 30 00 2E 04 03 05 03 06 03 08 07 08 08 08 1A 08 1B 08 1C 08 09 08 0A 08 0B 08 04 08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05 02 06 02 00 2B 00 05 04 03 04 03 03 00 2D 00 02 01 01 00 33 00 26 00 24 00 1D 00 20 E0 40 E1 0A BF AD 5B 08 48 16 E5 A6 A9 90 E4 28 A1 67 40 1F AF A4 7B 9B 0A F9 32 2A 01 95 8B 5D 00 15 00 AE 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
.handshake
  .1
    .dis
      .ver
        number 771
      .type
        number 1
      .name
        string client_hello
      .cipher_suites
        .1
          number 4866
        .2
          number 4867
        .3
          number 4865
        .4
          number 49196
        .5
          number 49200
        .6
          number 159
        .7
          number 52393
        .8
          number 52392
        .9
          number 52394
        .10
          number 49195
        .11
          number 49199
        .12
          number 158
        .13
          number 49188
        .14
          number 49192
        .15
          number 107
        .16
          number 49187
        .17
          number 49191
        .18
          number 103
        .19
          number 49162
        .20
          number 49172
        .21
          number 57
        .22
          number 49161
        .23
          number 49171
        .24
          number 51
        .25
          number 157
        .26
          number 156
        .27
          number 61
        .28
          number 60
        .29
          number 53
        .30
          number 47
      .compression_methods
        .1
          number 0
      .ext
        .1
          .type
            number 65281
          .name
            string renegotiation_info
          .data
            string 00
        .2
          .dis
            .list
              .1
                .name
                  string google.com
                .type
                  number 0
          .type
            number 0
          .name
            string server_name
          .data
            string 00 0D 00 00 0A 67 6F 6F 67 6C 65 2E 63 6F 6D
        .3
          .dis
            .list
              .1
                number 0
              .2
                number 1
              .3
                number 2
          .type
            number 11
          .name
            string ec_point_formats
          .data
            string 03 00 01 02
        .4
          .dis
            .list
              .1
                number 29
              .2
                number 23
              .3
                number 30
              .4
                number 25
              .5
                number 24
              .6
                number 256
              .7
                number 257
              .8
                number 258
              .9
                number 259
              .10
                number 260
          .type
            number 10
          .name
            string supported_groups
          .data
            string 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00 01 01 01 02 01 03 01 04
        .5
          .dis
            .list
              .1
                string h2
              .2
                string http/1.1
          .type
            number 16
          .name
            string application_layer_protocol_negotiation
          .data
            string 00 0C 02 68 32 08 68 74 74 70 2F 31 2E 31
        .6
          .type
            number 22
          .name
            string encrypt_then_mac
          .data
            string
        .7
          .type
            number 23
          .name
            string extended_master_secret
          .data
            string
        .8
          .type
            number 49
          .name
            string post_handshake_auth
          .data
            string
        .9
          .dis
            .list
              .1
                number 1027
              .2
                number 1283
              .3
                number 1539
              .4
                number 2055
              .5
                number 2056
              .6
                number 2074
              .7
                number 2075
              .8
                number 2076
              .9
                number 2057
              .10
                number 2058
              .11
                number 2059
              .12
                number 2052
              .13
                number 2053
              .14
                number 2054
              .15
                number 1025
              .16
                number 1281
              .17
                number 1537
              .18
                number 771
              .19
                number 769
              .20
                number 770
              .21
                number 1026
              .22
                number 1282
              .23
                number 1538
          .type
            number 13
          .name
            string signature_algorithms
          .data
            string 00 2E 04 03 05 03 06 03 08 07 08 08 08 1A 08 1B 08 1C 08 09 08 0A 08 0B 08 04 08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05 02 06 02
        .10
          .dis
            .list
              .1
                number 772
              .2
                number 771
          .type
            number 43
          .name
            string supported_versions
          .data
            string 04 03 04 03 03
        .11
          .dis
            .list
              .1
                number 1
          .type
            number 45
          .name
            string psk_key_exchange_modes
          .data
            string 01 01
        .12
          .dis
            .list
              .1
                .group
                  number 29
                .kex
                  string E0 40 E1 0A BF AD 5B 08 48 16 E5 A6 A9 90 E4 28 A1 67 40 1F AF A4 7B 9B 0A F9 32 2A 01 95 8B 5D
          .type
            number 51
          .name
            string key_share
          .data
            string 00 24 00 1D 00 20 E0 40 E1 0A BF AD 5B 08 48 16 E5 A6 A9 90 E4 28 A1 67 40 1F AF A4 7B 9B 0A F9 32 2A 01 95 8B 5D
        .13
          .type
            number 21
          .name
            string padding
          .data
            string 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      .session_id
        string 1C AF 31 7A EB D2 FD 8B 1F C6 E8 DB CF 02 28 93 C4 AE 13 E1 17 ED 62 D8 3D 2F DE 03 67 A1 1A 44
      .random
        string 87 36 D1 0E 19 78 8F 8B 41 5E 05 74 92 EF E7 9D 3E 83 F3 9D F4 C4 C6 6C 3E DC 5A 8C EF FD BC B4
    .type
      number 1
    .name
      string client_hello
    .data
      string 01 00 01 FC 03 03 87 36 D1 0E 19 78 8F 8B 41 5E 05 74 92 EF E7 9D 3E 83 F3 9D F4 C4 C6 6C 3E DC 5A 8C EF FD BC B4 20 1C AF 31 7A EB D2 FD 8B 1F C6 E8 DB CF 02 28 93 C4 AE 13 E1 17 ED 62 D8 3D 2F DE 03 67 A1 1A 44 00 3C 13 02 13 03 13 01 C0 2C C0 30 00 9F CC A9 CC A8 CC AA C0 2B C0 2F 00 9E C0 24 C0 28 00 6B C0 23 C0 27 00 67 C0 0A C0 14 00 39 C0 09 C0 13 00 33 00 9D 00 9C 00 3D 00 3C 00 35 00 2F 01 00 01 77 FF 01 00 01 00 00 00 00 0F 00 0D 00 00 0A 67 6F 6F 67 6C 65 2E 63 6F 6D 00 0B 00 04 03 00 01 02 00 0A 00 16 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 10 00 0E 00 0C 02 68 32 08 68 74 74 70 2F 31 2E 31 00 16 00 00 00 17 00 00 00 31 00 00 00 0D 00 30 00 2E 04 03 05 03 06 03 08 07 08 08 08 1A 08 1B 08 1C 08 09 08 0A 08 0B 08 04 08 05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04 02 05 02 06 02 00 2B 00 05 04 03 04 03 03 00 2D 00 02 01 01 00 33 00 26 00 24 00 1D 00 20 E0 40 E1 0A BF AD 5B 08 48 16 E5 A6 A9 90 E4 28 A1 67 40 1F AF A4 7B 9B 0A F9 32 2A 01 95 8B 5D 00 15 00 AE 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
</pre>
</details>

Successfully parsed elements are presented as `dis` subtables, while others remain as `raw data` fields.
Some elements include a `name` field for visual analysis purposes only; the `type` fields are the primary identifiers.

To locate values within lists, use the [array search functions](#array_search).

Numerous TLS-related constants are defined in `zapret-lib.lua`. Before hardcoding values, check if a suitable constant already exists.

The `handshake` table is indexed by handshake type. The most common types are `TLS_HANDSHAKE_TYPE_CLIENT` and `TLS_HANDSHAKE_TYPE_SERVER`. Since these have values 1 and 2 respectively, it might appear that handshake elements follow a sequential order starting from 1, but this is not the case.

Extensions and other lists are indexed numerically starting from 1 rather than by type. This is because their sequence matters and multiple elements of the same type may exist.

When adding custom data, you must reproduce the minimum required structure. You can choose to populate only the `raw data` field; if no `dis` subtable is present, this field will be used during reconstruction. If a `dis` subtable exists, it must be correctly populated according to the specific data element.

The following code example searches for the SNI extension within the `tdis` dissect. If missing, it inserts it at the beginning and then adds the domain "example.com".```

```
	local idx_sni = array_field_search(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, "type", TLS_EXT_SERVER_NAME)
	if not idx_sni then
		table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, 1, { type = TLS_EXT_SERVER_NAME, dis = { list = {} } } )
		idx_sni = 1
	end
	table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext[idx_sni].dis.list, { name = "example.com", type = 0 } )
```

## Working with L3 and L4 protocol elements

### find_tcp_options

```
function find_tcp_option(options, kind)
```

Returns the first element of `dis.tcp.options` with the specified `kind`. Returns `nil` if not found.

### ip6hdr

```
function find_ip6_exthdr(exthdr, proto)
```

Returns the first element of `dis.ip6.exthdr` where `type = proto`.

```
function insert_ip6_exthdr(ip6, idx, header_type, data)
function del_ip6_exthdr(ip6, idx)
function fix_ip6_next(ip6, last_proto)
```

### ip protocol

```
function ip_proto_l3(dis)
function ip_proto_l4(dis)
function ip_proto(dis)
```

Functions discover ip protocol of the end payload.

* ip_proto_l3 - ipv4 - ip.ip_p , ipv6 - ip6.ip6_nxt or next from the last extension header. nil, if next field is not set.
* ip_proto_l4 - IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6 depending on presence of tcp,udp,icmp,ip6. nil if tcp,udp,icmp are absent.
* ip_proto - ip_proto_l4. If it returned nil, then ip_proto_l3.

```
function fix_ip_proto(dis, proto)
```

Set end protocol as proto. If proto is not passed or nil - use result of "ip_proto(dis)".


### packet_len

These functions work with the IPv6 header dissect `ip6` and its extension headers (`ip6.exthdr`).
When inserting or deleting extension headers, the correct chain of subsequent protocols is maintained, starting from the base IPv6 header.

- `insert_ip6_exthdr` inserts an extension header with the protocol `header_type` and `data` into the `ip6` dissect at the specified index `idx`. If `idx=nil`, it is appended to the end. The `data` size must be 6+N*4 for `IPPROTO_AH` and 6+N*8 for others; otherwise, errors will occur during reconstruction.
- `del_ip6_exthdr` removes the extension header at the specified index `idx`.
- `fix_ip6_next` restores the correct chain of subsequent protocols using `ip6.ip6_nxt` and the `type` fields within `ip6.exthdr`.

```
function l3_base_len(dis)
function l3_extra_len(dis[, ip6_exthdr_last_idx])
function l3_len(dis)
function l4_base_len(dis)
function l4_extra_len(dis)
function l4_len(dis)
function l3l4_extra_len(dis)
function l3l4_len(dis)
function packet_len(dis)
```

Calculates the sizes of various dissect elements after reconstruction.

- `l3_base_len` – Base length of the IP/IPv6 header without options or extension headers.
- `l3_extra_len` – Length of IP options or the total length of all extension headers. If `ip6_exthdr_last_idx` is specified, it counts extension headers up to that index.
- `l3_len` – Total length of the IP/IPv6 header including options and extension headers.
- `l4_base_len` – Base length of the TCP or UDP header.
- `l4_extra_len` – Length of TCP options for TCP; 0 for UDP.
- `l4_len` – Total length of the TCP header with options, or the UDP header length.
- `l3l4_extra_len` – Sum of `l3_extra_len` and `l4_extra_len`.
- `l3l4_len` – Total length of IP/IPv6 and TCP headers, including all options and extension headers.
- `packet_len` – Total length of the reconstructed packet, including the L4 payload.

## Working with hostnames

### genhost

```
function genhost(len[, template])
```

Generates a random hostname of length `len`.

- If a `template` is provided, it generates a random subdomain to fit the specified `len`. If the length `len` is insufficient, it returns a left-truncated version of the template.
- If `template=nil`, it generates a random subdomain for one of the known 3-letter TLDs. If `len < 7`, it generates a random domain of length `len` without dots.

Examples:

```
-- template "google.com", len=16 : h82aj.google.com
-- template "google.com", len=11 : .google.com
-- template "google.com", len=10 : google.com
-- template "google.com", len=7 : gle.com
-- no template, len=6 : b8c54a
-- no template, len=7 : u9a.edu
-- no template, len=10 : jgha7c.com
```

### host_ip

```
function host_ip(desync)
function host_or_ip(desync)
```

- `host_ip` returns a string representation of `desync.target.ip` or `desync.target.ip6`.
- `host_or_ip` returns `desync.track.hostname` if both `track` and `track.hostname` exist; otherwise, it returns `host_ip(desync)`.

## File name and path operations

```
function is_absolute_path(path)
function append_path(path, file)
function writeable_file_name(filename)
```

- `is_absolute_path` returns true if the path starts from the root. It accounts for CYGWIN path specifics.
- `append_path` appends a file or directory name `file` to `path`, using '/' as a separator.
- `writeable_file_name` returns `filename` if it contains an absolute path or if the `WRITEABLE` environment variable is not set. Otherwise, it retrieves the path from the `WRITEABLE` environment variable and appends the `filename` using `append_path`.

## Reading and writing Files

```
function readfile(filename)
```

Reads the entire file. Throws an error if opening or reading the file fails.

```
function z_readfile(filename[, expected_ratio])
```

Automatically detects whether the file is gzipped. If so, it decompresses it; otherwise, it reads it as is. Throws an error if opening or reading the file fails.
`expected_ratio` is the expected ratio of decompressed data to compressed data (defaults to 4).

```
function writefile(filename, data)
```

Writes `data` to a file. Throws an error if opening the file fails.

## Data compression

```
function is_gzip_file(filename)
```

Returns true if the file is a gzip file, otherwise false. Throws an error if the file cannot be opened.

```
function gunzip_file(filename[, expected_ratio[, read_block_size]])
```

Decompresses a file and returns it as a raw string. Throws an error if opening or reading the file fails. Returns `nil` in case of memory exhaustion. `read_block_size` determines the chunk size for reading (defaults to 16K).
`expected_ratio` is the expected ratio of decompressed data to compressed data (defaults to 4).

```
function gzip_file(filename, data[, expected_ratio[, level[, memlevel[, compress_block_size]]]])
```

Compresses a raw string into a gzip file. Throws an error if opening or reading the file fails. Returns `nil` if the gzip data is corrupted or memory is exhausted.
`level` is the compression level from 1 to 9 (defaults to 9), `memlevel` is the allowed memory usage level from 1 to 8 (defaults to 8). `compress_block_size` is the chunk size for compression (defaults to 16K).
`expected_ratio` is the expected ratio of decompressed data to compressed data (defaults to 2).

## autottl

```
function parse_autottl(s)
function autottl(incoming_ttl, attl)
```

The `autottl` mechanism is used to automatically determine a TTL based on the incoming packet's TTL. The resulting TTL either falls slightly short of the destination or slightly exceeds the path length to it.
`delta` is the positive or negative difference relative to the estimated path length. `min-max` is the allowed range.
If the final result falls outside this range, the boundary values are assigned.
If `delta < 0` and the result is equal to or longer than the path, or if `delta >= 0` and the result is shorter than the path, the algorithm fails and returns `nil`.

Calculations are based on the assumption of symmetric inbound and outbound paths and the default TTLs used by major operating systems (64, 128, 255).
This heuristic is not always accurate due to these assumptions potentially being false, but it can sometimes be tuned to an acceptable margin of error.

- `parse_autottl` converts a string in the format `<delta>,<min>-<max>` into a table with identical fields. Throws an error if the format of `s` is invalid.
- `autottl` makes a heuristic guess about the hop length based on the TTL of incoming packets and calculates the TTL, taking into account the delta and the allowed range.
The `incoming_ttl` can be retrieved from `desync`. `attl` uses the table format obtained via `parse_autottl`.

## Operations with dissects

The following functions and transmission functions use standard option blocks, provided as fields in a separately passed table.
The options table follows the `desync.arg` format. `desync.arg` can be passed directly without modification.

### standard ipid

**ipid_options**

| Field      | Description                                                                                                                                  |
| :--------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| ip_id      | ip_id assignment mode: seq, rnd, zero, none<br>seq - sequential<br>rnd - random<br>zero - zero<br>none - do not change                       |
| ip_id_conn | remember the last generated seq value and start from it in the next packet. Does not work without desync.track                               |

The `seq` mode will not always result in the expected or acceptable sequence.
The `ip_id` setting is only applied within specific functions; it is not automatically applied to all passing packets.
Since the OS does not track modified `ip_id` values, the sequence may reset in packets that are left untouched.
Windows replaces zero `ip_id`s with its own sequence, whereas other operating systems do not.

On any OS, it is possible to maintain a continuous linear `ip_id` order for a period of time using a mix of original and generated packets. To achieve this, apply the `ip_id=seq:ip_id_conn` policy to all desync functions that support `ipid`. For other payloads, use a combination of [send](#send) instances with the same `ip_id` policy and [drop](#drop) within a limited [`--out-range`](#in-profile-filters) interval. This should not be done indefinitely, as it increases CPU overhead.

### standard fooling

**fooling_options**

| Field           | Description                                                                                                                                                                                                     |
| :-------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ip_ttl          | Set the TTL in the IPv4 header to the specified value.                                                                                                                                                          |
| ip6_ttl         | Set the Hop Limit (HL) in the IPv6 header to the specified value.                                                                                                                                               |
| ip_autottl      | Set the TTL in the IPv4 header automatically using the `delta,min-max` pattern. If the TTL cannot be determined, the `ip_ttl` value is used if provided; otherwise, the TTL remains unchanged.                  |
| ip6_autottl     | Set the Hop Limit (HL) in the IPv6 header automatically using the `delta,min-max` pattern. If the HL cannot be determined, the `ip6_ttl` value is used if provided; otherwise, the HL remains unchanged.        |
| ip6_hopbyhop    | Insert a "Hop-by-Hop Options" extension header. Defaults to 6 zeros, but a hex string can be specified. The length must be 6+N*8.                                                                               |
| ip6_hopbyhop2   | Insert a second "Hop-by-Hop Options" extension header.                                                                                                                                                          |
| ip6_destopt     | Insert a "Destination Options" extension header. Defaults to 6 zeros, but a hex string can be specified. The length must be 6+N*8.                                                                              |
| ip6_destopt2    | Insert a second "Destination Options" extension header.                                                                                                                                                         |
| ip6_routing     | Insert a "Routing Options" extension header. Defaults to 6 zeros, but a hex string can be specified. The length must be 6+N*8.                                                                                  |
| ip6_ah          | Insert an "Authentication Header" (AH) extension header. Defaults to 2 zeros and 4 random bytes, but a hex string can be specified. The length must be 6+N*4.                                                   |
| tcp_seq         | A positive or negative offset for the TCP Sequence Number.                                                                                                                                                      |
| tcp_ack         | A positive or negative offset for the TCP Acknowledgment Number.                                                                                                                                                |
| tcp_ts          | A positive or negative offset for the TCP Timestamp. This only functions if the Timestamp option is already present.                                                                                            |
| tcp_md5         | Add a TCP MD5 Signature header if it is not already present. Defaults to random bytes, but a 16-byte hex string can be specified.                                                                               |
| tcp_flags_set   | Set TCP flags. Flags are provided as a comma-separated list: FIN, SYN, RST, PUSH, ACK, URG, ECE, CWR.                                                                                                           |
| tcp_flags_unset | Clear (unset) TCP flags. Follows the same format as `tcp_flags_set`.                                                                                                                                            |
| tcp_ts_up       | Move the TCP Timestamp option to the very beginning of the options list, if present.                                                                                                                            |
| tcp_nop_del     | Delete all NOP TCP options to free space in the header                                                                                                                                                          |
| fool            | Name of the custom fooling function. It takes a dissect and a `fooling_options` table.                                                              |

IPv6 extension headers are added in the following order:

1. hopbyhop
2. hopbyhop2
3. destopt
4. routing
5. destopt2
6. ah

`tcp_ts_up` is a very strange phenomenon discovered during the testing of *nfqws2*.
It turns out that if a TCP timestamp option is present, Linux consistently drops packets with a valid SEQ but an invalid ACK-but only if the timestamp option comes first.
*nfqws1* did not respect the order of TCP options, resulting in the timestamp always being placed first.
Consequently, the old version worked stably, while the new one did not.
`tcp_ts_up` replicates the old behavior by moving the timestamp to the very top.

### standard ipfrag

The `ipfrag_options` contain only two standard parameters. The rest are handled by replaceable fragmenter functions, which have their own specific options.

**ipfrag_options**

| Field           | Description                                                                                                         |
| :-------------- | :------------------------------------------------------------------------------------------------------------------ |
| ipfrag          | Name of the fragmenter function. If not specified, `ipfrag2` is used. The fragmenter returns an array of dissects (fragments). |
| ipfrag_disorder | Send fragments in reverse order.                                                                                    |
| ipfrag_pos_udp  | (ipfrag2 fragmenter) UDP fragmentation position. Must be a multiple of 8; defaults to 8.                            |
| ipfrag_pos_tcp  | (ipfrag2 fragmenter) TCP fragmentation position. Must be a multiple of 8; defaults to 32.                           |
| ipfrag_next     | (ipfrag2 fragmenter) The "next protocol" type in the "fragment" extension header of the second fragment.            |

### apply_ip_id

```
function apply_ip_id(desync[, dis[, ipid_options[, def]]])
```

Applies the [ip_id policy](#standard-ipid) from `ipid_options` to the dissect `dis`.
If `dis` is `nil`, `desync.dis` is used.
If `ipid_options` is `nil`, `desync.arg` is used.
`def` contains the default assignment mode. If `nil`, "seq" is applied.

### apply_fooling

```
function apply_fooling(desync[, dis[, fooling_options]])
```

Applies a set of L3/L4 header modifications ([fooling](#standard-fooling)), as described in `fooling_options`, to the dissect `dis`.
If `dis` is `nil`, `desync.dis` is used.
If `fooling_options` is `nil`, `desync.arg` is used.

### ipfrag2

```
function ipfrag2(dis, ipfrag_options)
```

The standard fragmenter function. It returns an array of two fragment dissects derived from the original dissect `dis`.
It is invoked via `rawsend_dissect_ipfrag` if the `ipfrag` field is missing in `ipfrag_options`.
You are unlikely to need to call this function manually.
If you need to split IP packets differently, you can create your own fragmenter by analogy and specify it in `ipfrag_options`.

In the case of IPv6, the fragment header is inserted after all `hopbyhop`, `routing`, and the first `destopt` headers. This constitutes the "unfragmentable part."
The fragment header follows, and everything after it is considered the "fragmentable part."
The unfragmentable part is transmitted in every fragment with modified fragment header fields; the rest is sliced across the data block following the fragment header according to the fragment offset.

According to the standard, for IPv6 fragmentation, the "next protocol" is only read from the first fragment (where offset=0).
In subsequent fragments, it does not have to match and is ignored. Manipulating the "next protocol" field of subsequent fragments is a well-known penetration attack technique described in various security articles, allowing one to bypass certain firewalls.
`ipfrag2` implements this capability for two fragments via the `ipfrag_next` parameter.
Some firewalls can only be bypassed using a larger number of fragments-this would require a custom fragmenter function.

### wssize_rewrite

```
function wsize_rewrite(dis, arg)
```

Rewrite `dis.tcp.th_win` and the scale factor in TCP options within the dissect, if present. Increasing the scaling factor is blocked.

- arg: wsize - window size
- arg: scale - scale factor
- returns true if any changes were made

### dis_reverse

```
function dis_reverse(dis)
```

Swap the source and destination IP addresses and ports, as well as the seq and ack numbers.

## IP addresses and interfaces

```
function update_ifaddrs()
```

A wrapper around the C function [get_ifaddrs](#obtaining-ip-addresses). It may happen that you need to find the addresses on each packet.
Calling get_ifaddrs every time is CPU intensive. Addresses and interfaces rarely change.
update_ifaddrs() maintains the cache, which is updated no more than once per second.
The result is stored in the global variable "ifaddrs".

```
function ip2ifname(ip)
```

Get the name of the interface on which the IP address is present using the ifaddrs cache. nil if not found.


## Sending

The following functions can accept multiple blocks of the options described above, each represented by the `options` parameter field.
All functions utilize [options.reconstruct](#standard-reconstruct) and [options.rawsend](#standard-rawsend). These correspond to the parameter format of the C function [rawsend_dissect](#rawsend).

### rawsend_dissect_ipfrag

```
function rawsend_dissect_ipfrag(dis[, options])
```

Sends dissect `dis` with IP fragmentation as specified in `options.ipfrag`. If omitted, it is sent without fragmentation.
Uses a custom fragmenter function if `options.ipfrag.ipfrag` is provided.
Sends fragments in reverse order if `options.ipfrag.ipfrag_disorder` is specified.

### rawsend_dissect_segmented

```
function rawsend_dissect_segmented(desync[, dis[, mss[, options]]])
```

Sends dissect `dis` with automatic TCP segmentation based on MSS, applying `options.fooling` and `options.ipid`.
The `ipid` is applied to each fragment. Segmentation is not possible for UDP and is not performed.

- if dis is nil, desync.dis is used.
- if mss is nil, desync.tcp_mss is used.
- if options is nil, options are created from desync.arg

### rawsend_payload_segmented

```
function rawsend_payload_segmented(desync[, payload[, seq[, options]]])
```

Constructs a temporary dissect based on `desync.dis`, with optional payload replacement and optional `seq` offset, applying `options`, and sends it via `rawsend_dissect_segmented`.
The MSS is taken from `desync.tcp_mss`.
If `options` are missing, they are created based on `desync.arg`.

Standard `options` are formed as follows:

- `ipfrag`, `ipid`, and `fooling` take their values from `desync.arg`.
- `rawsend`: `repeats` is taken from `desync.arg.repeats`; `ifout` and `fwmark` are taken from `desync.arg` if present, otherwise from `desync` (the context passed to the desync function).
- `reconstruct`: only `desync.arg.badsum` is used; other options are ignored.

## Standard direction and payload filters

```
function direction_check(desync[, def])
function direction_cutoff_opposite(ctx, desync[, def])
```

The direction filter is a string ("in", "out", or "any") passed via `desync.arg.dir`. If the argument is missing, the `def` value is used.

- `direction_check` verifies if the current direction matches the filter.
- `direction_cutoff_opposite` performs an [instance cutoff](#instance_cutoff) on the current direction if it does not match the filter.

```
function payload_match_filter(l7payload[, l7payload_filter[, def]])
function payload_check(desync[, def])
```

These functions operate on a string representing a comma-separated list of [payloads](#protocol-detection). All empty packets have the payload `empty`, and unknown ones are `unknown`. Special values include `all` and `known`. `all` means any payload; `known` means anything that is not `unknown` or `empty`. A `~` prefix at the beginning denotes logical inversion (non-match).

- `payload_match_filter` checks if `l7payload` matches the `l7payload_filter` list, or `def` if `l7payload_filter` is `nil`. If both are `nil`, the list defaults to "known".
- `payload_check` calls `payload_match_filter(desync.l7payload, desync.arg.payload, def)`.

## Working with multi-packet payloads

Typically, operations are performed on the entire [reasm](#handling-multi-packet-payloads) rather than its individual parts. This is the purpose of reassembly: to avoid dealing with separate packets and instead process the entire message at once.

The standard scenario involves processing after receiving the first part of a [replay](#handling-multi-packet-payloads) and either ignoring or dropping the remaining parts. The choice between ignoring or dropping may depend on the success of actions involving [reasm](#handling-multi-packet-payloads). For example, whether or not a segmented [reasm](#handling-multi-packet-payloads) was successfully sent. If successful, all other parts must be dropped; otherwise, they will be sent as duplicates in the original segmentation. If an error occurs and the segmented packets could not be sent, dropping the rest would prevent the full message from reaching the recipient, leading to retransmissions. In such cases, it is better to leave them as is - this way nothing breaks.

```
function replay_first(desync)
function replay_drop_set(desync, v)
function replay_drop(desync)
```

- `replay_first` returns true if the current dissect is not a [replay](#handling-multi-packet-payloads) or is its first part.
- `replay_drop_set` marks a boolean flag `v` in `desync.track.lua_state` indicating whether subsequent parts of a [replay](#handling-multi-packet-payloads) should be dropped.
- `replay_drop` returns true if the current part of the [replay](#handling-multi-packet-payloads) needs to be dropped. If the part is the last one, it automatically clears the flag.

These functions work correctly with both [replays](#handling-multi-packet-payloads) and regular dissects. For regular dissects, `replay_first` is always true, `replay_drop_set` does not change the flag, and `replay_drop` is always false.

## Timer helpers

```
function dis_timer_name(dis)
```

Construct timer name based on ip src and dst addresses, l4 protocol name, port numbers or icmp codes.
May not be unique.

```
function desync_timer_name(desync)
```

Construct timer name that includes dis_timer_name result + conntrack packet number.
If track is absent random characters are added to the end.
This name can be considered unique per desync and can be used as an oneshot timer name.

## Orchestration

This group includes functions that support the orchestration and shimming processes.
Shims are duplicates of C code functions for situations where we lack the `ctx` context required to communicate with the C code.
Once orchestration begins, all subsequent instances are called by the orchestrator or nested orchestrators.
The last available `ctx` is the one from the primary orchestrator. If this `ctx` is passed to other instances, they will act on behalf of the orchestrator rather than themselves; therefore, `ctx=nil` should be passed to them.
After an [execution plan](#execution_plan) is canceled, the C code stops servicing subsequent instances and does not provide a `ctx` for them. Consequently, if execution needs to continue in the standard style, duplicate mechanisms for [instance cutoff](#instance_cutoff) and range/payload filters are required.

To ensure `--lua-desync` functions work transparently under orchestration, standard shims must be used instead of direct C function calls that require a `ctx`. For nested orchestrators to function correctly, you must follow the standard scheme of storing the [execution plan](#execution_plan) in `desync.plan` and use the helper functions described below.

It may be difficult to understand how orchestration works from a dry description alone. It is recommended to study the code of actual orchestrators and use this description to clarify the meaning of specific actions.

### instance_cutoff_shim

```
function instance_cutoff_shim(ctx, desync[, dir])
```

Performs a standard [instance cutoff](#instance_cutoff) in the direction `dir` if `ctx` is present; otherwise, it performs the cutoff via a duplicate mechanism whose state is stored in `desync.track.lua_state`. `dir = true` for the outgoing direction, `dir = false` for incoming, and `dir = nil` for both directions.

### cutoff_shim_check

```
function cutoff_shim_check(desync)
```

Checks the [instance cutoff](#instance_cutoff) state for `desync.func_instance` in the `desync.outgoing` direction.

### apply_arg_prefix

```
function apply_arg_prefix(desync)
```

Performs substitution of argument values from `desync.arg` that start with `%`, `#`,  `\`.
Multiple calls are safe but do not update desync.arg if blobs were changed.

### apply_execution_plan

```
function apply_execution_plan(desync, instance)
```

Copies the instance identification and its arguments from an [execution plan](#execution_plan) `instance` into the desync object, thereby recreating the desync state as if the `instance` were called directly by C code.
With one exception : apply_arg_prefix is not applied because args can refer a blob created by previous conditionally executed instances.

The [execution plan](#execution_plan) is provided by the C function `execution_plan()` as an array of `instance` elements.

### verdict_aggregate

```
function verdict_aggregate(v1, v2)
```

Aggregates verdicts v1 and v2. VERDICT_MODIFY overrides VERDICT_PASS, while VERDICT_DROP overrides both.

### plan_instance_execute

```
function plan_instance_execute(desync, verdict, instance)
function plan_instance_execute_preapplied(desync, verdict, instance)
```

Executes an [execution plan](#execution_plan) `instance`, taking into account the [instance cutoff](#instance_cutoff) and standard [payload](#in-profile-filters) and [range](#in-profile-filters) filters.
Calls apply_arg_prefix right before calling the instance.
Returns the aggregation of the current verdict and the `instance` verdict.

The "preapplied" version does not apply execution plan, allowing the calling code to do so.
Sometimes, to decide whether to call an instance, you need a desync table configured for the called instance.
"preapplied" version allows to avoid double copying.

### plan_instance_pop

```
function plan_instance_pop(desync)
```

Retrieves, removes, and returns the first element of the [execution plan](#execution_plan) from `desync.plan`. Returns `nil` if there are no elements.

### plan_clear

```
function plan_clear(desync, max)
```

Clears up to the "max" instances if "max" is defined or the whole [execution plan](#execution_plan) in `desync.plan`.

### orchestrate

```
function orchestrate(ctx, desync)
```

If the orchestrator is the primary one (i.e., `ctx` is present), it retrieves the [execution plan](#execution_plan), places it into `desync.plan`, and then executes `execution_plan_cancel()`.
If `ctx=nil`, it does nothing, assuming the plan is already in `desync.plan`.

### replay_execution_plan

```
function replay_execution_plan(desync, max)
```

Executes up to the "max" instances if "max" is defined, or the entire [execution plan](#execution_plan) from `desync.plan`, respecting the [instance cutoff](#instance_cutoff) and standard [payload](#in-profile-filters) and [range](#in-profile-filters) filters.

# zapret-antidpi.lua DPI attack program library

## Standard parameter sets

Many functions accept standard sets of arguments classified by their purpose.

Additional filters for direction and payload within the anti-DPI functions are primarily implemented as a safety measure against poorly written command-line options. This "foolproof" protection ensures it is difficult to accidentally trigger flooding, as happened in winws1 with the `--dpi-desync-any-protocol` option.

Another goal is to enable filtering for protocols that the C code is unaware of and that are detected by Lua detectors, such as [detect_payload_str](#detect_payload_str).

By default, nfqws2 blocks incoming traffic (`--in-range=x`), allows unlimited outgoing traffic (`--out-range=a`), and passes all payloads (`--payload=all`), which matches the behavior of nfqws1 with the `--dpi-desync-any-protocol` option. In nfqws1, all attacks were hardcoded into the C code, so it was known which techniques worked with which payloads. Some required any packets (including empty ones), while others required only TLS Hellos or HTTP requests.

nfqws2 has no knowledge of what `--lua-desync` functions require. Therefore, filtering by direction and payload type is entirely your responsibility. By default, only incoming traffic is blocked because it is rarely used; if the user fails to specify a restriction, all traffic would be passed to Lua functions, unnecessarily taxing the CPU with gigabytes of downloaded data.

### standard direction

Direction filter. In most functions using a direction filter, the default value is "out", though some default to "any". Direction filtering can also be implemented using C code via [`--in-range` and `--out-range`](#in-profile-filters).

**standard direction**

| Field | Description                                                                 |
| :---- | :-------------------------------------------------------------------------- |
| dir   | in - incoming direction<br> out - outgoing direction<br>any - any direction |

### standard payload

The payload filter accepts a list of [payload types](#protocol-detection). All empty packets are assigned the `empty` payload type, while unrecognized ones are labeled `unknown`. Special values include `all` and `known`: `all` matches any payload, while `known` matches anything that is neither `unknown` nor `empty`.

**standard payload**

| Field   | Description                                                                          |
| :------ | :----------------------------------------------------------------------------------- |
| payload | A comma-separated list of allowed payloads. A leading `~` indicates inversion (NOT). |

## Base functions

### drop

```
function drop(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- By default, `payload=all` and `direction=any`, meaning it drops everything.

Issues a `VERDICT_DROP` if the filter conditions are met.

### send

```
function send(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: delay - packet send delay in msec
- Default `ip_id` mode is `none`.

Sends the current dissect with optional modifications applied.
If delay is specified function returns VERDICT_DROP. Packet data and send options are remembered. After specified time packet is sent out.


### pktmod

```
function pktmod(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)

Applies modifications to the current dissect without sending it or issuing a verdict.

## HTTP fooling

### http_hostcase

```
function http_hostcase(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: spell - the exact spelling of the header. Defaults to "host".

Changes the case of the `Host:` HTTP header.

### http_domcase

```
function http_domcase(ctx, desync)
```

- arg: [standard direction](#standard-direction)

Changes the case of the domain within the `Host:` header. The case alternates for every character: `rUtRaCkEr.oRg`.

### http_methodeol

```
function http_methodeol(ctx, desync)
```

- arg: [standard direction](#standard-direction)

Inserts `\r\n` before the method, stripping the last two characters from the `User-Agent:` header content. This only works with Nginx; it breaks other servers.
If used with other http tampering functions should be the last !

### http_unixeol

```
function http_unixeol(ctx, desync)
```

- arg: [standard direction](#standard-direction)

Replaces the `0D0A` line endings with `0A`. The difference in length is compensated for by adding spaces to the end of the `User-Agent` header. This only works with Nginx; it breaks other servers.

## Window size replacement

### wsize

```
function wsize(ctx, desync)
```

- arg: wsize - TCP window size.
- arg: scale - scaling factor. Replaced in the TCP option if present. Only reduction is allowed; increasing the factor is blocked.

Changes `tcp.th_win` and/or the scaling factor in the TCP SYN,ACK packet, then executes an [instance cutoff](#instance_cutoff). If the modification is successful, it sets `VERDICT_MODIFY`.

The goal of this technique is to spoof the window size from the client or server side so that the peer responds by sending the next packet in parts, as the full packet would not fit into the spoofed window size. This may lead to performance slowdowns. This is an obsolete technique; it is recommended to use it only from the server side as a last resort for clients that do not employ any other bypass methods. From the client side, TCP segmentation techniques are preferred as they avoid speed penalties and offer more flexibility.

### wssize

```
function wssize(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: wsize - TCP window size.
- arg: scale - scaling factor. Replaced in the TCP option if present. Only reduction is allowed; increasing the factor is blocked.
- arg: forced_cutoff - a comma-separated list of payload types that trigger an [instance cutoff](#instance_cutoff) upon receipt. If `wssize` needs to be applied indefinitely, you can set `forced_cutoff=no` (using a non-existent payload type that will never occur).

Modifies `tcp.th_win` and/or the scaling factor in TCP options for all TCP packets in the flow's direction until the "cutoff" condition is met.
If a modification is performed, it returns `VERDICT_MODIFY`.
The "cutoff" occurs upon receiving any packet with data (if the `forced_cutoff` argument is not specified) or upon receiving one of the payloads specified in the `forced_cutoff` argument.
In this case, [instance cutoff](#instance_cutoff) is executed.

The goal of this technique is to force the server to fragment its responses while the DPI is inspecting them (TLS 1.2).
The idea is to keep the server "on its toes" by making it believe the client cannot receive large TCP segments, forcing it to slice its own responses-but only until the critical inspection phase has passed.
After that, the restriction must be lifted; otherwise, it will lead to a catastrophic drop in speed, potentially down to dial-up levels.
It reduces speed in any case. This is a phase-zero technique; when used with hostlists, it can only be applied if `--ipcache-hostname` is enabled.
When using hostlists, it may be necessary to duplicate this in a separate profile that is activated before the hostname is identified.
In this case, it will always be applied without checking the hostlist and will always reduce speed.
Typical parameters: `wsize=1:scale=6`. Recommended for use only when no alternatives are available.

## Fakes

Fakes are individual packets containing false information that the DPI should accept, but the server should not.
Fakes can be direct or hidden.
Direct fakes are standalone packets, while hidden fakes are part of original modified packets or groups of packets.

Direct fakes always require some form of header distortion so that the payload does not reach the server application; otherwise, it will break the connection. Without [fooling](#standard-fooling), a fake must replicate part of the original information to prevent the server from receiving false data.
Hidden fakes are ignored by the server due to the characteristics of the packets they are part of.

### syndata

```
function syndata(ctx, desync)
```

- arg: [standard fooling](#standard-fooling)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: blob - a [blob](#passing-blobs) containing the fake payload. It must fit into a single packet; segmentation is not possible.
- arg: tls_mod - apply the specified [tls_mod](#tls_mod) to the blob payload.

The function adds a payload to the TCP SYN packet, applies modifications to it, and sends it instead of the original, issuing a `VERDICT_DROP`.
If a non-SYN packet passes through, [instance cutoff](#instance_cutoff) is executed.
Thus, the manipulation is performed on all SYN retransmissions, after which the function stops.
It is a phase-zero strategy that works with hostlists only in `--ipcache-hostname` mode.

### tls_client_hello_clone

```
function tls_client_hello_clone(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: blob - the name of the blob that receives the result
- arg: fallback - the name of the blob to be copied to the result if the payload is of the wrong type or invalid
- arg: sni_del_ext - delete the SNI extension; other parameters are ignored
- arg: sni_del - delete all hosts
- arg: sni_snt - replace the "server name type" field for all existing hosts
- arg: sni_snt_new - the "server name type" field for newly added hosts
- arg: sni_first - add a host to the beginning of the list
- arg: sni_last - add a host to the end of the list

Prepares a blob with the specified name in the desync table, filled with the result of modifying the current [reasm](#handling-multi-packet-payloads).
Works only with TCP and the `tls_client_hello` payload. If an SNI modification is specified and the SNI extension is missing, it is added to the beginning of the extensions list.

Order of operations:

1. sni_del_ext. All other SNI operations become irrelevant and will not be executed.
2. sni_del
3. sni_snt
4. sni_first
5. sni_last

This function does not affect traffic by itself; it only prepares data for other functions.

### fake

```
function fake(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: blob - a blob containing the fake payload. It can be of any length-segmentation is performed automatically.
- arg: optional - abort the operation if the blob is missing.
- arg: tls_mod - apply the specified [tls_mod](#tls_mod) to the blob payload.
- default payload filter - "known"

This is a direct fake-a separate packet or group of packets. The function does not issue a verdict and does not block the transmission of the original packet.

### rst

```
function rst(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: rstack - send RST,ACK instead of RST.
- default payload filter - "known"

Sends an empty TCP packet with RST or RST+ACK flags. The function does not issue a verdict and does not block the transmission of the original packet.

## TCP segmentation

### multisplit

```
function multisplit(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a comma-separated list of [markers](#markers) representing split points. Defaults to "2".
- arg: seqovl - a number representing the offset relative to the current sequence to create an additional segment part that extends to the left beyond the TCP window boundary.
- arg: seqovl_pattern - the [blob](#passing-blobs) used to fill the seqovl. Defaults to 0x00.
- arg: blob - replace the current payload with the specified [blob](#passing-blobs).
- arg: optional - abort the operation if a blob is specified but missing. If seqovl_pattern is specified but missing, use the 0x00 pattern.
- arg: nodrop - do not issue a VERDICT_DROP.
- default payload filter - "known"

Multisplit implements sequential segmentation of the current dissect or [reassembly](#handling-multi-packet-payloads) with splits at positions defined by the [marker](#markers) list. It optionally supports replacing a data block with an arbitrary [blob](#passing-blobs) and the seqovl technique.
A VERDICT_DROP is issued after all segments are successfully sent, unless "nodrop" is specified.

If [replaying](#handling-multi-packet-payloads) delayed packets and [reassembly](#handling-multi-packet-payloads) is present, desync.reasm_data is used instead of desync.dis.payload. Splitting occurs only during the replay of the first part of the [reassembly](#handling-multi-packet-payloads); for the remaining parts, a VERDICT_DROP is issued if the transmission was successful and "nodrop" is not specified. Since the entire [reassembly](#handling-multi-packet-payloads) has already been sent in segments, there is no need to re-send its original parts.

It can be used to send arbitrary data, including fakes, by replacing the current payload with an arbitrary blob.

There is no need to worry about part sizes or MTU fitting-additional automatic segmentation by MSS is applied.

seqovl can only be a number; markers are not supported. It is applied to the first segment being split. The seqovl_pattern is prepended to the first segment's payload according to the seqovl size, and tcp.th_seq is decreased by seqovl. This creates a data block on the left that extends beyond the TCP window, causing the server to ignore it, while the part within the TCP window is accepted.

seqovl is essentially a method for interleaving fake and real data, a tool for creating hidden fakes within real TCP segments. If a DPI does not track sequence numbers, it may ingest the entire transmitted segment and fall for the false information at the beginning, which the server will not actually accept.

A particular advantage of seqovl is that it eliminates the need for [fooling](#standard-fooling). The server accepts only a portion of the segment by manipulating sequence numbers, rather than by modifying IP or TCP header elements, which could lead to total rejection.

### multidisorder

```
function multidisorder(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a comma-separated list of [markers](#markers) - split points. Default is "2".
- arg: seqovl - marker - an offset relative to the current sequence to create an additional part of the segment extending to the left.
- arg: seqovl_pattern - the [blob](#passing-blobs) used to fill the seqovl. Default is 0x00.
- arg: blob - replace the current payload with the specified [blob](#passing-blobs).
- arg: optional - skip the operation if a blob is specified but missing. If seqovl_pattern is specified but missing, use the 0x00 pattern.
- arg: nodrop - disable issuing a VERDICT_DROP.
- default payload filter - "known"

Similar to [multisplit](#multisplit), but segments are sent in reverse order-from the last to the first.

The seqovl technique works differently in this case. It is applied to the second segment in the original sequence (the penultimate one sent). seqovl can be a marker. For example, you can set a split at "midsld" and set seqovl to "midsld-1". seqovl must be smaller than the first segment in the original sequence (the last one sent); otherwise, the condition is recognized as invalid and seqovl is cancelled.

The purpose of seqovl in the disorder variant is to rewrite the socket buffer on the receiving end. A TCP socket delivers data to the application sequentially, in the order of its original transmission. If a "forward" segment arrives first that does not form a continuous sequence with already accepted data, the information is held in the buffer without being released to the application. If an overlapping sequence segment arrives later, the information from it overwrites what is already in the buffer. All systems behave this way except for Windows; therefore, this technique does not work on Windows servers. Windows preserves the old information.

A seqovl_pattern of size seqovl (the result of marker resolution) is prepended to the penultimate segment sent (the 2nd in the original order), and tcp.th_seq is decreased by seqovl.

The last segment sent (the 1st in the original order) is sent unchanged, overwriting the fake data from the seqovl_pattern in the socket buffer with real data. The continuous stream sequence is restored, and the data is passed to the application socket.

### multidisorder_legacy

```
function multidisorder_legacy(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a comma-separated list of [markers](#markers) - split points. Default is "2".
- arg: seqovl - marker - an offset relative to the current sequence to create an additional part of the segment extending to the left.
- arg: optional - skip the operation if a blob is specified but missing. If seqovl_pattern is specified but missing, use the 0x00 pattern.
- arg: seqovl_pattern - the [blob](#passing-blobs) used to fill the seqovl. Default is 0x00.

A multidisorder implementation fully compatible with nfqws1.

The new multidisorder works with the entire [reasm](#handling-multi-packet-payloads) (reassembly), whereas the legacy nfqws1 version works with individual [replay](#handling-multi-packet-payloads) segments. Consequently, the sequence of parts will differ when handling multi-packet requests.

In the new version, the original segmentation is not preserved. If any split segment exceeds the MSS, it is further divided by the MSS and sent in ascending sequence order. In the legacy version, the original segmentation was preserved. Split points were normalized based on the offset of each individual [reasm](#handling-multi-packet-payloads) part. Segments were sent in reverse order only within each part, while the subsequent part followed with its original sequence increment. Similarly, seqovl was normalized and applied only within the original segment where the normalized position was located.

### fakedsplit

```
function fakedsplit(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a single [marker](#markers) acting as the split point. Defaults to "2".
- arg: seqovl - numeric value - an offset relative to the current sequence to create an additional segment part that extends to the left of the TCP window boundary.
- arg: seqovl_pattern - the [blob](#passing-blobs) used to fill the seqovl. Defaults to 0x00.
- arg: blob - replaces the current payload with the specified [blob](#passing-blobs).
- arg: optional - skip the operation if the blob is specified but missing. If seqovl_pattern is specified but missing, use the 0x00 pattern.
- arg: nodrop - prevents issuing a VERDICT_DROP.
- arg: nofake1, nofake2, nofake3, nofake4 - skip sending specific fake packets.
- arg: pattern - the [blob](#passing-blobs) used to fill the fake segments. Defaults to 0x00.
- Default payload filter: "known"

The function operates similarly to multisplit with a single split point, but it interleaves fake packets between real segments. Fake packets match the size of the segments being sent and are generated based on a pattern with an offset corresponding to the TCP sequence offset of the segment relative to the first one.
Fake packets require [fooling](#standard-fooling) to ensure they are not accepted by the server.

Transmission sequence:

1. Fake of the 1st part. (fake1)
2. Real 1st part.
3. Fake of the 1st part. (fake2)
4. Fake of the 2nd part. (fake3)
5. Real 2nd part.
6. Fake of the 2nd part. (fake4)

The purpose of this technique is to confuse the DPI regarding which data is original and which is fake. Since the segments are identical in size - one containing junk and the other containing real data - the DPI cannot determine which to process. Both appear as retransmissions with identical sequences and sizes.

- Only `fooling_opts.tcp_ts_up` is applied to the original segments; `reconstruct_opts` are not used.
- Both `fooling_opts` and `reconstruct_opts` are applied in full to the fake segments.
- `ipid_opts` and `rawsend_opts` are applied to both fakes and originals. `ipfrag_opts` are not used for either fakes or originals.

If the transmission is successful, a VERDICT_DROP is issued unless "nodrop" is specified.
The [blob](#passing-blobs) parameter allows replacing the current payload with an arbitrary [blob](#passing-blobs), enabling the transmission of any compatible payload using the same segmentation.

### fakeddisorder

```
function fakeddisorder(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a single [marker](#markers) - the split point. Defaults to "2".
- arg: seqovl - [marker](#markers) - offset relative to the current sequence to create an additional segment part extending to the left.
- arg: seqovl_pattern - [blob](#passing-blobs) used to fill the seqovl. Defaults to 0x00.
- arg: blob - replace the current payload with the specified [blob](#passing-blobs).
- arg: optional - abort the operation if a blob is specified but missing. If seqovl_pattern is specified but missing, use the 0x00 pattern.
- arg: nodrop - skip issuing a VERDICT_DROP.
- arg: nofake1, nofake2, nofake3, nofake4 - skip sending specific fake packets.
- arg: pattern - [blob](#passing-blobs) used to fill the fake segments. Defaults to 0x00.
- default payload filter - "known"

This function operates similarly to multidisorder with a single split point, but it intersperses fake segments among the real ones. The fakes match the size of the transmitted parts and are generated based on the pattern, with an offset corresponding to the TCP sequence offset of the transmitted part relative to the first one.
[Fooling](#standard-fooling) is required for fakes to prevent them from being accepted by the server.

Transmission sequence:

1. Fake of the 2nd part. (fake1)
2. Real 2nd part.
3. Fake of the 2nd part. (fake2)
4. Fake of the 1st part. (fake3)
5. Real 1st part.
6. Fake of the 1st part. (fake4)

In addition to confusing the DPI with real and fake segments, the sequence itself is also obfuscated.

- Only fooling_opts.tcp_ts_up is applied to the originals. reconstruct_opts are not applied.
- fooling_opts and reconstruct_opts are applied to the fakes in full.
- ipid_opts and rawsend_opts are applied to both fakes and originals. ipfrag_opts are not used for either fakes or originals.

If the transmission is successful, a VERDICT_DROP is issued unless "nodrop" is specified.
The [blob](#passing-blobs) option allows replacing the current payload with an arbitrary [blob](#passing-blobs), thereby sending any compatible payload using the same splitting logic.

### hostfakesplit

```
function hostfakesplit(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: host - template for [fake host generation](#genhost) - random.template
- arg: midhost - [marker](#markers) for an additional split of the segment containing the real host.
- arg: disorder_after - [marker](#markers) for an additional split of the final real part and sending segments in reverse order.
- arg: nofake, nofake2 - skip sending specific fake packets.
- arg: blob - replace the current payload with the specified [blob](#passing-blobs).
- arg: optional - abort the operation if the blob is specified but missing.
- arg: nodrop - skip issuing a VERDICT_DROP.
- default payload filter - "known"

This is a specialized "splitter" that intersperses fakes for payloads containing a hostname, such as http_req and tls_client_hello.
The two primary split points are the beginning of the hostname - the [marker](#markers) "host" - and the end of the hostname - the [marker](#markers) "endhost". Additional optional split points include the [marker](#markers) midhost (must be within the host..endhost range) and the [marker](#markers) disorder_after (must be greater than endhost). When splitting by disorder_after, the parts are sent in reverse order.
[Fooling](#standard-fooling) is required for fakes to prevent them from being accepted by the server.

Transmission sequence:

1. Real part before host
2. Fake host..endhost-1 (fake1)
3. Real part host..endhost, or 2 parts: host..midhost-1, midhost..endhost-1
4. Fake host..endhost-1 (fake2)
5. Real part after host, or 2 parts: disorder_after..-1, endhost..disorder_after-1

- Only `fooling_opts.tcp_ts_up` is applied to originals. `reconstruct_opts` are not applied.
- `fooling_opts` and `reconstruct_opts` are applied in full to fakes.
- `ipid_opts` and `rawsend_opts` apply to both fakes and originals. `ipfrag_opts` are not used for either fakes or originals.

In case of successful transmission, a `VERDICT_DROP` is issued unless "nodrop" is specified.
The [blob](#passing-blobs) allows replacing the current payload with an arbitrary [blob](#passing-blobs), thereby sending any compatible payload with the same splitting.

### tcpseg

```
function tcpseg(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: pos - a list of two [markers](#markers) defining the boundaries of the TCP segment
- arg: seqovl - a number representing the offset relative to the current sequence to create an additional segment part that extends to the left beyond the TCP window boundary
- arg: seqovl_pattern - a [blob](#passing-blobs) used to fill the seqovl. Defaults to 0x00
- arg: blob - replace the current payload with the specified [blob](#passing-blobs)
- arg: optional - skip the operation if a blob is specified but missing. If `seqovl_pattern` is specified but missing, use the 0x00 pattern.
- default payload filter - "known"

Sends a part of the current dissect, [reasm](#handling-multi-packet-payloads), or an arbitrary blob, limited by two `pos` [markers](#markers) with optional application of the `seqovl` technique in the same way as in [multisplit](#multisplit). Additional segmentation is performed automatically if the MSS is exceeded.

In the case of [reasm](#handling-multi-packet-payloads), it only works when receiving its first part (as it operates on the reasm as a whole, not its individual parts).

No verdict is issued.

Using `tcpseg`, you can perform `seqovl` without segmentation by using markers "0,-1". To replace the current dissect, it can be combined with `drop`.

### oob

```
function oob(ctx, desync)
```

- arg: [standard fooling](#standard-fooling)
- arg: [standard ipid](#standard-ipid)
- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: char - one OOB character
- arg: byte - one OOB byte 0..255
- arg: urp - urgent pointer [marker](#markers), "b" or "e". "b" is default.

Function intercepts TCP handshake shifting sequence numbers one byte to the left then inserts OOB byte into the first non-empty payload.
After it's done it executes [instance cutoff](#instance_cutoff).

Target OS throws away OOB byte from the stream but DPI may analyze message with OOB byte as it's part thus breaking the message.

- OOB is obsolete but still supported in most OS. There are two RFCs. One assumes that th_urp points to the OOB byte,
another one - to the next byte. Therefore, the value th_urp=0 is invalid according to one of the standards, but it can still work.
To enable it, specify "urp=b".
- Marker "urp" defines 0-based position of the OOB byte. Resulting th_urp , except the "b" case, is set incremented by 1. This is what most of the modern OS expect.
- "urp=e" inserts an OOB byte after the very last byte of the payload - generally useless for DPI bypass, since DPI gets the entire original message.
- For protocols in which the server initially waits for a client request, `--in-range=-s1` is enough. In Windows `--wf-tcp-in` is not needed. Automatically intercepted incoming packets with the SYN flag are sufficient.
- For protocols in which the server sends data before the first message from client all incoming packets before that message should be intercepted. In Windows `--wf-tcp-in` is required.
- Cannot be filtered by payload because after the start it's not possible to stop and not to insert the byte. Inserting a byte without OOB breaks the data.
- Hostlist filtering is not possible.
- oob is "lasting" desync. If profile switch occurs before oob is finished it must be duplicated to that profile or TCP will break because of sequence desync.
- Can't work with functions that resend modified payload. multisplit, multidisorder, fakedsplit, fakeddisorder, etc will send duplicates without OOB.
- If the payload is [multi-segment](#handling-multi-packet-payloads), the entire [reasm](#handling-multi-packet-payloads) is sent. OOB is inserted into the segment where urp hits.
In this segment the th_urp is normalized by segment offset, the TH_URG flag is set. The rest of the parts are sent as is. The function drops the whole replay then [cuts itself off](#instance_cutoff).


## UDP Fooling

There are far fewer options for UDP than for TCP due to the simplicity of the protocol. There isn't much that can be done with it.
[Fakes](#fake) can help against stateful DPI, but they won't help against stateless ones. [IP-level fragmentation](#standard-ipfrag) might help.
For IPv6, [extension headers](#standard-fooling) may work.

Aside from that, the only option is distorting the payload itself. Not all programs will tolerate data distortion; many will simply discard corrupted packets. However, there are some where it is clear what can be "tweaked."

### udplen

```
function udplen(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: [standard payload](#standard-payload)
- arg: min - do not touch packets with an L4 payload length smaller than this
- arg: max - do not touch packets with an L4 payload length larger than this
- arg: increment - how much to increase (+) or decrease (-) the L4 payload length
- arg: pattern - the [blob](#passing-blobs) used to fill the end of the packet when increasing the length
- arg: pattern_offset - initial offset within the pattern
- default payload filter - "known"

The function increases or decreases the length of the UDP L4 payload. When decreasing, part of the information is truncated and lost; when increasing, the extra space is filled with the `pattern`. UDP segmentation is impossible - if the MTU or PMTU is exceeded, the packet will be fragmented by OS on IP level. An error in case of exceeding the MTU will only be reported on Linux; other systems will silently fail to send the packet (WinDivert and ipdivert have no means of error detection).

### dht_dn

```
function dht_dn(ctx, desync)
```

- arg: [standard direction](#standard-direction)
- arg: dn - the number N following 'd' in a DHT message

DHT uses the bencode format for transmitting messages. 'd' represents the directory data type. DHT messages typically start with 'd1' or 'd2' and end with 'e' (end). Some DPIs have these exact signatures hardcoded-only 'd1' or 'd1'+'d2'. However, one can use 'd3', 'd4', etc., if the content is edited correctly without violating the bencode format. This is what this function does. It only works on payloads with the "dht" type.

## Other Functions

### synack

```
function synack(ctx, desync)
```

- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)

Sends a SYN,ACK packet before the SYN to confuse the DPI regarding the TCP connection direction. This attack is referred to in literature as "TCB turnaround." It breaks NAT-usage through NAT is impossible. Usage on transit traffic requires nftables and POSTNAT mode. After a non-SYN packet passes, it performs an [instance cutoff](#instance_cutoff). It does not issue a verdict.

### synack_split

```
function synack_split(ctx, desync)
```

- arg: [standard ipfrag](#standard-ipfrag)
- arg: [standard reconstruct](#standard-reconstruct)
- arg: [standard rawsend](#standard-rawsend)
- arg: mode - "syn", "synack", or "acksyn"

This technique is intended for servers. In literature, it is known as "TCP split handshake." It replaces the outgoing SYN,ACK packet from the server with a SYN, two SYN + ACK packets, or two ACK + SYN packets. If the transmission is successful, it issues a VERDICT_DROP. After a non-SYN,ACK packet passes, it performs an [instance cutoff](#instance_cutoff).

Many DPIs expect a standard response to a SYN in the form of a SYN,ACK. In reality, the response to the SYN becomes another SYN, and then the client sends a SYN,ACK to the server. Consequently, the DPI loses track of which side is the client and which is the server, causing the inspection algorithm to fail. The attack may work even if the client does nothing to bypass blocking. It can be used in conjunction with client-side techniques for targeted TCP bypassing.


# zapret-auto.lua automation and orchestration library

The standard order of instance application is linear-from left to right, taking into account [in-profile filters](#in-profile-filters) and [instance cutoff](#instance_cutoff). nfqws2 provides no other options by default.

Of course, you can write your own Lua function that does what is needed when it is needed. However, you would have to reinvent the wheel, duplicate code, or worse-patch standard antidpi functions to add your own features and then maintain them yourself.

The essence of orchestration mechanisms is to separate the control logic from the logic of the actual actions. This way, nothing needs to be patched, and if you do write your own functions, you only need to write the control algorithm itself without mixing it with action algorithms.

Orchestration is inextricably linked to the concept of an [execution plan](#execution_plan). It includes a list of instances that need to be called sequentially with their parameters and [filters](#in-profile-filters). A basic linear orchestrator is built into the C code, but this role can also be taken over by a Lua function where any logic can be programmed.

For example, you can create automatic strategies - if one doesn't work, use another. The C code has similar logic only within the [automatic hostlist](#filtering-by-lists) mechanism, but it does not implement dynamic strategy switching.

## State storage

Automation logic typically spans across packets and relies on conntrack. Flow states are stored using `desync.track.lua_state` elements.

Other information spans across flows and is tied to the host. Global tables indexed by keys are used to store this information.

### automate_conn_record

```
function automate_conn_record(desync)
```

Returns a table serving as automation state storage bound to the stream. Automation functions can utilize any fields within it.

### standard_hostkey

```
function standard_hostkey(desync)
```

- arg: reqhost - require a hostname; do not operate via IP.
- arg: nld - the domain level number to which the hostname is truncated. If not specified, no truncation occurs.

A standard host-key generator. This function calculates a key string associated with the hostname or the IP address if the hostname is unavailable. If it fails to generate a key, it returns `nil`.

### automate_host_record

```
function automate_host_record(desync)
```

- arg: key - a key within the global `autostate` table. If not specified, the current instance name is used as the key.
- arg: hostkey - the name of the host-key generator function. If not specified, [standard_hostkey](#standard_hostkey) is used.

Returns a table serving as automation state storage bound to a specific host or IP address. It utilizes two keys: `key` and `hostkey`. The resulting location is `autostate.key.hostkey`. If the `hostkey` cannot be retrieved, it returns `nil`.

## Handling successes and failures

A simple, though not entirely precise, explanation of "success" and "failure" is "the site opens" versus "the site does not open." In automation logic, these states are abstract. Any process can result in a success or a failure. Detecting these states is necessary for tracking failures via a counter. The counter increments on failure and resets on success. When a target threshold is reached, a flag is returned, allowing external logic to perform an action-such as switching strategies.

### automate_failure_counter

```
function automate_failure_counter(hrec, crec, fails, maxtime)
```

- hrec - [host storage](#automate_host_record)
- crec - [stream storage](#automate_conn_record)
- fails - the target number of failures.
- maxtime - the time in seconds after which, since the last failure, the next failure restarts the count from scratch.

Returns `true` if the counter reaches the `fails` value. The counter is reset upon returning `true`.

### automate_failure_counter_reset

```
function automate_failure_counter_reset(hrec)
```

- hrec - [host storage](#automate_host_record)

Resets the failure counter value.

## Success and failure detection

Success and failure detectors are swappable functions that take `desync` and [crec](#automate_conn_record) as parameters and return `true` if a success or failure is detected.

### automate_failure_check

```
function automate_failure_check(desync, hrec, crec)
```

- hrec - [host storage](#automate_host_record)
- crec - [stream storage](#automate_conn_record)
- arg: success_detector - the name of the success detector function. Defaults to `standard_success_detector` if not specified.
- arg: failure_detector - the name of the failure detector function. Defaults to `standard_failure_detector` if not specified.
- arg: fails - the target failure counter value. Default is 3.
- arg: maxtime - the maximum time in seconds between failures before the counter resets. Default is 60 seconds.

This function maintains the failure counter by invoking the success and failure detectors. It returns `true` if the counter reaches the target value. The counter resets automatically in this case.

### standard_success_detector

Standard success and failure detectors require inbound and outbound traffic to be redirected in the volume necessary to trigger their criteria.
For relative sequence detection, packets up to the specified `rseq` plus the maximum payload length of one packet (1460 bytes for TCP) are required.

```
function standard_success_detector(desync, crec)
```

- crec - [stream storage](#automate_conn_record)
- arg: maxseq - the outgoing relative sequence threshold for marking a success. Default is 32768. Purpose: Sufficient data has been sent without the stream stalling due to blocking.
- arg: inseq - the incoming relative sequence threshold for marking a success. Default is 4096. Purpose: The peer has sent enough data to ensure it is not a DPI-generated response.
- arg: udp_out, udp_in - more than `udp_in` UDP packets received, provided that `udp_out` > 0. Purpose: The peer has sent enough data to ensure it is not a DPI-generated response.

Standard success detector.

### standard_failure_detector

```
function standard_failure_detector(desync, crec)
```

- crec - [stream storage](#automate_conn_record)
- arg: maxseq - count retransmissions within outgoing relative sequences from 1 to `maxseq`. Default is 32768.
- arg: retrans - consider it a failure if there are at least `retrans` retransmissions. Default is 3.
- arg: reset - send an RST to the retransmitter to terminate long wait times.
- arg: inseq - treat RSTs and HTTP redirects within incoming relative sequences from 1 to `inseq` as failures. Default is 4096.
- arg: no_rst - do not treat RST as a failure.
- arg: no_http_redirect - do not treat HTTP redirects as failures.
- arg: udp_out, udp_in - treat as a failure if >=`udp_out` packets are sent but <=`udp_in` packets are received. Purpose: We are sending a lot, but receiving little or no response.

Standard failure detector.

DPI-based HTTP redirects are defined the same way as in [autohostlists](#autohostlist-failure-detector).

## Orchestrators

### circular

```
function circular(ctx, desync)
```

- arg: [standard host storage](#automate_host_record)
- arg: [standard checker](#automate_failure_check)
- arg: (standard detector only) [standard success detector](#standard_success_detector)
- arg: (standard detector only) [standard failure detector](#standard_failure_detector)

This orchestrator tracks failures and cycles through strategies once the failure counter reaches the `fails` target. All subsequent instances are labeled with a "strategy" argument containing the strategy number, starting from 1. Instances without a "strategy" argument are not called by `circular`. Strategy numbers must be continuous from 1 to the last; gaps are not allowed and will trigger an error. If any instance of strategy N includes a "final" argument, that strategy becomes the last one-further cycling is blocked.

Usage example:

```
--lua-desync=circular:fails=4:retrans=2:maxseq=16384
--lua-desync=argdebug:v=1.1:strategy=1
--lua-desync=argdebug:v=1.2:strategy=1
--lua-desync=argdebug:v=2.1:strategy=2
--lua-desync=argdebug:v=3.1:strategy=3:final
--lua-desync=argdebug:v=3.2:strategy=3
--lua-desync=argdebug:v=3.3:strategy=3
```

In this example, debug output is used instead of real strategies to trace `circular` operations in the debug log. There are 3 strategies: the 1st strategy includes 2 instances, the 2nd includes 1, and the 3rd includes 3. The 3rd strategy is final; returning to the 1st is blocked. To test this, try accessing blocked sites via curl to observe the failure detector's operation.

### repeater

```
function repeater(ctx, desync)
```

- arg: instances - how many subsequent instances to repeat.
- arg: repeats - the number of repetitions.
- arg: stop - do not execute the instances following "instances" as a standalone pass.
- arg: clear - clear the execution plan after repetitions.
- arg: iff - the name of the [condition function](#iff-functions) for continuing the repetition cycle. If not specified, the condition is always true.
- arg: neg - invert the `iff` value. Default is false.

As the name suggests, the `repeater` orchestrator repeats the subsequent `instances` a specified number of `repeats`. The repetition follows the pattern `1-2-3-1-2-3-1-2-3-4-5-6`. In this example, `4-5-6` are the instances following the first three, assuming `instances=3`. If `stop` or `clear` is specified, `4-5-6` are not called. The `clear` flag additionally clears the execution plan, which is useful for interacting with higher-level orchestrators.

The `iff` function allows you to define an additional dynamic condition for continuing the repetition loop. If `xor(iff, neg) = false`, the loop is terminated.

`repeater` supports arbitrary levels of nesting.
In the example below, the resulting call sequence is: `1 1 1 2 2 2 1 1 1 2 2 2 3`.
The `stop` parameter in nested instances prevents the execution of instances that do not belong to their own repetition cycle.
The first `repeater` is not restricted by `stop`, so it proceeds to execute `3`.

```
--lua-desync=repeater:repeats=2:instances=4
 --lua-desync=repeater:repeats=3:stop --lua-desync=argdebug:v=1
 --lua-desync=repeater:repeats=3:stop --lua-desync=argdebug:v=2
--lua-desync=argdebug:v=3
```

### condition

```
function condition(ctx, desync)
```

- arg: `iff` - name of the [iff function](#iff-functions)
- arg: `neg` - invert the `iff` value; defaults to `false`
- arg: `instances` - how many following instances to execute conditionally. all if not defined.

`condition` calls `iff`. If `iff xor neg = true`, all instances in the `plan` are executed; otherwise, the plan is cleared.

### per_instance_condition

```
function per_instance_condition(ctx, desync)
```

- arg: `instances` - how many following instances to execute conditionally. all if not defined.

All following instanced are called only if they have "cond" argument with the "iff" function name and it returns true. The "cond_neg" argument inverts "cond" result.
Names are not iff/neg to avoid conflict with other orchestrators.


### stopif

```
function stopif(ctx, desync)
```

- arg: `iff` - name of the [iff function](#iff-functions)
- arg: `neg` - invert the `iff` value; defaults to `false`

`stopif` calls `iff`. If `iff xor neg = true`, the plan is cleared; otherwise, no action is taken.

`stopif` is useful as a nested orchestrator. For example, it can be used with `circular` to block strategy execution under certain conditions. `condition` is unsuitable for this purpose because it has no awareness of higher-level orchestrators or the "strategy" parameter, and would simply execute instances indiscriminately until the end. `stopif` clears the plan, thereby halting further execution of the parent orchestrator.

### iff functions

These are used across several orchestrators and take `desync` as a parameter.
They can contain any logic programmable in Lua. The base set includes several `iff` functions for demonstration and testing purposes.

#### cond_true

```
function cond_true(desync)
```

Always returns `true`.

#### cond_false

```
function cond_false(desync)
```

Always returns `false`.

#### cond_random

```
function cond_random(desync)
```

- arg: `percent` - the probability of returning `true`. Defaults to 50.

Returns `true` randomly based on the `percent` probability; otherwise returns `false`.

#### cond_payload_str

```
function cond_payload_str(desync)
```

- arg: `pattern` - the string to search for in the payload.

Returns `true` if the substring `pattern` is present in `desync.dis.payload`.
This is a basic signature detector. If the C code does not recognize the protocol you need, you can write your own signature detector and run subsequent instances under a `condition` orchestrator using your detector as the `iff` function.

#### cond_tcp_has_ts

```
function cond_tcp_ts(desync)
```

Returns `true` if the dissect is tcp and has tcp timestamp option.

#### cond_lua

```
function cond_lua(desync)
```

Executes a Lua code from the "cond_code" argument. The code returns condition value. Direct addressing of the desync table is possible within the code.
desync.arg is passed without called "apply_arg_prefix" : `%`, `#`, `\` remain as is without substitution because can refer blobs created by previous conditionally executed instances.


# Auxiliary programs

## ip2net

The `ip2net` utility is designed to convert IPv4 or IPv6 address lists into a list of subnets to reduce the overall list size. It reads from `stdin` and outputs to `stdout`.

```
-4                             ; list is ipv4 (default)
-6                             ; list is ipv6
--prefix-length=min[-max]      ; range of prefix lengths to consider. e.g., 22-30 (ipv4), 56-64 (ipv6)
--v4-threshold=mul/div         ; ipv4: include subnets where at least mul/div addresses are filled. e.g., 3/4
--v6-threshold=N               ; ipv6: minimum number of IPs required to create a subnet
```

The list may contain entries in the format `ip/prefix` and `ip1-ip2`. These entries are passed to `stdout` without modification.
They are accepted by the `ipset` command. For `hash:net` lists, `ipset` can generate optimal `ip/prefix` coverage from `ip1-ip2` ranges.
FreeBSD's `ipfw` supports `ip/prefix` but does not support `ip1-ip2`.
`ip2net` filters input data, discarding invalid IP addresses.

A subnet is selected if it contains a specified minimum number of addresses.
For IPv4, the minimum is set as a percentage of the subnet size (`mul/div`, e.g., `3/4`); for IPv6, the minimum is specified directly.

The subnet size is determined by the following algorithm:
First, the tool searches within the specified prefix length range for subnets that contain the maximum number of addresses.
If multiple such subnets are found, the smallest one (the one with the longest prefix) is chosen.
For example, given the parameters `v6_threshold=2` and `prefix_length=32-64`, and the following IPv6 addresses:

```
1234:5678:aaaa::5
1234:5678:aaaa::6
1234:5678:aaac::5
Result:
1234:5678:aaa8::/45
```

These addresses are also part of a `/32` subnet. However, there is no point in using "blanket coverage" when the exact same addresses fit perfectly into a `/45` and their count remains the same.
If `v6_threshold` is changed to `4`, the result will be:

```
1234:5678:aaaa::5
1234:5678:aaaa::6
1234:5678:aaac::5
```

In this case, the IPs will not be merged into a subnet because there are too few of them.
If `prefix_length=56-64` is used, the result will be:

```
1234:5678:aaaa::/64
1234:5678:aaac::5
```

The CPU time required for calculations depends heavily on the width of the prefix length range, the size of the target subnets, and the length of the list.
If `ip2net` takes too long, avoid using excessively large subnets and narrow the prefix length range.
Note that `mul/div` arithmetic uses integers. If the 32-bit integer limit is exceeded, the results are unpredictable.
Avoid using values like `5000000/10000000`; `1/2` is much more efficient.

## mdig

This program is designed for multithreaded resolving of large lists via the system DNS.
It reads a list of domains from `stdin` and outputs the resolution results to `stdout`. Errors are sent to `stderr`.

```
--family=<4|6|46>              ; select IP address family: ipv4, ipv6, ipv4+ipv6
--threads=<threads_number>     ; number of threads. Default is 1.
--eagain=<eagain_retries>      ; number of retries after EAI_AGAIN. Default is 10.
--eagain-delay=<ms>            ; wait time in ms between EAI_AGAIN retries. Default is 500.
--verbose                      ; debug log to console
--stats=N                      ; output statistics every N domains
--log-resolved=<file>          ; save successfully resolved domains to a file
--log-failed=<file>            ; save failed domain resolutions to a file
--dns-make-query=<domain>      ; output a binary DNS query for the domain to stdout. If --family=6, the query will be AAAA, otherwise A.
--dns-parse-query              ; parse a binary DNS response and output all IPv4 and IPv6 addresses from it to stdout
```

The `--dns-make-query` and `--dns-parse-query` parameters allow you to resolve a single domain through an arbitrary channel.
For example, you can perform a DoH (DNS over HTTPS) request using only `mdig` and `curl` as follows:

```
mdig --family=6 --dns-make-query=rutracker.org | curl --data-binary @- -H "Content-Type: application/dns-message" https://cloudflare-dns.com/dns-query | mdig --dns-parse-query
```

# blockcheck2

`blockcheck2` is a tool for automating strategy testing. It is a POSIX shell script with a modular test structure.

A test consists of a set of pluggable shell scripts used to test a specific group of strategies. The strategies under test can be generated by the script's algorithm based on various conditions or the success of previous checks to reduce the overall testing time.

Test suites are located in the `blockcheck2.d` subdirectories. The name of the subdirectory corresponds to the name of the test.

By default, blockcheck2 runs in interactive mode, displaying messages and prompting the user for parameters. However, since there are many parameters, it only asks for the most essential ones. The rest are passed via [shell variables](#shell-variables).

A typical launch scheme using variables:

`BATCH=1 DOMAINS=bbc.com CURL_CMD=1 SKIP_DNSCHECK=1 /opt/zapret2/blockcheck2.sh`

If you need to record a log, use standard shell tools:

`/opt/zapret2/blockcheck2.sh | tee /tmp/blockcheck2.log`

In the [win bundle](https://github.com/bol-van/zapret-win-bundle), you can use the cygwin prompt (`cygwin/cygwin-admin.cmd`). Aliases have already been created there to launch blockcheck from the first version of zapret, blockcheck2, winws, and winws2 with the standard Lua scripts already connected. This is convenient because you don't have to worry about file paths or repeatedly typing or pasting long strings of text-especially when dealing with national characters and spaces in paths, which can lead to confusion with character escaping and encodings.

Sequential testing of multiple domains is possible. To do this, specify them separated by spaces.

URIs such as `rutracker.org/forum/index.php` are supported. There should be no protocol prefix like `https://`. By default, the root URI ('/') is used. HTTP is tested using the GET method, while HTTPS uses the HEAD method, as nothing is visible under TLS anyway. However, there are situations where blocking does not occur immediately, but rather upon a long server response. In this case, you can use [CURL_HTTPS_GET=1](#shell-variables) and specify a URI where the server returns a long response.

blockcheck2 is not a panacea; it is not a tool for generating "magic strings" that you can simply paste somewhere to make sites start working. It is a customizable tool for researching DPI and automating routine tasks. Understanding the results and how to apply them is the responsibility of the user.

You should also not expect highly complex strategy selection algorithms from blockcheck. Shell scripts are not a full-fledged programming language and lack the tools to work with complex data structures. Shell programming often becomes a struggle when dealing with complex data, as it must somehow be recorded into a linear set of environment variables.

blockcheck2 works on all supported platforms: Linux, FreeBSD, OpenBSD, and Windows. On Windows, the easiest way to use it is through the [win bundle](https://github.com/bol-van/zapret-win-bundle) - a minimal cygwin system pre-configured for zapret.

## DNS check

Nothing will work if the provider returns spoofed IP addresses for blocked domains, unless your client or OS supports routing requests through encrypted channels (e.g., DoH). Even if the browser works due to built-in DoH, there are other programs that lack such support. If the OS itself supports encrypted DNS, you can use that feature; if not, solving the DNS problem is up to you.

If IPs are only spoofed on the provider's DNS servers, and access to other DNS servers is neither blocked nor spoofed, you can use alternative DNS services. For example, public ones like 1.1.1.1, 8.8.8.8, or 9.9.9.9. If access to other DNS servers is blocked or spoofed, you must encrypt the DNS channel. It is also possible that spoofing only occurs on port 53, while DNS responses on other ports remain untouched. However, standard clients do not support such configurations. You would need to either set up transparent redirection on your router or use a DNS aggregator (like dnsmasq) that supports querying DNS on non-standard ports.

Yandex provides DNS on port 1253. On OpenWrt, this is configured quite simply:

**/etc/config/dhcp**

```
config dnsmasq
 list server '77.88.8.88#1253'
```

**/etc/config/network**

```
config interface 'wan'
 option peerdns '0'
```

blockcheck2 can detect whether DNS is being spoofed and whether requests to third-party DNS servers are being intercepted. If spoofing is detected, it automatically switches to DoH.
The list of external DNS servers, domains for spoofing tests, the selected DoH server, and the list of DoH servers for automatic selection can be modified via [shell variables](#shell-variables). You can also use the same method to opt out of testing.

The `SECURE_DNS` variable allows you to manually disable the switch to DoH or, conversely, force it even if no spoofing is detected.

## Main testing modes

### Multiple attempts

Strategy instability is a common phenomenon. A provider might use load balancing, causing different requests to pass through different DPI systems. As a result, a strategy might work one moment and fail the next. Strategy stability is tested through multiple repetitions-attempts. The number of attempts is set either in the dialog or via [shell variables](#shell-variables).

Parallel mode is [supported](#shell-variables). In this mode, each attempt is executed in a separate child process, and results are then aggregated from all processes. This mode is enabled only via the [PARALLEL variable](#shell-variables). It can significantly speed up testing but may also trigger a rate limit-a situation where the server restricts or bans you due to excessive hammering.

### Scanning levels

- **standard** - uses a test algorithm that excludes strategies deemed irrelevant based on previous successes or other criteria. In the case of multiple attempts, testing does not stop upon failure. The success rate and curl errors can also provide useful information for situational analysis.
- **quick** - same as standard, but when using multiple attempts, testing stops after the first failure.
- **force** - tests as extensively as possible, regardless of previous test results.

### Supported protocols

blockcheck2 tests strategies using curl. It supports checking http, https via TLS 1.2, https via TLS 1.3, and http3 (quic). Support for TLS 1.3 and quic may be missing in the curl version installed on your system. If so, you can download a static curl binary from [curl.se](https://curl.se), save it somewhere, grant it execution permissions, and specify the `CURL=<path>/curl` variable. Blockcheck will then use it instead of the system version. On OpenWRT devices with minimal disk space, you can use `/tmp`, which is a tmpfs stored in RAM.

TLS 1.2 is more difficult for DPI bypass than TLS 1.3 because the certificate is returned in plain text during the TLS Server Hello, exposing the domain name. DPI can block the connection based on the server's response, and this is quite difficult to counter. The best tactic for bypassing TLS 1.2 is to ensure the DPI is satisfied with the client's request so that it doesn't bother checking the server's response. If this fails, there is [wssize](#wssize), but it reduces speed and does not work with hostlists.

TLS 1.3 provides minimal unencrypted information during the TLS Server Hello. There is no domain information in plain text, and virtually no fingerprint, so DPI cannot block by domain by analyzing the server's response. However, it can still block the TLS protocol entirely if its rules prohibit TLS.

### IP block check

zapret cannot bypass IP-based blocks.
IP blocks come in various forms.

1. **Full IP block.** Absolutely nothing gets through-no pings, no port connections. Communication is impossible without a proxy.
2. **Port or L4 protocol block.** For example, pings (ICMP) work, but no TCP ports connect, while UDP traffic still passes. Alternatively, a specific port like TCP 443 might be blocked. A TCP port block means all packets with that destination port are dropped. The connection hangs on an endless loop of sending SYN requests; the 3-way handshake never completes. Communication is impossible without a proxy.
3. **Partial IP/port block.** The 3-way handshake completes successfully, but after that, anything you send results in a hang or an RST (reset) packet. The very fact that the connection establishes suggests the potential existence of "whitelisted" messages that could grant access. These might be requests with approved SNIs or packets using a different protocol altogether - something other than TLS. You can only bypass this block if you have specific information on how to "pierce" it, or if you are technically proficient and persistent enough to test various options manually.

**blockcheck2** is designed to assist in identifying IP blocks, but it does not provide an automated verdict - you must decide whether a block exists based on its actions.

The first step is checking port availability via `nc` or `ncat`. These must be installed, as they may not be included in your system out of the box. `ncat` is preferred because it offers more features and handles IPv6 reliably. If neither is installed, the test is canceled. Automated decision-making is hindered by the inconsistent exit codes across different versions of netcat. Some versions do not return success or failure codes at all, providing only version-specific text messages.

You must examine the log yourself: if you do not see a successful connection to the port, it likely indicates an IP or port block. It is possible that only a portion of the IP resources is blocked. If you proceed without addressing this, strategies will behave inconsistently because requests will be routed to random available IPs. If all IPs and ports are blocked, further testing is pointless, as every attempt will result in an error.

Next, a partial IP block is tested using `curl`. This investigates scenarios where the initial port connection is successful. The goal is to determine if blocking occurs on a blocked domain's IP when using an unblocked domain, and vice versa. If an unblocked domain fails on a blocked domain's IP, but works on its own native IP, there is a partial IP block. If blocked domains fail on unblocked IPs, while the unblocked domains themselves work, there is an SNI block. IP and SNI blocks can also be used in combination.

Evaluating the success or failure of these checks is the main challenge, which is why the interpretation falls to the user. What constitutes "success" or "failure"? This varies wildly and can depend on both the DPI (Deep Packet Inspection) system and the server itself.

For example, a TLS error when requesting `iana.org` via the IP of `rutracker.org` might actually indicate success. A certificate error can be either a success or a failure-an invalid certificate could be returned by the server itself or by the DPI via a Man-in-the-Middle (MiTM) attack. It is crucial to determine whether the server returned *any* response and whether that response truly came from the server or was generated by the DPI. A TLS alert when requesting a domain not hosted on that server is normal and common. Conversely, some servers are configured to serve a page regardless of the SNI provided in the TLS handshake - this is also normal.

A hang is usually a sign of failure, but it could also result from server-side issues or the server banning your IP. An RST is likely a failure, but it could be a legitimate response from the server or its DDoS protection system.

There are many variables at play here, so observe the results carefully and use your judgment.

#### Examples of domain-only blocking without IP blocking

```
> testing iana.org on its original
!!!!! AVAILABLE !!!!!
> testing rutracker.org on 192.0.43.8 (iana.org)
curl: (28) Operation timed out after 1002 milliseconds with 0 bytes received
> testing iana.org on 172.67.182.196 (rutracker.org)
HTTP/1.1 409 Conflict
> testing iana.org on 104.21.32.39 (rutracker.org)
HTTP/1.1 409 Conflict

> testing iana.org on its original ip
!!!!! AVAILABLE !!!!!
> testing rutracker.org on 192.0.43.8 (iana.org)
curl: (28) Connection timed out after 1001 milliseconds
> testing iana.org on 172.67.182.196 (rutracker.org)
curl: (35) OpenSSL/3.2.1: error:0A000410:SSL routines::ssl/tls alert handshake failure
> testing iana.org on 104.21.32.39 (rutracker.org)
curl: (35) OpenSSL/3.2.1: error:0A000410:SSL routines::ssl/tls alert handshake failure

> testing iana.org on its original ip
!!!!! AVAILABLE !!!!!
> testing rutracker.org on 192.0.43.8 (iana.org)
HTTP/1.1 307 Temporary Redirect
Location: https://www.gblnet.net/blocked.php
> testing iana.org on 172.67.182.196 (rutracker.org)
HTTP/1.1 409 Conflict
> testing iana.org on 104.21.32.39 (rutracker.org)
HTTP/1.1 409 Conflict

> testing iana.org on its original ip
!!!!! AVAILABLE !!!!!
> testing rutracker.org on 192.0.43.8 (iana.org)
curl: (35) Recv failure: Connection reset by peer
> testing iana.org on 172.67.182.196 (rutracker.org)
curl: (35) OpenSSL/3.2.1: error:0A000410:SSL routines::ssl/tls alert handshake failure
> testing iana.org on 104.21.32.39 (rutracker.org)
curl: (35) OpenSSL/3.2.1: error:0A000410:SSL routines::ssl/tls alert handshake failure
```

#### Example of full IP block or TCP port block in the absence of domain blocking

```
* port block tests ipv4 startmail.com:80
  ncat -z -w 1 145.131.90.136 80
  145.131.90.136 does not connect. netcat code 1
  ncat -z -w 1 145.131.90.152 80
  145.131.90.152 does not connect. netcat code 1

* curl_test_http ipv4 startmail.com
- checking without DPI bypass
  curl: (28) Connection timed out after 2002 milliseconds
  UNAVAILABLE code=28

- IP block tests (requires manual interpretation)

> testing iana.org on its original ip
!!!!! AVAILABLE !!!!!
> testing startmail.com on 192.0.43.8 (iana.org)
HTTP/1.1 302 Found
Location: https://www.iana.org/
> testing iana.org on 145.131.90.136 (startmail.com)
curl: (28) Connection timed out after 2002 milliseconds
> testing iana.org on 145.131.90.152 (startmail.com)
curl: (28) Connection timed out after 2002 milliseconds
```

### Standard tests

#### standard test

This is the primary test, consisting of a series of subtests located in `blockcheck2.d/standard`. If you do not need certain tests, you can copy the `standard` directory to `my` and keep only the necessary scripts there. The `def.in` file is mandatory.

It accepts several additional variables:

```
MIN_TTL - minimum TTL
MAX_TTL - maximum TTL. 0 disables TTL tests
MIN_AUTOTTL_DELTA - minimum negative autottl delta
MAX_AUTOTTL_DELTA - maximum negative autottl delta. 0 disables AUTOTTL tests
FAKE_REPEATS - number of fake repeats
FOOLINGS46_TCP - space-separated list of TCP foolings for IPv4+IPv6
FOOLINGS6_TCP - space-separated list of specific TCP foolings for IPv6

FAKE_HTTP - path to the HTTP fake file
FAKE_HTTPS - path to the HTTPS fake file
FAKED_PATTERN_HTTP - path to the fakedsplit/fakeddisorder pattern file for HTTP
FAKED_PATTERN_HTTPS - path to the fakedsplit/fakeddisorder pattern file for HTTPS
FAKE_QUIC - path to the QUIC fake file
SEQOVL_PATTERN_HTTP - path to the seqovl pattern file for HTTP
SEQOVL_PATTERN_HTTPS - path to the seqovl pattern file for HTTPS

MULTIDISORDER=multidisorder_legacy - replace multidisorder with the version from nfqws1

NOTEST_BASIC_HTTP=1 - disable 10-http-basic.sh tests
NOTEST_MISC_HTTP=1 - disable http 15-misc.sh tests
NOTEST_MISC_HTTPS=1 - disable https 15-misc.sh tests
NOTEST_MULTI_HTTP=1 - disable http 20-multi.sh tests
NOTEST_MULTI_HTTPS=1 - disable https 20-multi.sh tests
NOTEST_SEQOVL_HTTP=1 - disable http 23-seqovl.sh tests
NOTEST_SEQOVL_HTTPS=1 - disable https 23-seqovl.sh tests
NOTEST_SYNDATA_HTTP=1 - disable http 24-syndata.sh tests
NOTEST_SYNDATA_HTTPS=1 - disable https 24-syndata.sh tests
NOTEST_FAKE_HTTP=1 - disable http 25-fake.sh tests
NOTEST_FAKE_HTTPS=1 - disable https 25-fake.sh tests
NOTEST_FAKED_HTTP=1 - disable http 25-faked.sh tests
NOTEST_FAKED_HTTPS=1 - disable https 25-faked.sh tests
NOTEST_HOSTFAKE_HTTP=1 - disable http 35-hostfake.sh tests
NOTEST_HOSTFAKE_HTTPS=1 - disable https 35-hostfake.sh tests
NOTEST_FAKE_MULTI_HTTP=1 - disable http 50-fake-multi.sh tests
NOTEST_FAKE_MULTI_HTTPS=1 - disable https 50-fake-multi.sh tests
NOTEST_FAKE_FAKED_HTTP=1 - disable http 55-fake-faked.sh tests
NOTEST_FAKE_FAKED_HTTPS=1 - disable https 55-fake-faked.sh tests
NOTEST_FAKE_HOSTFAKE_HTTP=1 - disable http 60-fake-hostfake.sh tests
NOTEST_FAKE_HOSTFAKE_HTTPS=1 - disable https 60-fake-hostfake.sh tests
NOTEST_QUIC=1 - disable 90-quic.sh tests
```

#### custom test

A simple tester that uses strategy lists from files. Strategies must be on separate lines; line breaks within a single strategy are not allowed. Separate lists are used for different protocols: `list_http.txt`, `list_https_tls12.txt`, `list_https_tls13.txt`, and `list_quic.sh`. These files support comments starting with `#`.

When defining parameters, keep in mind that they will be interpreted as shell arguments. Special characters must be escaped according to shell rules.
For example, leaving `<` unquoted across the entire parameter or incorrectly quoting the `--luaexec=code=print("abc")` parameter will result in an error. If your Lua code uses strings, it is best to enclose them in single quotes and wrap the entire parameter in double quotes.
Note that `blockcheck2` will output strategy parameters without escaping.

The recommended way to use this is to copy it into its own subdirectory within `blockcheck2.d` and populate the `.txt` files with your tests. Then, select your custom test name from the dialog.

## Summary

At the end of the test, all successful strategies are displayed for each domain and each IP protocol version. If more than one domain was tested, the intersection of successful strategies (those that worked for all) is also provided. However, this intersection can only be fully relied upon when using `SCANLEVEL=force`. Otherwise, strategies that might have worked for subsequent domains might not have been tested for the first one.

## Shell variables

```
CURL - path to the curl executable
CURL_MAX_TIME - curl timeout in seconds
CURL_MAX_TIME_QUIC - curl timeout for QUIC. If not set, CURL_MAX_TIME is used
CURL_MAX_TIME_DOH - curl timeout for DoH servers
CURL_CMD=1 - display curl commands
CURL_OPT - additional curl options. `-k` to ignore certificates, `-v` for verbose protocol output
CURL_HTTPS_GET=1 - use the GET method instead of HEAD for HTTPS
DOMAINS - space-separated list of domains or domains with URIs to test
TEST - name of the test
IPVS=4|6|46 - IP protocol versions to test
ENABLE_HTTP=0|1 - enable plain HTTP test
ENABLE_HTTPS_TLS12=0|1 - enable HTTPS TLS 1.2 test
ENABLE_HTTPS_TLS13=0|1 - enable HTTPS TLS 1.3 test
ENABLE_HTTP3=0|1 - enable QUIC test
REPEATS - number of test attempts
PARALLEL=0|1 - enable parallel attempts. May overwhelm the site due to aggressive requests and lead to incorrect results
SCANLEVEL=quick|standard|force - scanning level
BATCH=1 - batch mode (no prompts or waiting for console input)
HTTP_PORT, HTTPS_PORT, QUIC_PORT - port numbers for the respective protocols
SKIP_DNSCHECK=1 - skip DNS check
SKIP_IPBLOCK=1 - skip port or IP blocking tests
PKTWS_EXTRA_POST - additional nfqws/dvtws/winws parameters added after the main strategy
PKTWS_EXTRA_POST_1 .. PKTWS_EXTRA_POST_9 - separate additional parameters that contain spaces
PKTWS_EXTRA_PRE - additional nfqws/dvtws/winws parameters added before the main strategy
PKTWS_EXTRA_PRE_1 .. PKTWS_EXTRA_PRE_9 - separate additional parameters that contain spaces
DNSCHECK_DNS - space-separated list of third-party DNS servers for DNS spoofing tests
DNSCHECK_DOM - space-separated list of domains for DNS spoofing tests
SECURE_DNS=0|1 - force enable or disable DoH
DOH_SERVERS - space-separated list of DoH URLs for automatic selection of a working server
DOH_SERVER - specific DoH URL (disables auto-selection)
UNBLOCKED_DOM - an unblocked domain used for IP block tests
SIMULATE=1 - enable simulation mode for debugging script logic. Disables real curl requests and replaces them with random results.
SIM_SUCCESS_RATE=<percent> - simulation success probability as a percentage
```

## Why it won't open

Blockcheck shows OK, but the site still won't open. Why?
Blockcheck only verifies the availability of a single specific "domain[/uri]" using a specific protocol, and nothing more.
A browser does far more than that. So, what's the difference?

1. It can all start with DNS. `blockcheck` might use system DNS or DoH, while the browser does the opposite. Sites like Instagram are partially blocked by IP. Success depends on the specific IP address returned by a particular DNS. If your DNS is poisoned by your ISP and your client doesn't support encrypted DNS, it's game over for all bypass methods. You will be directed to a block page IP, and naturally, no amount of `zapret` will help. Sometimes, the ISP provides no DNS response at all for a blocked domain or returns 127.0.0.1.
2. A website is not just a single domain or a single URI. Press F12 in your browser and check the "Network" tab to see where the site is actually connecting. It might be tripping up on a secondary domain.
3. A browser's goal is to open a site as quickly as possible without burdening the user with technical jargon that sounds like Greek to them. Therefore, it attempts to reach the site using various protocols to ensure the page opens faster. It might jump between IPv4 and IPv6, or between TLS and QUIC. That’s already four combinations. Each of these requires a separate `blockcheck` test. Did a single strategy bypass all of them? Did you migrate these strategies to your working config correctly? Did you merge them properly?
4. A particularly important parameter is Kyber. This post-quantum cryptography turns a single-packet TLS/QUIC request into a 2 or 3-packet one. This is a significant factor in DPI circumvention. Modern browsers usually use Kyber. For `curl`, it depends on the version and the age of the crypto library it is linked with. OpenSSL 3.5.0 supports Kyber; older versions do not. LibreSSL or mbedTLS do not support Kyber yet. But they will tomorrow, because that is where the trend is heading.
5. Censors will use any dirty trick available. Sometimes they even target the client's fingerprint. What is that? Primarily, it is the presence and order of TLS extensions characteristic of a specific browser or `curl`. If they cannot ban the IP addresses but need to eliminate a new VPN client, they analyze its handshake, find unique features, and block based on them. If something else breaks in the process, they simply don't care.
6. ECH (Encrypted Client Hello) is a technology for encrypted SNI transmission designed to prevent censors from seeing which resource is being accessed. It is an excellent technology, but unfortunately, it arrived too late. It missed the window to become an undisputed de facto standard. Consequently, they may block based on the presence of ECH itself or by the decoy SNI-for Cloudflare, this is "cloudflare-ech.com". `curl` might hit a site without ECH while the browser uses it-hence the discrepancy.
7. TLS protocol version. By default, `blockcheck2` tests TLS 1.2 as the most difficult case to bypass. A browser will most likely use TLS 1.3. There have been cases where censors intentionally blocked the TLS 1.3 protocol because it is used and required by the popular VLESS-REALITY bypass method. The level of disregard for collateral damage is now so high that breaking numerous legitimate resources no longer stops them.

8. The famous "16 KB" block. How do you test for a 16 KB block? Hit a URI with `curl` where the site returns a sufficiently long page. If the download hangs in the middle, that's it. By default, `blockcheck2` uses `HEAD` requests for HTTPS to avoid taxing the server and to save traffic-since nothing is visible under HTTPS anyway. This can be changed via [CURL_HTTPS_GET=1](#shell-variables). However, doing so will likely result in a stream of "UNAVAILABLE" errors. The standard option provides strategies that work when bypassing the 16 KB block, making it more informative. Why do they do this? The goal is to force everyone into Russian jurisdiction, and to achieve this, they are squeezing major hosting providers : Cloudflare, Hetzner, Akamai, AWS, and others. CDNs are often used for hidden proxy or VPN tunneling. They have to leave a few critical sites accessible. For example, hp.com-where else are you going to download LaserJet drivers? And HP is hosted on one of these providers. This creates a whitelist. Consequently, you need a payload that satisfies this whitelist. The trouble is that `blockcheck`, much like `zapret` itself, is merely a tool. It does not include ready-made recipes. You need to find what works to bypass specific hosts yourself. This is the situation today; tomorrow it will be something else. The author will not chase every change or constantly update `blockcheck` to give you ready-to-use copy-paste recipes. You need to analyze the situation and find a solution yourself. Currently, "16 KB" style whitelists are bypassed either by using a whitelisted SNI or some other whitelisted protocol type that isn't TLS. Tomorrow it will be something else. The [standard checker](#standard-test) accepts a whole list of variables for scan customization. There is an option to [insert something before and something after](#shell-variables) the strategy. Finally, `blockcheck` isn't the only option; sometimes it's more convenient to check things manually.
9. Following up on the previous point-the practice of implementing specific rules on certain IP ranges has become widespread. Therefore, you might find a strategy that works for most resources but fails on others.
10. There are reports of DPI behavior in the "punish the troublemaker" style. The DPI detects attempts to fool it and temporarily blocks access by IP. It might work once or twice, and then no connections go through. If the IP is dynamic, reconnecting to the ISP helps, but only until the next attempt. Another variation involves sending a UDP packet to a trigger IP (for example, via a torrent client) followed by a block of certain IP ranges. The author has not encountered such blocks personally, but dynamic blocking is the path China has already taken. It can be expected in Russia as well.
11. Strategy instability. Load balancing at the ISP level is a frequent occurrence. Traffic may pass through one DPI instance one moment and another the next, causing a strategy to work only intermittently. By default, `blockcheck2` only tests a single attempt. If there are doubts about stability, you should increase the number of attempts to at least 5. You can use [PARALLEL=1](#shell-variables), but this may trigger the resource's own protection against aggressive hammering.
The main goal of those implementing the blocks is to eliminate mass circumvention.
If the button doesn't work for 99% of people, the solution doesn't work for them.
In reality, technical research is required to see what they've come up with this time. It takes a lot of manual testing to identify their algorithms and find a workaround.

# Startup scripts

Startup scripts refer to the Linux wrapper that allows you to install, configure, remove, start, and stop the program. This also includes the maintenance system for IP and host lists. it supports OpenWrt and classic Linux distributions with `systemd` and `openrc`. For other Linux versions and firmwares, you can configure the parameters, but you will need to set up the autostart yourself.

Official support is guaranteed only for OpenWrt, starting from version 18. On older versions, it may work partially or not at all. On Keenetic, it works under Entware, but only through additional "support measures" that fall outside the scope of the zapret2 project and are maintained by third-party developers. For all other firmwares, the setup is entirely the user's responsibility. There are ready-made integrations for various firmwares, but their support lies entirely with their respective authors; they are not officially supported by the author of zapret.

nfqws2 can also operate standalone without startup scripts. However, you will need to handle the automatic startup, parameter passing, and firewall configuration yourself.

On Windows, no dedicated startup system is required-everything is typically handled by batch files to run winws2 in interactive mode or to manage the service.

On BSD, only the ipset list retrieval system is functional. On FreeBSD, it can load ipsets (tables) into ipfw. On OpenBSD, pf loads the IP list files directly.

## config file

Used by all components of the startup scripts, this file is named "config" and is located in the root of the zapret directory. It is a shell include file where variables are assigned and comments starting with '#' are supported. You can also use any shell constructs, such as variable referencing or arithmetic operators.

nfqws2 itself is unaware of the startup scripts or the config file and does not accept a path to it as a command-line argument.

| Parameter | Description |
| :--- | :--- |
| TMPDIR | Temporary directory to be used instead of /tmp. This is useful if the device has limited memory and the tmpfs in /tmp is insufficient. |
| WS_USER | The user account under which nfqws2 is executed. By default, this is determined automatically based on the operating system. |
| FWTYPE | The firewall type: iptables, nftables, or ipfw. This is automatically detected by default. |
| SET_MAXELEM | The maximum number of entries allowed in the created ipsets. |
| IPSET_OPT | ipset options for iptables. |
| IPSET_HOOK | A script that receives the ipset name as $1 and outputs a list of IPs to stdout, which are then added to the ipset. |
| IP2NET_OPT4<br>IP2NET_OPT6 | ip2net settings for scripts used to retrieve IP lists. |
| MDIG_THREADS | The number of mdig threads to use. This is utilized when resolving hostlists. |
| MDIG_EAGAIN                                                                                                                                                                                                                         | Number of attempts when receiving EAI_AGAIN                                                                                                   |
| MDIG_EAGAIN_DELAY                                                                                                                                                                                                                   | Delay in ms between attempts when receiving EAI_AGAIN                                                                                        |
| AUTOHOSTLIST_INCOMING_MAXSEQ<br>AUTOHOSTLIST_RETRANS_MAXSEQ<br>AUTOHOSTLIST_RETRANS_THRESHOLD<br>AUTOHOSTLIST_RETRANS_RESET<br>AUTOHOSTLIST_FAIL_THRESHOLD<br>AUTOHOSTLIST_FAIL_TIME<br>AUTOHOSTLIST_UDP_IN<br>AUTOHOSTLIST_UDP_OUT | [Autohostlist](#autohostlist-failure-detector) parameters                                                                                     |
| AUTOHOSTLIST_DEBUGLOG                                                                                                                                                                                                               | Enable autohostlist debug logging. The log is written to `ipset/zapret-hosts-auto-debug.log`                                                  |
| GZIP_LISTS                                                                                                                                                                                                                          | Whether to apply gzip compression to generated host and IP lists                                                                              |
| DESYNC_MARK                                                                                                                                                                                                                         | Mark bit to prevent looping                                                                                                                   |
| DESYNC_MARK_POSTNAT                                                                                                                                                                                                                 | Mark bit for tagging flows using the POSTNAT scheme                                                                                           |
| FILTER_MARK                                                                                                                                                                                                                         | If set, intercepts only packets with this mark bit. Useful for creating specific filters, such as by local network source IP.                |
| POSTNAT                                                                                                                                                                                                                             | Use post-NAT interception mode on nftables. Default is 1. On iptables, interception is always pre-NAT.                                        |
| NFQWS2_ENABLE                                                                                                                                                                                                                       | Enable standard nfqws2 mode                                                                                                                   |
| NFQWS2_PORTS_TCP<br>NFQWS2_PORTS_UDP                                                                                                                                                                                                | Interception ports for standard nfqws2 mode                                                                                                   |
| NFQWS2_TCP_PKT_OUT<br>NFQWS2_TCP_PKT_IN<br>NFQWS2_UDP_PKT_OUT<br>NFQWS2_UDP_PKT_IN                                                                                                                                                  | connbytes limiters by TCP/UDP and direction for standard nfqws2 mode                                                                          |
| NFQWS2_PORTS_TCP_KEEPALIVE<br>NFQWS2_PORTS_UDP_KEEPALIVE                                                                                                                                                                            | List of TCP/UDP ports for which the outgoing connbytes limiter is disabled in standard nfqws2 mode                                            |
| NFQWS2_OPT                                                                                                                                                                                                                          | Command-line parameters for standard nfqws2 mode                                                                                              |
| MODE_FILTER                                                                                                                                                                                                                         | Filtering mode: none, ipset, hostlist, autohostlist                                                                                           |
| FLOWOFFLOAD                                                                                                                                                                                                                         | Offload mode: donttouch, none, software, hardware                                                                                             |
| OPENWRT_LAN<br>OPENWRT_WAN4<br>OPENWRT_WAN6                                                                                                                                                                                         | Space-separated list of LAN and WAN interfaces for IPv4 and IPv6 in OpenWRT. Use netifd INTERFACES, NOT Linux interfaces! Defaults to "lan" and "wan" |
| IFACE_LAN<br>IFACE_WAN<br>IFACE_WAN6                                                                                                                                                                                                | Space-separated list of LAN and WAN interfaces for IPv4 and IPv6 in classic Linux. Use Linux INTERFACES!                                      |
| INIT_APPLY_FW                                                                                                                                                                                                                       | Whether [startup scripts](#startup-scripts) should apply firewall rules                                                                       |
| INIT_FW_PRE_UP_HOOK<br>INIT_FW_POST_UP_HOOK<br>INIT_FW_PRE_DOWN_HOOK<br>INIT_FW_POST_DOWN_HOOK                                                                                                                                      | Hook scripts called before/after bringing the firewall up and before/after taking it down                                                     |
| DISABLE_IPV4<br>DISABLE_IPV6<br>                                                                                                                                                                                                    | Disable specific IP protocol versions                                                                                                         |
| FILTER_TTL_EXPIRED_ICMP | Filter "time exceeded" messages in response to packets belonging to flows processed by zapret |
| GETLIST | [Script within ipset](#list-management-system) called from `ipset/get_config.sh`. Defaults to `ipset/get_ipban.sh` if not specified |

- "Standard nfqws2 mode" refers to the instance launched with the `NFQWS2_OPT` parameters when `NFQWS2_ENABLE` is active. This is in contrast to [custom scripts](#custom-scripts), which may launch non-standard or custom nfqws2 instances.
- netifd interfaces are those visible in `/etc/config/network` or LuCI, and are retrieved via the `ifstatus` command. These are not Linux interfaces. Linux interfaces are specified in the `device` parameter of an interface definition and are visible via the `ip link` command. For example, a netifd interface might be "lan", while the Linux interface is "br-lan". You must enter "lan" into `OPENWRT_LAN` rather than "br-lan"; otherwise, it will not work.
- Specifying LAN interfaces is only necessary for flow offloading in nftables and is not used for any other purpose.
- The `NFQWS2_OPT` command-line parameters should only include the strategy. Standard Lua files and service parameters like `--qnum` or `--user` are added automatically. You can add your own `--blob` or `--lua-init` parameters.
- `NFQWS2_OPT` accepts the `<HOSTLIST>` and `<HOSTLIST_NOAUTO>` placeholders. These act as substitutions for standard lists and are replaced by `--hostlist` and `--hostlist-auto` parameters depending on the `MODE_FILTER` setting. `<HOSTLIST_NOAUTO>` adds the auto-hostlist as a regular list without the "auto" functionality. Only files that actually exist are included in the parameters. These placeholders can be used in different profiles; their placement depends entirely on the logic of your specific strategies.
- Directly specifying parameters in `NFQWS2_OPT`, such as `--hostlist=/opt/zapret2/ipset/zapret-hosts-user.txt`, is strongly discouraged. This breaks the `MODE_FILTER` logic and the list retrieval scripts, meaning their results might not be taken into account.
- Storing your own files in `/opt/zapret2` is risky, as the installer may delete them during a zapret2 update. Use a location outside the zapret2 directory.

## List management system

Located in the `ipset` directory, this system consists of shell scripts that manage files with fixed names within the same directory.

### Standard list files

Lists are categorized into hostlists and IP lists, and further divided into user-defined and auto-generated files.
User-defined lists are maintained manually and are not modified by the software. Auto-generated lists are the result of program execution (such as downloaded lists) and are not intended for manual editing. Any changes to auto-generated lists may be overwritten.

User-defined hostlists can contain hostnames, IPv4 addresses, IPv6 addresses, or CIDR subnets. Auto-generated hostlists can only contain hostnames.

All lists can be compressed with gzip. In this case, ".gz" is added to their filenames. Gzip compression is typically not used for user-defined lists because they are generally small and difficult to edit when compressed. For auto-generated lists, gzip is usually employed to save disk space. Whether compression is applied to generated lists depends on the [GZIP_LISTS](#config-file) configuration variable.

IP lists are separated into IPv4 and IPv6. IPv6 lists are identified by a "6" character appended to the filename before the extension.

Depending on the mode, hostlists can be resolved into IP lists using [mdig](#mdig) or applied as is. If hostlists are applied as is in nfqws2, only domain names are considered, while IP addresses and subnets are ignored.

Inclusion IP lists are loaded into kernel sets and applied in table rules only if [MODE_FILTER=ipset](#config-file) is specified.
The exclusion IP list is loaded into kernel sets and is always applied in table rules.

| Hostlist                      | Type            | Purpose             | IP Lists                                              |
| :---------------------------- | :-------------- | :------------------ | :---------------------------------------------------- |
| zapret-hosts-user.txt         | user-defined    | inclusion           | zapret-ip-user.txt<br>zapret-ip-user6.txt             |
| zapret-hosts-user-exclude.txt | user-defined    | exclusion           | zapret-ip-exclude.txt<br>zapret-ip-exclude6.txt       |
| zapret-hosts-user-ipban.txt   | user-defined    | traffic redirection | zapret-ip-user-ipban.txt<br>zapret-ip-user-ipban6.txt |
| --                            | generated       | traffic redirection | zapret-ip-ipban.txt<br>zapret-ip-ipban6.txt           |
| zapret-hosts.txt              | generated       | inclusion           | zapret-ip.txt<br>zapret-ip6.txt                       |

### ipset scripts

All scripts that generate hostlists call `get_ipban.sh`. All scripts that generate IP lists call `get_user.sh`. Essentially, ipban is always resolved regardless of whether you use hostlists or IP lists, while user lists are always resolved if you use any scripts to retrieve IP lists.

#### clear_lists.sh

Deletes all generated lists from the ipset.

#### create_ipset.sh

Loads all available IP lists into the corresponding ipsets. Here, "ipset" refers to iptables ipsets, nftables sets, or ipfw tables. The script selects the ipset backend based on the [FWTYPE](#config-file) config variable or automatically based on the OS and installed components if the variable is not set. Whether to load IPv4 or IPv6 versions depends on [DISABLE_IPV4](#config-file) and [DISABLE_IPV6](#config-file).

It takes one command-line parameter. This can be "clear" (to clear ipsets) or "no-update" (to load only if ipsets haven't been created yet, without performing an update).

ipset names:

- nozapret, nozapret6 - IP address exclusions
- zapret, zapret6 - IP address inclusions
- ipban, ipban6 - a separate inclusion list for third-party redirection or proxying

ipfw uses sets that include both IPv4 and IPv6 addresses, so the "6" variants are not used.

#### get_config.sh

Executes the ipset script specified in the [GETLIST](#config-file) config variable. If the variable is not set, it executes `get_ipban.sh`.

#### get_user.sh

Resolves `zapret-hosts-user.txt`, `zapret-hosts-exclude.txt`, and `zapret-hosts-ipban.txt`.

#### get_ipban.sh

Resolves `zapret-hosts-exclude.txt` and `zapret-hosts-ipban.txt`.

#### get_exclude.sh

Resolves `zapret-hosts-exclude.txt`.

#### get_antifilter_*.sh

Downloads IP or hostlists from <https://antifilter.network>.

Roskomnadzor, in its tireless concern for the well-being of the citizens of the Russian Federation, maintains several lists of resources that citizens are forbidden from visiting. Unfortunately, due to a lack of energy caused by constant thoughts about the future of Russia, they are unable to deliver the contents of these lists to every citizen.

We have decided to provide whatever assistance we can to Roskomnadzor and offer everyone up-to-date and complete lists of IP addresses that should not be visited. Based on these, you can even automate your "non-visiting" of them.

The website states that the lists are taken from zapret-info, which has since met its demise, so their relevance is questionable.

#### get_antizapret_domains.sh

Downloads hostlists from <https://antizapret.prostovpn.org>.

Hostlist from the legacy censorship circumvention service "prostovpn.org".

#### get_refilter_*.sh

Downloads IP or host lists from <https://github.com/1andrevich/Re-filter-lists>.

Re:filter is an attempt to maintain an up-to-date list of domains and IP addresses blocked in Russia, as well as those that are popular yet restricted for users within the country.

It excludes casinos, pornography, prostitution, drugs, and similar content.

#### get_reestr_*.sh

Downloads IP or host lists from <https://github.com/bol-van/rulist>.
IP lists contain both IPv4 and IPv6 addresses.

- `get_reestr_resolvable_domains.sh` - A list of blocked domains that actually resolve. More than half of all blocked domains are already dead; they are removed to avoid bloating the list.
- `get_reestr_preresolved.sh` - Periodically resolves the list of blocked domains. This does not help with "jumping" domains that have frequently changing IPs or domains that resolve differently based on GeoIP.
- `get_reestr_preresolved_smart.sh` - The previous list plus subnets of certain problematic ASNs, while excluding confirmed unblocked (whitelisted) ASNs. Problematic IPs include popular CDNs with rotating IPs and hosters subject to more stringent filtering rules in Russia. As of this writing, problematic ASNs include: AS32934 (Facebook, Instagram), AS13414 (Twitter), AS13335 (Cloudflare), AS15169 (Google), AS16509 (Amazon), AS16276 (OVH), AS24940 (Hetzner). Whitelisted ASNs: AS47541 (VK), AS35237 (Sberbank), AS47764 (Mail.ru), AS13238 (Yandex).

### ipban system

This is simply a system for resolving (and potentially downloading) a list, which results in the creation of kernel ipsets named "ipban" and "ipban6."
`zapret` itself does not perform any actions with them. They are intended for you to manually configure PBR (Policy-Based Routing) or selective proxy redirection for connections targeting "ipban" addresses. As the name suggests, IP addresses in this list cannot be bypassed autonomously; a VPN or proxy is required. PBR or selective redirection is used to avoid routing all traffic through them. Configuration instructions are beyond the scope of this project, but some information can be found in the [zapret1 documentation](https://github.com/bol-van/zapret/tree/master/docs).

A typical `ipban` usage scenario begins with creating an ipset from the saved lists.

```
#!/bin/sh
. /opt/zapret2/init.d/openwrt/functions
#. /opt/zapret2/init.d/sysv/functions

create_ipset no-update
```

You cannot be certain which will start first : your script or `zapret`.
Startup must be synchronized and should not run in parallel.
The best way to achieve this is by using [INIT_FW_*_HOOK](#config-file).

## Init scripts

These are available only for Linux and OpenWRT. The Linux version is located in `init.d/sysv`, and the OpenWRT version is in `init.d/openwrt`. The main executable is `zapret2`. The required action is passed via the `$1` argument. The startup procedure is split into starting the daemons (nfqws2 processes) and initializing the firewall (applying iptables/nftables rules).

| Command ($1)                                     | Action                                                                                                                                                                                                                                                                |
| :----------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| start<br>stop<br>restart                         | Starts/stops/restarts daemons and the firewall. The firewall will not start if [INIT_APPLY_FW](#config-file) is not set to 1. On OpenWRT with fw3 (iptables), the firewall is started separately; these commands only affect daemons and do not touch the firewall. |
| start_daemons<br>stop_daemons<br>restart_daemons | Starts/stops/restarts daemons.                                                                                                                                                                                                                                        |
| start_fw<br>stop_fw<br>restart_fw                | Starts/stops/restarts the firewall. On OpenWRT with fw3 (iptables), these commands work, but the firewall is started separately via a firewall include in `/etc/config/firewall`. Individual operations are not recommended.                                          |
| reload_ifsets                                    | (nftables only) Reloads wanif, wanif6, and lanif sets.                                                                                                                                                                                                                |
| list_ifsets                                      | (nftables only) Displays wanif, wanif6, lanif, and flowtable.                                                                                                                                                                                                         |
| list_table                                       | (nftables only) Displays the zapret2 table.                                                                                                                                                                                                                           |

The sysv variant is intended for any Linux distribution other than OpenWRT. On systems with different init systems, the sysv script is still used, while the integration with the native init system acts merely as an adapter to trigger it. For unsupported init systems or custom firmwares, you must determine where to hook "zapret2 start" and "zapret2 stop" yourself to ensure proper autostart and shutdown within your environment.

### Firewall integration

If the OS uses a firewall management system, conflicts may occur between it and zapret. Most commonly, these manifest as race conditions-a competition over who populates the rules first or clears the other's rules. This leads to chaos: sometimes it works, sometimes it doesn't, or only one component functions, making the overall state unpredictable. Race conditions usually happen with iptables because it uses shared tables. nftables generally avoids these issues since each application uses its own table. However, if the firewall management system decides to flush the entire ruleset, a race condition will still occur.

If you encounter race conditions or conflicts, the best solution is synchronization. Disable `INIT_APPLY_FW` in the [config](#config-file) file; this prevents the `start` command scripts from launching the firewall and creating a conflict. Next, determine how to trigger a third-party script to apply additional rules once your system's primary firewall is up. This script should be `zapret2 start_fw`. You can also integrate `stop_fw` and `restart_fw` in a similar fashion. Alternatively, you can take the opposite approach: use the `zapret` firewall initialization as a base and utilize [firewall hooks](#config-file) to trigger your system's firewall management commands. Ensure that your firewall management system does not overwrite or wipe the `zapret` rules.

If your firewall management system only works with its own rules and is highly incompatible with third-party additions, you might consider bypassing the startup scripts entirely. Instead, determine how to manually add `NFQUEUE` rules according to its specific logic and run the daemons separately via your distribution's init system. If this is undesirable or impossible, you may want to consider switching to a different firewall management system or abandoning it altogether.

#### OpenWRT firewall integration

OpenWRT comes with ready-made firewall integration. The startup scripts automatically detect `fw3` and disable firewall management via `start/stop/restart`. Instead, a firewall include `firewall.zapret2` is added to `/etc/config/firewall`, which launches the `zapret` rules synchronously after `fw3` is initialized. Additionally, a `90-zapret2` hook is placed in `/etc/hotplug.d/iface` to handle interface up/down events. In the `fw3` version, `fw3` is restarted so that rules are applied to new interfaces or removed for those that no longer exist. In the `nftables` version, only the `wanif`, `wanif6`, `lanif`, and `flowtable` sets are reloaded.

### Custom scripts

The standard [NFQWS2_OPT](#config-file) instance cannot always solve highly specific tasks. Interception is performed only by port. There is no way to include additional conditions-for example, intercepting a specific payload on any port, setting a specific `connbytes` filter, or using a special kernel `ipset` to apply unique strategies to that intercepted traffic.

Since these requirements are often very specific, they are not included in the core functionality. Instead, a system of custom scripts has been created. These are shell includes located in `init.d/sysv/custom.d` or `init.d/openwrt/custom.d`. Their primary task is to apply the firewall rules you need and launch `nfqws2` instances with the required parameters. Other auxiliary actions are also possible.

A custom script can contain the following shell functions, which are called by the startup system:

- **zapret_custom_daemons** - starts and stops daemons. `$1 = 1` for start, `0` for stop.
- **zapret_custom_firewall** - applies and removes `iptables` rules. `$1 = 1` for apply, `0` for remove.
- **zapret_custom_firewall_nft** - applies `nftables` rules. A stop function is not required because the main code clears the `nft` chains along with custom rules upon stopping.
- **zapret_custom_firewall_nft_flush** - called when `nftables` is stopped to allow for the removal of objects outside the standard chains, such as custom sets or custom chains.

If you do not need `iptables` or `nftables`, you do not need to write functions for that specific firewall type. It is highly recommended to use the core code's helpers within these functions; this allows you to follow the startup script ideology without needing to focus on low-level details. You can freely reference variables from the [config](#config-file) and add your own.

The best way to start writing your own scripts is to study the examples provided in `init.d/custom.d.examples.linux`.

#### Custom helpers

These are functions from the main startup script code that are useful when writing custom scripts.

##### Retrieving dynamic numbers

```
alloc_dnum()
# $1 - name of the variable to which the daemon number is assigned
alloc_qnum()
# $1 - name of the variable to which the queue number is assigned
```

Functions for obtaining dynamic numbers from the pool are necessary to prevent conflicts between different startup scripts. A queue number is a unique value; two instances cannot bind to the same queue, as the second one will fail with an error. A daemon number is required for PID tracking. If numbers overlap, start/stop/restart operations will not function correctly.

These functions should be called from the main body of the script, not from within a function. Custom scripts are always executed in alphabetical order-this is the standard scheme for ".d" directories in Unix. Given the same set of scripts, the same `qnum` and `dnum` values will always be returned for each script during both startup and shutdown. This allows them to be used as unique identifiers without colliding with other scripts. If the composition of custom scripts is changed after startup, this rule is broken, which will lead to issues. Therefore, it is best not to modify the set of custom scripts while zapret2 is running.

##### Working with daemons

```
do_nfqws()
# $1 - 1 to start, 0 to stop
# $2 - daemon number
# $3 - nfqws2 parameters
```

Starts or stops an `nfqws2` instance. Base parameters are appended automatically. These include user selection, fwmark, and the connection of standard Lua scripts: [zapret-lib.lua](#zapret-liblua-base-function-library), [zapret-antidpi.lua](#zapret-antidpilua-dpi-attack-program-library), and [zapret-auto.lua](#zapret-autolua-automation-and-orchestration-library).

You must specify the queue number yourself using `--qnum`.

```
filter_apply_hostlist_target()
# $1 - name of the variable containing nfqws2 options
```

Replaces the `<HOSTLIST>` and `<HOSTLIST_NOAUTO>` markers in $1 depending on the [MODE_FILTER](#config-file) and the presence of list files in ipset.

```
standard_mode_daemons()
# $1 - 1 to start, 0 to stop
```

Starts or stops the [standard instance](#config-file) of `nfqws2`.
Any config variables can be overridden locally.

##### Working with iptables

```
fw_nfqws_post()
fw_nfqws_pre()
# $1 - 1 to enable, 0 to disable
# $2 - iptables filter for IPv4
# $3 - iptables filter for IPv6
# $4 - queue number
```

Enables or disables redirection rules to the queue for `nfqws2`. Filters are written separately for IPv4 and IPv6 because they may contain protocol-specific elements that would cause errors on the other IP version.

"post" refers to the chain for outgoing traffic, while "pre" refers to incoming traffic.

`$FW_EXTRA_PRE` is prepended to the rules, and `$FW_EXTRA_POST` is appended.

What should NOT be included in the filter:

- Checking standard exclude ipsets: `nozapret`, `nozapret6`.
- Checking by [DESYNC_FWMARK](#config-file).

Whether rules are applied for each IP version depends on the [config](#config-file) settings.

```
zapret_do_firewall_standard_tpws_rules_ipt()
# $1 - 1 to enable, 0 to disable
```

Applies or removes iptables rules for the [standard](#config-file) `nfqws2` instance.
You can locally override [config](#config-file) variables and apply `FW_EXTRA_POST` and `FW_EXTRA_PRE`.

```
filter_apply_ipset_target()
# $1 - name of the variable containing iptables filter rules
# $2 - name of the variable containing ip6tables filter rules
```

Adds checks for the standard `zapret`/`zapret6` sets in the outgoing direction (dst) to variables $1 and $2.

```
reverse_nfqws_rule_stream()
# stdin - iptables or ip6tables filter rules
reverse_nfqws_rule()
# $@ - iptables or ip6tables filter rules
```

Swaps iptables filter elements from the forward to the reverse direction (changes `dst` to `src`). The result is sent to stdout.

```
ipt()
ipta()
ipt_del()
ipt6()
ipt6a()
ipt6_del()
# $@ - iptables rule
ipt_add_del()
ipta_add_del()
ipt6_add_del()
ipt6a_add_del()
# $1 - 1 to add, 0 to delete
# $2+ - all other arguments define the iptables rule
```

A set of functions for managing iptables rules. All functions that add rules first check for the rule's existence; if it is already present, it will not be added. This is necessary to prevent rule duplication. All rules are prefixed with `$FW_EXTRA_PRE` and suffixed with `$FW_EXTRA_POST`. The suffix "6" indicates IPv6 support; its absence indicates IPv4.

All rules begin with the chain name, omitting iptables commands such as `-A`, `-D`, `-I`, etc.

- `ipt` - iptables -I - prepend to the beginning.
- `ipta` - iptables -A - append to the end.
- `ipt_del` - iptables -D - delete.
- `ipt_add_del` - add via -I or delete. `$1`: 1 for addition, 0 for deletion. The rule itself starts from `$2`.
- `ipta_add_del` - same as above, but uses -A instead of -I.

```
ipt_first_packets()
# $1 - number of packets or the string "keepalive"
```

Outputs to stdout: `-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes $RANGE`. `RANGE` is defined as "1:$1". If `$1` is "keepalive", nothing is output (no connbytes filter).

```
ipt_port_ipset()
# $1 - ipset name
# $2 - comma separated port or port range list. ranges are port1-port2
```

Creates "bitmap:port" ipset filled with the supplied port list. If the set already exists it's elements are replaced.


##### Working with nftables

```
nft_fw_nfqws_post()
nft_fw_nfqws_pre()
# $1 - nftables filter for ipv4
# $2 - nftables filter for ipv6
# $3 - queue number
```

Enables or disables redirection rules to the queue for nfqws2. Filters are written separately for IPv4 and IPv6 because they may contain version-specific elements that would trigger an error on the other IP version.

"post" refers to the chain for outgoing traffic, "pre" for incoming traffic. The chain type is selected based on the [POSTNAT](#config-file) variable. If you need a specific chain, you can override `POSTNAT` for a single call or as a local variable within the function.

Rules are prefixed with `$FW_EXTRA_PRE` and suffixed with `$FW_EXTRA_POST`.

What should NOT be included in the filter:

- Checks for standard exclude ipsets - `nozapret`, `nozapret6`.
- Checks based on [DESYNC_FWMARK](#config-file).

Whether rules are applied for each IP version depends on the [config](#config-file) settings.

```
zapret_do_firewall_standard_tpws_rules_nft()
```

Applies nftables rules for the [standard](#config-file) nfqws2 instance.
You can locally override [config](#config-file) variables and apply `FW_EXTRA_POST` and `FW_EXTRA_PRE`.

```
nft_filter_apply_ipset_target()
# $1 - name of the variable containing nftables filter rules for ipv4
# $2 - name of the variable containing nftables filter rules for ipv6
```

Adds checks for standard `zapret`/`zapret6` sets in the outbound direction (dst) to variables `$1` and `$2`.

```
nft_reverse_nfqws_rule()
# $@ - nftables filter rule
```

Reverses nftables filter elements from the forward to the reverse direction - replaces `dst` with `src`. The result is output to stdout.

```
nft_add_chain()
# $1 - chain name
# $2 - parameters inside { }
nft_delete_chain()
# $1 - chain name
nft_create_set()
# $1 - set name
# $2 - parameters inside { }
nft_del_set()
# $1 - set name
nft_flush_set()
# $1 - set name
nft_set_exists()
# $1 - set name
nft_add_set_element()
# $1 - set or map name
# $2 - element
nft_add_set_elements()
# $1 - set or map name
# $2,$3,... - elements

nft_flush_chain()
# $1 - chain name

nft_add_rule()
# $1 - chain name
# $2+ - nftables rule
nft_insert_rule()
# $1 - chain name
# $2+ - nftables rule
```

These functions operate on the `zapret2` table, allowing you to avoid direct `nft` calls with hardcoded table names. The names are self-explanatory.

```
nft_first_packets()
# $1 - number of packets or "keepalive"
```

Outputs to stdout: `ct original packets $RANGE`. `RANGE` is defined as "1-$1" if `$1 > 1`, or "1" if `$1 = 1`. If `$1` is "keepalive", nothing is output (no connbytes filter).

##### Additional functions

Many useful helpers are located in `common/base.sh`. Their purpose is easily understood from the code.

## Installer

Consists of the files `install_bin.sh`, `install_prereq.sh`, `install_easy.sh`, and `uninstall_easy.sh`. These utilize files from the `common` directory.

- `install_bin.sh` - an automated tool for finding and configuring architecture-appropriate binary files from the `binaries` folder. It creates symlinks in the `nfq2`, `mdig`, and `ip2net` directories pointing to files within one of the subdirectories in `binaries`. It is specifically designed for stripped-down firmware where many standard utilities are missing. While it works on almost everything, it is not 100% foolproof. The absence or limited functionality of a standard system utility might break the script-a common issue with unsupported firmwares like Padavan, Merlin, and similar. If it fails, create the symlinks manually.
- `install_prepreq.sh` - a prerequisite installer for the packages required for zapret to function. It works on OpenWRT and most Linux distributions, but not all, as package management systems and individual system configurations vary significantly. If the script fails, you must install the packages manually.
- `install_easy.sh` - the main installer. Designed to be run from any location. It operates in an interactive mode, prompting the user with questions. It automatically configures binaries and installs prerequisites (no need to run the previous scripts separately). On unsupported Linux systems, it cannot configure autostart-you will have to do this manually.
- `uninstall_easy.sh` - the uninstaller. It cannot remove autostart on unsupported systems. It offers to remove prerequisites only on OpenWRT; on other systems, it does not. It does not delete the installation directory itself. To remove it completely, you must delete it manually.

The individual files `install_bin.sh` and `install_prereq.sh` are useful when you do not intend to perform a full installation but need a working [blockcheck2](#blockcheck2) or want to run the [startup scripts](#startup-scripts) manually.

The installer always copies files to `/opt/zapret2` if the source is located elsewhere. When replacing the target directory, it deletes all existing files there. It can optionally preserve standard files: config, [custom scripts](#custom-scripts), [user lists](#standard-list-files) from ipset, and the autohostlist.

When copying to `/opt/zapret2`, it sets the correct permissions for files and directories, even if they were corrupted (for example, by repacking in Windows) in the source location. To run it from a location with broken permissions, simply call `sh install_easy.sh`.

Binary files are only present in releases. They are missing after a `git clone`. If the `binaries` folder is absent, the installer will attempt to compile them. To do this, it requires a C compiler, `make`, and several dev packages. See `docs/compile` for details.

The actions performed by the installer for integration with various Linux versions are described below. You can opt out of the installer by performing these steps manually and configuring the [config file](#config-file).

### OpenWRT integration principles

1. Autostart.

```
ln -s /opt/zapret2/init.d/openwrt/zapret2 /etc/init.d
/etc/init.d/zapret2 enable
```

2. Updating firewall rules on interface up/down events.

```
ln -s /opt/zapret2/init.d/openwrt/90-zapret2 /etc/hotplug.d/iface
```

3. (fw3 only) Firewall integration.

```
ln -s /opt/zapret2/init.d/openwrt/firewall.zapret2 /etc
uci add firewall include
uci set firewall.@include[-1].path="/etc/firewall.zapret"
uci set firewall.@include[-1].reload=1
uci commit
```

4. List updates - a cron job calling `/opt/zapret2/ipset/get_config.sh` at a random time during the night every 2 days to update lists. This assumes the router runs 24/7.

### OpenWRT cheat sheet

- Start service: `/etc/init.d/zapret2 start`
- Stop service: `/etc/init.d/zapret2 stop`
- Restart service: `/etc/init.d/zapret2 restart`
- Service status: `/etc/init.d/zapret2 status`
- Disable autostart: `/etc/init.d/zapret2 disable`
- Enable autostart: `/etc/init.d/zapret2 enable`

### systemd integration principles

1. Autostart

```
cp /opt/zapret2/init.d/systemd/zapret2.service /lib/systemd/system
systemctl daemon-reload
systemctl enable zapret2
```

2. List update timer - runs at a random time of day every 2 days. It is designed for any system, including desktops that may only be powered on during the day.

```
cp /opt/zapret2/init.d/systemd/zapret2-list-update.* /lib/systemd/system
systemctl daemon-reload
systemctl enable zapret2-list-update.timer
systemctl start zapret2-list-update.timer
```

### systemd cheat sheet

- Start service: `systemctl start zapret2`
- Stop service: `systemctl stop zapret2`
- Restart service: `systemctl restart zapret2`
- Service status: `systemctl status zapret2`
- Disable autostart: `systemctl disable zapret2`
- Enable autostart: `systemctl enable zapret2`

### OpenRC integration principles

1. Autostart

```
ln -s /opt/zapret2/init.d/openrc/zapret2 /etc/init.d
rc-update add zapret2
```

2. List updates - a cron job to call `/opt/zapret2/ipset/get_config.sh` at a random time during the day every 2 days. This is designed for any system, including desktops that may only be powered on during the day.

### OpenRC cheat sheet

- Start service: `rc-service zapret2 start`
- Stop service: `rc-service zapret2 stop`
- Restart service: `rc-service zapret2 restart`
- Service status: `rc-service zapret2 status`
- Disable autostart: `rc-update del zapret2`
- Enable autostart: `rc-update add zapret2`

## Alternative installation on systemd

On classic Linux distributions with systemd, you can use the provided template unit `init.d/systemd/nfqws2@.service` to run nfqws2 instances.

1. `cp /opt/zapret2/init.d/systemd/nfqws2\@.service /lib/systemd/system`
2. `systemctl daemon-reload`
3. `mkdir /etc/zapret2`
4. Create a text file in `/etc/zapret2` containing the nfqws2 command-line parameters. The file should be named `INSTANCE.conf`, where `INSTANCE` is a name of your choice.
5. Enable autostart: `systemctl enable nfqws2@INSTANCE`
6. Start: `systemctl start nfqws2@INSTANCE`
7. Stop: `systemctl stop nfqws2@INSTANCE`
8. Restart: `systemctl restart nfqws2@INSTANCE`

This method does not apply iptables/nftables rules - you will have to handle that separately, as well as write the rules themselves. The rules must be placed somewhere so they are applied after the system starts. For example, you can create a separate systemd unit that runs a shell script or `nft -f /path/to/file.nft`.

# Other firmwares

For static binaries, the host environment doesn't matter: PC, Android, set-top box, router, or any other device. Any firmware or Linux distribution will work; static binaries run on everything. They only require a kernel with the necessary build options or modules. However, in addition to binaries, the project uses scripts that rely on certain standard utilities.

Main reasons why you cannot simply install this system on any device out of the box:
* Lack of shell access to the device
* Lack of root privileges
* Absence of a r/w partition for writing and persistent file storage
* No way to add items to autostart
* Absence of cron
* Non-disableable flow offload or other proprietary netfilter implementations
* Missing kernel modules or specific kernel build options
* Missing iptables modules (`/usr/lib/iptables/lib*.so`)
* Missing standard utilities (like `ipset`, `curl`) or their "stripped-down" (lightweight) versions
* A limited or non-standard `sh` shell

If your firmware provides everything required, you can adapt zapret for your device to one degree or another.

Rebuilding the kernel or its modules will likely be quite difficult. To do this, you would at least need the source code for your firmware. User-mode components can be added relatively painlessly if there is a place to store them. For devices that have a r/w area, the Entware project exists. Some firmwares even offer a simplified installation of Entware via a web interface. Entware provides a repository of user-mode components that are installed in `/opt`. These can compensate for the lack of software in the base firmware, with the exception of the kernel.

You can attempt to use the [SysV init script](#startup-scripts).
If the system reports missing basic programs, you should install them via Entware.
Before running the script, the path to these additional programs must be added to your `PATH`.

Note that Entware is patched to replace standard file paths like `/etc/passwd` with `/opt/etc/passwd`.
Zapret's static binaries are built without accounting for this, so the `--user` option may not work-the system looks for the user in `/etc/passwd` (which is on a read-only partition), while `adduser` adds users to `/opt/etc/passwd`.
Therefore, you may need to uncomment `WS_USER` in the [config](#config-file) and specify a user that already exists in `/etc/passwd`.

For Keenetic devices, there are additional critical nuances; without addressing them, `zapret` will either crash every few minutes or fail to work with UDP.
There are ready-made third-party solutions available for Keenetic integration.

A detailed description of settings for other firmwares is beyond the scope of this project.

OpenWrt is one of the few relatively full-featured Linux systems for embedded devices.
It was chosen for this project based on the following characteristics:
* Full root access to the device via shell. This is usually absent in factory firmwares but present in many alternative ones.
* Read/write (r/w) root partition. This is a nearly unique feature of OpenWrt. Factory and most alternative firmwares are built on a squashfs root (r/o), where configurations are stored in a specially formatted area of internal memory called NVRAM. Systems without an r/w root are severely limited; they cannot install software from repositories without complex workarounds and are primarily designed for users who are only slightly more advanced than average, offering fixed functionality managed through a web interface. Alternative firmwares can usually mount an r/w partition to some area of the file system, while factory firmwares typically only mount USB drives and even then, they may only support FAT and NTFS rather than Unix file systems.
* The ability to move the root file system to external media (extroot) or create an overlay on it.
* The presence of the `opkg` package manager and a software repository.
* Flow offloading is predictably, standardly, and selectively manageable, as well as disableable.
* All kernel modules are available in the repository and can be installed via `opkg`, eliminating the need to recompile the kernel.
* All `iptables` modules are available in the repository and can be installed via `opkg`.
* The repository contains a vast number of standard programs and additional software.
* The availability of an SDK, allowing you to compile any missing components.


# Windows

zapret was initially written for unix. It uses unix emulation layer cygwin on Windows to help migration.

If winws2 is run standalone cygwin1.dll is required in it's directory. If winws2 is run inside cygwin environment - cygwin1.dll must NOT be present in it's directory or it won't run.

cygwin emulate shared PID namespace and deliver signals only within one cygwin1.dll instance !
To send signals sending program (kill, killall) must be run with the same cygwin1.dll as winws2.

It's possible to install cygwin and use winws2 inside cygwin installation.
But it may be more comfortable to use [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle) which includes minimal cygwin.
cygwin prompt is pre-configured with aliases for blockcheck, blockcheck2, winws, winws2, winws2 with standard Lua scripts.

32-bit Windows versions are not supported by zapret-win-bundle.

## Windows 7

Requirements for Windows driver signing have changed in 2021.
Official free updates of Windows 7 ended in 2020.
After 2020 for the years paid updates were available (ESU).
One of the updates from ESU enables signatures used in WinDivert 2.2.2-A.
There are several options :

1. Take `WinDivert64.sys` and `WinDivert.dll` version `2.2.0-C` or `2.2.0-D` from [here](https://reqrypt.org/download) and replace existing files.

2. [Hack ESU](https://hackandpwn.com/windows-7-esu-patching)

3. Use "BypassESU" patcher. Google it by name.

4. Use [UpdatePack7R2](https://blog.simplix.info). If you are in Russia or Belarus temporary change region in Control Panel.

## Windows Server

To use `--ssid-filter` install wireless networking feature.
Run power shell as administrator and execute command `Install-WindowsFeature -Name Wireless-Networking`.
Then reboot the system.

## Windows ARM64

The main problem is lack of a signed WinDivert driver. Therefore, it is required to enable the test signature mode: 'bcdedit/set {current} testsigning on'.
There's unsigned WinDivert64.sys driver in [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle).
There is also cmd file for rolling the driver to the arm64 Win11.

Another problem is lack of cygwin for non-x86 platforms. However, win11 has x64 emulation, so you can use the x64 build, but with replaced WinDivert64.sys driver.
There is no need to replace WinDivert.dll - only WinDivert64.sys needs to be replaced. It's verified and confirmed working.

There is no x64 emulation on win10 arm64, but there is x86 32-bit emulation.
Therefore, theoretically you can use the win32 variant and put the WinDivert64.sys driver for arm64 to the same dir.
This hasn't been verified.
