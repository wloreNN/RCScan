# Scope and Safety Model

This document describes the implemented M1 validation model. It is a technical
guardrail, not legal advice and not proof of authorization.

## Accepted target forms

- One IPv4 address, for example `192.168.1.10`
- One strict IPv4 network, for example `192.168.1.0/24`
- One syntactically valid hostname, normalized to lowercase with a trailing dot
  removed

URLs, paths, embedded ports, whitespace, IPv6, malformed addresses, and host-bit-set
CIDRs are rejected. Parsing does not resolve names or access the network.

## Containment matrix

- IP scope contains only the identical IP target.
- Network scope contains IP targets within it and network targets that are its
  subnets.
- Hostname scope contains only the identical normalized hostname target.
- IP/network scope and hostname targets never contain one another.

There is no wildcard hostname scope and no implicit subdomain authorization. A
hostname's DNS result is neither looked up nor inherited into scope.

## Policy layers

Containment and policy are separate and both must pass:

- RFC 1918 networks (`10/8`, `172.16/12`, and `192.168/16`) are treated as private.
- IPv4 values outside those three ranges are conservatively treated as public.
- Loopback (`127/8` and `localhost`) is a separate class, blocked unless enabled by
  CLI opt-in or configuration.
- Every hostname is treated as public because M1 has no DNS or ownership-verification
  system. Public targets are blocked unless configuration explicitly permits them.

Special-use IPv4 ranges outside RFC 1918 are therefore treated as public by this
specific policy. Enabling public targets through `--allow-public-targets` for one
scan, or through explicit configuration, means only that policy classification may
pass; exact scope and authorization confirmation remain mandatory.

## Limits

The default request supports at most 256 deduplicated targets and 4,096 unique ports.
Configuration may set target limits from 1 to 65,536 and port limits from 1 to 65,535.
Ports themselves must be integers from 1 to 65,535.

Target files are UTF-8 and use one entry per line. Blank lines and comments beginning
with `#` after optional leading whitespace are ignored. Duplicate normalized entries
do not count twice.

## Non-goals in M1

M1 does not prove ownership, evaluate contracts, authenticate an operator, persist an
authorization record, resolve hostnames, discover assets, or initiate traffic. The
operator remains responsible for keeping authorization evidence outside RCScan.
