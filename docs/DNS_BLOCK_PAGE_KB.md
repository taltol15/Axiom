# Axiom DNS Block Page Knowledge Base

## What the Feature Does

When a DNS policy blocks a domain, Axiom can return a controlled IPv4 address
instead of `NXDOMAIN` or `REFUSED`. A lightweight HTTP listener on the DNS node
then displays a branded explanation page.

This mode is called `Branded block page` in the Management Console and
`sinkhole` in the serialized policy.

## Block Response Options

| Option | DNS result | User experience | Typical use |
| --- | --- | --- | --- |
| NXDOMAIN | Domain does not exist | Browser shows name-resolution error | Minimal exposure, no page |
| REFUSED | Resolver refuses query | Browser shows resolution failure | Explicit DNS refusal and troubleshooting |
| Branded block page | A record points to block-page IP | HTTP page explains the block | Help-desk friendly policy enforcement |

## HTTP and HTTPS Behavior

### HTTP

The browser resolves the blocked domain to the Axiom block-page IP, connects to
TCP 80, sends the original domain in the HTTP `Host` header, and receives the
custom page.

### HTTPS

The browser starts TLS before sending an HTTP request. It expects a certificate
valid for the original blocked domain. Axiom does not impersonate arbitrary
domains and cannot present a universally valid certificate, so the browser will
normally show a certificate error before any custom page can be displayed.

This is correct security behavior. A clean HTTPS block page requires a separate,
organization-approved TLS inspection platform with a trusted enterprise CA.

## Policy Fields

| Field | Meaning |
| --- | --- |
| Serve block page | Enables the local HTTP listener when branded mode is active |
| Block Page IPv4 | Blank means each DNS node's own listener IP; explicit IP targets an external page/VIP |
| Organization Name | Brand or security team shown at the top |
| Accent Color | Valid `#RRGGBB` color used by the page |
| Title | Main policy message; UTF-8 and Hebrew supported |
| Message | Detailed explanation; UTF-8, line breaks and Hebrew supported |
| Support Text | Help-desk instruction or contact label |
| Support URL | Optional `https://`, `http://`, or `mailto:` destination |
| Custom Logo | Embedded PNG, JPEG, or WebP, maximum 256 KB decoded |

Selecting `Use Axiom logo` removes the custom image. `Reset Axiom defaults`
restores all standard Axiom text and colors in the editor; click `Save and
apply` to persist and push those values.

## Air-Gapped Design

The default page has no external assets. A custom logo is embedded into the DNS
policy as a data URL and distributed to the nodes in the encrypted policy
payload. The browser does not need internet access to render the page.

## Security Controls

The node HTTP server applies:

- A 16 KB request-header limit.
- A five-second request read timeout.
- A 256-concurrent-connection limit.
- `GET` and `HEAD` only.
- HTML escaping for policy text and requested host names.
- A restrictive Content Security Policy.
- `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- No cache and no referrer forwarding.
- No scripts, forms, remote fonts, or remote images.

The DNS service remains available if TCP 80 cannot bind. The node logs a warning
and retries the block-page listener every 15 seconds.

## Network Requirements

Allow client networks to reach the effective block-page IPv4 on TCP 80.

In automatic cluster mode, allow TCP 80 to every DNS node because each node may
answer with its own address. If using an external block-page VIP, allow TCP 80
to that VIP instead.

## Validation Procedure

1. Open `DNS Security` in the Management Console.
2. Set `Blocked Domain Action` to `block`.
3. Set `Block Response` to `Branded block page`.
4. Leave `Block Page IPv4` blank for automatic node-local mode.
5. Add `blocked-test.example` to Blocked Domains.
6. Customize text/logo if desired and click `Save and apply`.
7. Confirm every DNS node acknowledges the push.
8. On a client using Axiom DNS, query:

```bash
nslookup blocked-test.example DNS_NODE_IP
```

9. The returned A record should equal that DNS node's listener IPv4.
10. Add a temporary local hosts-test domain under a controlled domain or use a
    real test FQDN, then open `http://that-domain/` in a browser.
11. Confirm the page, logo, Hebrew direction, support link and audit event.
12. Open the HTTPS version and document the expected certificate warning.

## Troubleshooting Commands

On a DNS node:

```bash
sudo ss -lntup | egrep ':53|:80|:9443'
sudo journalctl -u axiom -n 200 -l --no-pager | egrep -i 'block page|DNS|policy'
sudo grep -nA20 '\[dns.policy.block_page\]' /etc/axiom/axiom.toml
```

From a client:

```bash
nslookup blocked-test.example DNS_NODE_IP
curl -v -H 'Host: blocked-test.example' http://DNS_NODE_IP/
```

If DNS returns the node address but `curl` fails, check host firewall, network
ACLs, routing and whether another service owns TCP 80.
