# unbound-dns-filter (ABANDONED)
Python Module for UNBOUND to filter DNS requests/responses

This is basically a rewrite from scratch of <a href="https://www.github.com/cbuijs/unbound-dns-firewall">unbound-dns-firewall</a> with all lessons learned to make it way more lean, less cluttered and going back to basics on features.

It pretty much self-explanatory, it uses black/whitelists and accepts domain, ip-addresses (including CIDR) and regex definitions.

To-Do:

- Documentation/Wiki.
- RPZ feature to load RPZ DB-Style (BIND Syntax) zone either from file or via zone-transfer
- Caching of response/rcodes other to NOERROR.
- Optimizations of parsing response records
- Debug logging.
- etc...
