# bones
# scripts and no fresh meat

Still no go on silly netblocks after all...
Why that went by silently, TBD.

Works for openwrt 22.03 with these two programs:
https://github.com/jrlevine/grepcidr3
https://gitlab.com/prips/prips

netblocks smaller than 24 get converted to single ip.
several rounds of regex to process.
checks for overlapping netblocks and unique addresses to not get nft ipset crashes.

never flushes, adds and removes addresses.
keeps last aggregated raw blocklist in /tmp/badhost

has whitelist and support for logging addresses one want to be alerted about found in blocklists.
where STONITH from not whitelisting an addresses on alert list.
shoot the offending node in the head.

failure to download will clear nft ipset.
