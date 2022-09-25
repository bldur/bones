# bones
# scripts and no fresh meat

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

TODO:
Making it pretty, separating bogon, cidr blocks and single ip in separate ipsets.
Have now seen 224.0.0.0/3 be converted to an ip range, double sets would perhaps fool proof.
And generally making things pretty.

And must object the quirky things with nft ipset that does this:
"224.0.0.0-255.255.255.255 }"

So, BUGS:

Depending on the mood of nftables ipset and whats in blocklists, it can delete 224.0.0.0-255.255.255.255 and add 224.0.0.0/3 every run of the script.
It now deletes silently, and show the cidr address in the diff.
