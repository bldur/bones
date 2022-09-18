# bones
# scripts and no fresh meat

Awk needs to be shafted unless someone that knows awk well write up.

These two programs:
https://github.com/jrlevine/grepcidr3
https://gitlab.com/prips/prips

Which together with generic grep, sort and diff can do what i want.

# broken without above.

Told runtime for VoIPBL voipbl.org/ on i5 is 7 seconds on openwrt 22.03 using nft.

Works such that giving it a blank blocklist will remove all ip's from the ipset.

This is just a mess of with reasonable regex, two awk programs mangled to work.
AWK programs taken from UNIX.com and regex from pf-badhost and another from oreilly.com.

Function to batch process from stackexchange, etc.
So mostly combining and finding the simple, dumb, old and reasonably fast.

Easy to adapt and change, as there is no "meat", just basic functionality bones.
Where perhaps only IPv4 is useful for public blocklists.
A missing feature is whitelisting, which grep -vf file1 downloaded_lists_parsed could do.

Focus is on greedily coaxing and forcing individual ip's in the blocklist.
If it can't convert a CIDR /32 all /xx are stripped.


On ARM64 Cortex 72A clocked to 1Ghz.

# time sh wrt-badhost.sh

real	0m35.103s
user	0m27.306s
sys	0m5.850s

Here it downloaded 644 KB blocklist text involving 37119 IPv4 addresses.
Created a diff of NFT ipset and compared.

Adding 50 IP's to the set, and removing 0, as none had been removed since last download.

And empty blocklist file is the same as removing or flushing the ipset.

# puzzling intermittently

Haven't myself tested just giving it various /24 to properly test everything involved
and what it does with /8 apart from noticing that it is not quite right and for ipv4 ipset
with interval flag turned on and not stripping this.

It moves away from greedily catch-all where perhaps various service specific blocklists for log spam.
