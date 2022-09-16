# bones
# scripts and no fresh meat

This is just a mess of with reasonable regex, two awk programs mangled coaxed to work.
AWK programs taken from UNIX.com and regex from pf-badhost and another from oreilly.com.

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
