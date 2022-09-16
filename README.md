# bones
# scripts and no fresh meat

This is just a mess of with reasonable regex, two awk programs that are useful and link.

# time sh wrt-badhost.sh

real	0m35.103s
user	0m27.306s
sys	0m5.850s

Here it downloaded 644 KB blocklist text involving 37119 IPv4 addresses.
Created a diff of NFT ipset and compared.

Adding 50 IP's to the set, and removing 0, as none had been removed since last download.

And empty blocklist file is the same as removing or flushing the ipset.
