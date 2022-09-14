# bones
# scripts and no fresh meat

This is just a mess of with reasonable regex, two awk programs that are useful and link.

# time sh wrt-badhost.sh 2>wrt.log

real	1m6.613s
user	0m39.809s
sys	0m11.373s

/tmp/badhost# wc -l blocklist_ipv4.jiaAej 
47767 blocklist_ipv4.jiaAej

without downloading it's below 30 seconds and works with openwrt 22.03.
creating a diff prefixed with add and delete from processing
output of nft list and downloaded blocklists.

so just sharing the mess using awk, sort, diff and grep and doesn't do nft flush
and don't get collision when adding and deleting ip's.

May not be catching all CIDR ip's and expanding them to single ip's fully.
A separate ipset would bee better for CIDR addresses due to interval shenanigans.

Also batching addition and deletion to ipset to avoid a list length limit.
