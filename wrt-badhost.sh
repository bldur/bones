#!/bin/sh

set -x

# IP blacklisting script for openwrt nftables
# started with a openwrt forum script.
# mangled with and made into an unreadable mess using following sources with least effort:
# https://www.unix.com/shell-programming-and-scripting/233825-convert-ip-ranges-cidr-netblocks.html
# https://www.geoghegan.ca/pfbadhost.html
# copyleft, restrictions from above sources may apply.

GAWK_CIDR32() {
gawk --source='
function range2cidr(ipStart, ipEnd,  bits, mask, newip) {
    bits = 1
    mask = 1
    result = ""
    while (bits < 32) {
        newip = or(ipStart, mask)
        if ((newip>ipEnd) || ((lshift(rshift(ipStart,bits),bits)) != ipStart)) {
           bits--
           mask = rshift(mask,1)
           break
        }
        bits++
        mask = lshift(mask,1)+1
    }
    newip = or(ipStart, mask)
    bits = 32 - bits
    result = result dec2ip(ipStart) "/" bits
    if (newip < ipEnd) result = result "\n" range2cidr(newip + 1, ipEnd)
    return result
}

# convert dotted quads to long decimal ip
#       int ip2dec("192.168.0.15")
#
function ip2dec(ip,   slice) {
        split(ip, slice, ".")
        return (slice[1] * 2^24) + (slice[2] * 2^16) + (slice[3] * 2^8) + slice[4]
}

# convert decimal long ip to dotted quads
#       str dec2ip(1171259392)
#
function dec2ip(dec,    ip, quad) {
        for (i=3; i>=1; i--) {
                quad = 256^i
                ip = ip int(dec/quad) "."
                dec = dec%quad
        }
        return ip dec
}


# convert decimal ip to binary
#       str dec2binary(1171259392)
#
function dec2binary(dec,    bin) {
        while (dec>0) {
                bin = dec%2 bin
                dec = int(dec/2)
        }
        return bin
}

# Convert binary ip to decimal
#       int binary2dec("1000101110100000000010011001000")
#
function binary2dec(bin,   slice, l, dec) {
        split(bin, slice, "")
        l = length(bin)
        for (i=l; i>0; i--) {
                dec += slice[i] * 2^(l-i)
        }
        return dec
}

# convert dotted quad ip to binary
#       str ip2binary("192.168.0.15")
#
function ip2binary(ip) {
        return dec2binary(ip2dec(ip))
}


# count the number of ips in a dotted quad ip range
#       int countIp ("192.168.0.0" ,"192.168.1.255") + 1
#
function countQuadIp(ipStart, ipEnd) {
        return (ip2dec(ipEnd) - ip2dec(ipStart))
}


# count the number of ips in a CIDR block
#       int countCidrIp ("192.168.0.0/12")
#
function countCidrIp (cidr) {
        sub(/.+\//, "", cidr)
        return 2^(32-cidr)
}

function sanitize(ip) {
        split(ip, slice, ".")
        return slice[1]/1 "." slice[2]/1 "." slice[3]/1 "." slice[4]/1
}

#BEGIN{
#       FS=" , | - "
#       print "-N cidr nethash --maxelem 260000\n-N single iphash --maxelem 60000\n"
#}

# sanitize ips
{$1 = sanitize($1); $2 = sanitize($2)}

# range with a single IP
#$1==$2 {printf "-A single %s\n", $1} 

# ranges with multiple IPs
$1!=$2{print range2cidr(ip2dec($1), ip2dec($2))}


# footer
#END {print "COMMIT\n"}
'
}

# some blocklists 
URLS="
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://www.binarydefense.com/banlist.txt
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
https://isc.sans.edu/api/threatlist/shodan/?text
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
https://lists.blocklist.de/lists/22.txt
https://lists.blocklist.de/lists/ssh.txt
https://lists.blocklist.de/lists/bruteforcelogin.txt
https://www.blocklist.de/downloads/export-ips_all.txt
"

# create set to contain ip addresses
if ! nft list set inet fw4 blackhole6 > /dev/null 2> /dev/null; then
  nft add set inet fw4 blackhole { flags interval\; type ipv4_addr\; auto-merge\; }
  nft add set inet fw4 blackhole6 { flags interval\; type ipv6_addr\; auto-merge\; }
fi

# insert chain to drop where source address in blackhole set
if ! nft list chain inet fw4 input_wan > /dev/null 2> /dev/null | grep @blackhole6; then
  nft insert rule inet fw4 input_wan ip saddr @blackhole drop
  nft insert rule inet fw4 input_wan ip6 saddr @blackhole6 drop
fi

# temp filename
blocklist=$(mktemp)

# add new elements to the set
for url in $URLS; do
    # download the blocklist
    wget -q -O - "$url" 2> /dev/null
    echo
done | grep -v ^# | grep -v ^$ > "${blocklist}"



# clear old ipv4
nft flush set inet fw4 blackhole

# create ipv4 block rules
# replace with matching
grep -E -o -- '((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])(/(3[0-2]|[1-2][[:digit:]]|[1-9]))?' "${blocklist}" | sort -u | GAWK_CIDR32 | awk -v RS="" '{gsub (/\n/,", ")}1' | while read line; do
  echo add element inet fw4 blackhole "{ $line }"
done | nft -f -

# clear old ipv6
nft flush set inet fw4 blackhole6

# create ipv6 block rules
# replace with matching
grep -E  -v -- '^#|^;|^[[:space:]]*#|^[[:space:]]*;|^[[:space:]]*$' "${blocklist}" | gawk -- '{print $1}' | sort -u | grep -E -x -- '(([[:xdigit:]]{1,4}:){7,7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,7}:|([[:xdigit:]]{1,4}:){1,6}:[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,5}(:[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}:){1,4}(:[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}:){1,3}(:[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}:){1,2}(:[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}:((:[[:xdigit:]]{1,4}){1,6})|:((:[[:xdigit:]]{1,4}){1,7}|:)|[fF][eE]80:(:[[:xdigit:]]{0,4}){0,4}%[[:alnum:]]{1,}|::([fF]{4}(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])|([[:xdigit:]]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]]))(/(12[0-8]|1[0-1][[:digit:]]|[1-9][[:digit:]]{0,1}))?' | while read line; do
  echo add element inet fw4 blackhole6 { $line }
done | nft -f -

# cleanup
rm "${blocklist}"

