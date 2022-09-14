#!/bin/sh

LC_ALL=C

set -x

# IP blacklisting script for openwrt nftables
# started with a openwrt forum script.
# mangled with and made into an unreadable mess using following sources with least effort:
# https://www.unix.com/shell-programming-and-scripting/233825-convert-ip-ranges-cidr-netblocks.html
# https://www.geoghegan.ca/pfbadhost.html
# copyleft, restrictions from above sources may apply.

AWK_CIDR32() {
awk -e '
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

BEGIN{
       FS=" , | - "
       print "-N cidr nethash --maxelem 260000\n-N single iphash --maxelem 60000\n"
}
 
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

AWK_IPRANGE() {
awk -e '
# Convert IP ranges to CIDR notation
# awk, gawk, mawk compatible

function range2cidr(ipStart, ipEnd, result, bits, mask, newip) {
    bits = 1
    mask = 1
    while (bits < 32) {
        newip = bit_or(ipStart, mask)
        if ((newip > ipEnd) || ((bit_lshift(bit_rshift(ipStart,bits),bits)) != ipStart)) {
            bits--
            mask = bit_rshift(mask,1)
            break
        }
        bits++
        mask = bit_lshift(mask,1)+1
    }
    newip = bit_or(ipStart, mask)
    bits = 32 - bits
    result = (result)?result ORS dec2ip(ipStart) "/" bits : dec2ip(ipStart) "/" bits
    if (newip < ipEnd) result = range2cidr(newip + 1, ipEnd,result)
    return result
}

# convert dotted quads to long decimal ip
# int ip2dec("192.168.0.15")
#
function ip2dec(ip, slice) {
    split(ip, slice, /[.]/)
    return (slice[1] * 2^24) + (slice[2] * 2^16) + (slice[3] * 2^8) + slice[4]
}

# convert decimal long ip to dotted quads
# str dec2ip(1171259392)
#
function dec2ip(dec, ip, quad) {
    for (i=3; i>=1; i--) {
        quad = 256^i
        ip = ip int(dec/quad) "."
        dec = dec%quad
    }
    return ip dec
}

# Bitwise OR of var1 and var2
function bit_or(a, b, r, i, c) {
    for (r=i=0;i<32;i++) {
        c = 2 ^ i
        if ((int(a/c) % 2) || (int(b/c) % 2)) r += c
    }
    return r
}

# Rotate bytevalue left x times
function bit_lshift(var, x) {
    while(x--) var*=2;
    return var;
}

# Rotate bytevalue right x times
function bit_rshift(var, x) {
    while(x--) var=int(var/2);
    return var;
}

function sanitize(ip) {
    split(ip, slice, /[.]/)
    return slice[1]/1 "." slice[2]/1 "." slice[3]/1 "." slice[4]/1
}

BEGIN{
    FS=" - |-|:"
}

# sanitize ips
!/^#/ && NF {
    f1 = sanitize($(NF-1))
    f2 = sanitize($NF)
    print range2cidr(ip2dec(f1), ip2dec(f2))
}

END {print ""}
'
}

GREP_IPV4() {
	grep -E -o -- '((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])(/(3[0-2]|[1-2][[:digit:]]|[1-9]))?'
}

GREP_IPV6() {
	grep -E  -v -- '^#|^;|^[[:space:]]*#|^[[:space:]]*;|^[[:space:]]*$' "${blocklist}" | awk -- '{print $1}' | sort -u | grep -E -x -- '(([[:xdigit:]]{1,4}:){7,7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,7}:|([[:xdigit:]]{1,4}:){1,6}:[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,5}(:[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}:){1,4}(:[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}:){1,3}(:[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}:){1,2}(:[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}:((:[[:xdigit:]]{1,4}){1,6})|:((:[[:xdigit:]]{1,4}){1,7}|:)|[fF][eE]80:(:[[:xdigit:]]{0,4}){0,4}%[[:alnum:]]{1,}|::([fF]{4}(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])|([[:xdigit:]]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]]))(/(12[0-8]|1[0-1][[:digit:]]|[1-9][[:digit:]]{0,1}))?'
}

DIFFER() {
	 diff -N --old-line-format=$'delete %l\n' --new-line-format=$'add %l\n'  --unchanged-line-format='' "$@"
}

function readlines () {
    local N="$1"
    local line
    local rc="1"

    # Read at most N lines
    for i in $(seq 1 $N)
    do
        # Try reading a single line
        read line
        if [ $? -eq 0 ]
        then
            # Output line
            echo $line
            rc="0"
        else
            break
        fi
    done

    # Return 1 if no lines where read
    return $rc
}

GREP_IPV4_NO_CIDR() {
	grep -E -o "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
}

GREP_IPV4_RANGE_NO_CIDR() {
	grep -E -o "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}?\s-?\s(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
}

	

# some blocklists 
URLS="
https://www.team-cymru.org/Services/Bogons/bogon-bn-nonagg.txt
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
https://www.blocklist.de/downloads/export-ips_all.txt

https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
https://rules.emergingthreats.net/blockrules/compromised-ips.txt
https://www.binarydefense.com/banlist.txt
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset
https://isc.sans.edu/api/threatlist/shodan/?text
https://feodotracker.abuse.ch/downloads/ipblocklist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
https://www.spamhaus.org/drop/dropv6.txt
https://www.spamhaus.org/drop/drop.txt
https://www.spamhaus.org/drop/edrop.txt
https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt
https://www.stopforumspam.com/downloads/listed_ip_1_ipv46.gz
https://ozgur.kazancci.com/ban-me.txt
https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset
"

# create set to contain ip addresses
if ! nft list set inet fw4 blackhole6 > /dev/null 2> /dev/null; then
  nft add set inet fw4 blackhole { type ipv4_addr\; }
  nft add set inet fw4 blackhole6 { type ipv6_addr\; }
fi

# insert chain to drop where source address in blackhole set
if ! nft list chain inet fw4 input_wan > /dev/null 2> /dev/null | grep @blackhole6; then
  nft insert rule inet fw4 input_wan ip saddr @blackhole drop
  nft insert rule inet fw4 input_wan ip6 saddr @blackhole6 drop
fi

# temp folder and keep a few days
export TMPDIR="/tmp/badhost"
mkdir -p $TMPDIR
#find $TMPDIR -type f -mtime +2 -delete

blocklist=$(mktemp -t blocklist.XXXXXX)

blocklist_ipv4=$(mktemp -t blocklist_ipv4.XXXXXX)
#persistent_blocklist_ipv4="/var/lib/wrt-badhost_ipv4"
#persistent_blocklist_ipv6="/var/lib/wrt-badhost_ipv4"
diff_add_del_ipv4=$(mktemp -t diff_add_del_ipv4.XXXXXX)
nft_ipv4=$(mktemp -t nft_ipv4.XXXXXX)
nft_ipv4_list=$(mktemp -t nft_ipv4_list.XXXXXX)

#blocklist_ipv6=$(mktemp -p $TMPDIR)
#diff_add_del_ipv6=$(mktemp -p $TMPDIR)
#nft_ipv6_list=$(mktemp -p $TMPDIR)

# download the blocklist
for url in $URLS; do
    wget -q -O - "$url" 2> /dev/null
    echo
done  > "${blocklist}"

# get an ip list from the nft set
nft list set inet fw4 blackhole  > "${nft_ipv4}"
#nft list set inet fw4 blackhole6 | GREP_IPV6 | sort -u > "${nft_ipv6_list}"


# stupid nft regex
# give me ip with CIDR
# grep -E -o "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/.?."
# give me ip with ranges
# grep -E -o "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}-(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
#


# ip ranges are fine, add unsorted
# deal with stupid nft ipset quirks.
# CIDR, and usually /31 ips need special treatment as individual delete don't work.
# all of which irks in the day of vxlan and other things to avoid it stealing ipv4 addressess.
# whole mess would make more sense counting in binary for ip addresses minus the rest
cat "${nft_ipv4}" | GREP_IPV4 | AWK_CIDR32 | GREP_IPV4_NO_CIDR | sort -u > "${nft_ipv4_list}"



# more CIDR ips and fix those ranges first.


# create two column list of added and removed
# "${blocklist}"

cat "${blocklist}" | GREP_IPV4 | AWK_CIDR32 | GREP_IPV4_NO_CIDR | sort -u > "${blocklist_ipv4}"
#cat "${blocklist}" | GREP_IPV6 | sort -u > "${blocklist_ipv6}"

#if [ $(nft list set inet fw4 blackhole | wc -l) -le 100 ] ; then echo yes ;fi
#if [ -f ${persistent_blocklist} ] ; then
#cat "${blocklist}" | GREP_IPV4 | AWK_CIDR32 | sort -u > "${persistent_blocklist}"
#fi
#treating missing file as empty
#else diff


# ipv4 update nft set
#NFT_ADD_IPV4=$(cut -d ' ' -f 7 "${diff_add_del_ipv4}" | grep ">" | GREP_IPV4)
#NFT_DEL_IPV4=$(cut -f 1 "${diff_add_del_ipv4}" | grep "<" | GREP_IPV4)
#grep add "${diff_add_del_ipv4}" | cut -f 2 | xargs -L 10000 nft add element inet fw4 blackhole \{ $(AWK_DELIM_COMMA_SPACE)
#awk '$1=$1' RS= OFS=, infile

# pull /31 etc from nft ipset and delete.
# first prepare a list without them.
#grep -E -v "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/.?[0-1]" "${nft_ipv4}" | GREP_IPV4 | sort -u | AWK_IPRANGE | sort -u >> "${nft_ipv4_list}"
# also treat missing file as empty for clutching
DIFFER "${nft_ipv4_list}" "${blocklist_ipv4}" | sort -u > "${diff_add_del_ipv4}"
# now delete the mostly /31 ranges by excluding /32
#grep -E -o "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/[1-9]?[0-1]" "${nft_ipv4}" | while batch=$(readlines 100) ; do
#	echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
#		nft delete element inet fw4 blackhole { $line }
#	done
#done


# and we are fairly certain we only send valid IP's to nft
grep delete "${diff_add_del_ipv4}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
        echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
        nft delete element inet fw4 blackhole { $line }
        done
done
grep add "${diff_add_del_ipv4}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
	echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
	nft add element inet fw4 blackhole { $line }
	done
done



#rm -rf /tmp/badhost
#mv "${blocklist_ipv4}" "${persistent_blocklist}"


#grep delete "${diff_add_del_ipv4}" | cut -d ' ' -f 2 | xargs -n 1000 -d ',' | AWK_DELIM_COMMA_SPACE | while read line; do
#        nft delete element inet fw4 blackhole { $line }
#done

#if [ ! -z "$NFT_DEL_IPV4" ]; then
#echo  del element inet fw4 blackhole "{ $NFT_DEL_IPV4 }" | nft -f -
#fi
# ipv6 update nft set
#NFT_ADD_IPV6=$(awk '{print $3}' "${diff_add_del_ipv6}" | AWK_DELIM_COMMA_SPACE)
#NFT_DEL_IPV6=$(awk '{print $1}' "${diff_add_del_ipv6}" | AWK_DELIM_COMMA_SPACE)

#nft add element inet fw4 blackhole6 { $NFT_ADD_IPV6 }
#nft del element inet fw4 blackhole6 { $NFT_DEL_IPV6 }

#rm -rf /tmp/badhost

# done!
