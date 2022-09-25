#!/bin/sh

#turn off to not see what script does
#set -x

# IP blacklisting script for openwrt nftables
# started with a openwrt forum script.
# mangled with and made into an unreadable mess using following sources with least effort:
# https://www.unix.com/shell-programming-and-scripting/233825-convert-ip-ranges-cidr-netblocks.html
# https://www.geoghegan.ca/pfbadhost.html
# copyleft, restrictions from above sources may apply.
# and went BSD type from those choices.

# only whitelisting ipv4 currently, don't have to overlap with alarm list.
# shoot yourself, failure to download is the same as flushing ipset.
WHITELIST_FILE=""
# does logger and ip found in raw blocklist
# as logger -s "ALERT: $i found in blocklists"
# relies on grepcidr and takes raw blocklist and takes also ipv6
BLOCKLIST_ALARM=""

URLS="
http://www.voipbl.org/update/
https://lists.blocklist.de/lists/all.txt
https://www.team-cymru.org/Services/Bogons/bogon-bn-nonagg.txt
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
  nft add set inet fw4 blackhole { type ipv4_addr\; flags interval\; }
  nft add set inet fw4 blackhole6 { type ipv6_addr\; flags interval\; }
fi

# insert chain to drop where source address in blackhole set
if ! nft list chain inet fw4 input_wan | grep -q blackhole; then
  nft insert rule inet fw4 input_wan ip saddr @blackhole reject
  nft insert rule inet fw4 input_wan ip6 saddr @blackhole6 reject
fi

# temp folder and keep a few days
export TMPDIR="/tmp/badhost/wrk"
mkdir -p $TMPDIR
#find $TMPDIR -type f -mtime +2 -delete

# here begins populating ipsets inet fw4 blackhole and blackhole6

GREP_IPV4() {
	grep -E -o -- '((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])(/(3[0-2]|[1-2][[:digit:]]|[1-9]))?'
}

GREP_V_COM() {
	grep -E  -v -- '^#|^;|^[[:space:]]*#|^[[:space:]]*;|^[[:space:]]*$'
}
#| awk -- '{print $1}' | sort -u |
GREP_IPV6() {
	grep -E -x -- '(([[:xdigit:]]{1,4}:){7,7}[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,7}:|([[:xdigit:]]{1,4}:){1,6}:[[:xdigit:]]{1,4}|([[:xdigit:]]{1,4}:){1,5}(:[[:xdigit:]]{1,4}){1,2}|([[:xdigit:]]{1,4}:){1,4}(:[[:xdigit:]]{1,4}){1,3}|([[:xdigit:]]{1,4}:){1,3}(:[[:xdigit:]]{1,4}){1,4}|([[:xdigit:]]{1,4}:){1,2}(:[[:xdigit:]]{1,4}){1,5}|[[:xdigit:]]{1,4}:((:[[:xdigit:]]{1,4}){1,6})|:((:[[:xdigit:]]{1,4}){1,7}|:)|[fF][eE]80:(:[[:xdigit:]]{0,4}){0,4}%[[:alnum:]]{1,}|::([fF]{4}(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])|([[:xdigit:]]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[[:digit:]]){0,1}[[:digit:]]))(/(12[0-8]|1[0-1][[:digit:]]|[1-9][[:digit:]]{0,1}))?'
}

# not perfect, takes 1.2.3.4.5 as 2.3.4.5, spaces, new lines from back
GREP_IPV4_NO_CIDR() {
	 grep -E -o -- "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}($|\s)"
}

# matches 0.0.0.0-0.0.0.0 and 0.0.0.0 - 0.0.0.0
# not 0.0.0.0-
#0.0.0.0
# or anything not space and dash, and doesn't understand / or --
# warning, accepts up to 20 spaces or tabs on either side of -
# as for comlete documentation of these:
# https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
GREP_IPV4_RANGE_NO_CIDR() {
	grep -E -o -- "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(\b\s{0,20}-\s{0,20})(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
}

# regex to get all ipv4 /24 or bigger, or /25 until /32
GREP_CIDR_0_24() {
	grep -E -o -- "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b/([0-9]\>|[1][0-9]\>|[2][0-4]\>)"
}

GREP_CIDR_25_32() {
	grep -E -o -- "(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}([/][2][5-9]|[/][3][0-2])\>"
}



DIFFER() {
	 diff -N --old-line-format=$'del %l\n' --new-line-format=$'add %l\n'  --unchanged-line-format='' "$@"
}

# a function to use in while loops to batch process.
# something faster or simpler would be great, but may bloat dependencies.
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

	


blocklist=$(mktemp -t blocklist.XXXXXX)

blocklist_ipv4=$(mktemp -t blocklist_ipv4.XXXXXX)
blocklist_ipv6=$(mktemp -t blocklist_ipv6.XXXXXX)
#persistent_blocklist_ipv4="/var/lib/wrt-badhost_ipv4"
#persistent_blocklist_ipv6="/var/lib/wrt-badhost_ipv4"
diff_add_del_ipv4=$(mktemp -t diff_add_del_ipv4.XXXXXX)
diff_add_del_ipv6=$(mktemp -t diff_add_del_ipv6.XXXXXX)
nft_ipv4=$(mktemp -t nft_ipv4.XXXXXX)
nft_ipv4_list=$(mktemp -t nft_ipv4_list.XXXXXX)
nft_ipv6=$(mktemp -t nft_ipv6.XXXXXX)
nft_ipv6_list=$(mktemp -t nft_ipv6_list.XXXXXX)
cidr_ipv4=$(mktemp -t cidr_ipv4.XXXXXX)
cidr_ipv4_unmerge=$(mktemp -t cidr_ipv4_unmerge.XXXXXX)
single_ipv4=$(mktemp -t single_ipv4.XXXXXX)
single_nft_ipv4=$(mktemp -t single_nft_ipv4.XXXXXX)
cidr_nft_ipv4=$(mktemp -t cidr_nft_ipv4.XXXXXX)
diff_single_ipv4=$(mktemp -t diff_single_ipv4.XXXXXX)
diff_cidr_ipv4=$(mktemp -t diff_cidr_ipv4.XXXXXX)
diff_input_nft_ipv4=$(mktemp -t diff_input_nft_ipv4.XXXXXX)
diff_input_blocklist_ipv4=$(mktemp -t diff_input_blocklist_ipv4.XXXXXX)
single_cidr_ipv4=$(mktemp -t single_cidr_ipv4.XXXXXX)

#blocklist_ipv6=$(mktemp -p $TMPDIR)
#diff_add_del_ipv6=$(mktemp -p $TMPDIR)
#nft_ipv6_list=$(mktemp -p $TMPDIR)

# download the blocklist
for url in $URLS; do
    wget -q -O - "$url" 2> /dev/null
    echo
done  > "${blocklist}"

echo downloaded blocklists $(date)

# get an ip list from the nft set
#nft list set inet fw4 blackhole  > "${nft_ipv4}"
#cat "${nft_ipv4}" | GREP_IPV4 | AWK_CIDR32 | GREP_IPV4_NO_CIDR | sort -u > "${nft_ipv4_list}"

# just do this twice, once for ip ranges and prips convert them to CIDR.
# something is weird with nft, as these ranges are never added.
nft list set inet fw4 blackhole | GREP_V_COM | awk '$1=$1' RS="," OFS="\n" | grep -v "-" |GREP_IPV4 > "${nft_ipv4}"
nft list set inet fw4 blackhole6 | GREP_V_COM | awk '$1=$1' RS="," OFS="\n" | GREP_IPV6 | sort -u > "${nft_ipv6_list}"

# just in case of auto-merge, hmm, two ipsets

# check
if test -s "${BLOCKLIST_ALARM}"; then
        cat "${BLOCKLIST_ALARM}" | while read line ; do
                grepcidr -i $line "${blocklist}" && logger "ALERT: $line found in blocklists"
        done
fi
# same from downloaded raw file
cat "${blocklist}" | GREP_V_COM | awk -- '{print $1}' | GREP_IPV6 | sort -u > "${blocklist_ipv6}"
#ipv4
if test -s "${WHITELIST_FILE}" ;then
	cat "${blocklist}" | GREP_IPV4 | grepcidr -vf ${WHITELIST_FILE} | sort -u > "${blocklist_ipv4}"
	else
	cat "${blocklist}" | GREP_IPV4 | sort -u > "${blocklist_ipv4}"
fi

# This function comes with quirks, creating a variable with inserted \n after ip.
# used to loop over and find overlapping id addresses for second pass and removal.
# don't know why first line is "N ip", and second line " N ip", but worked around.
# asume it is for substring separation in string.
sanitize_cidr() {

file="$1"
overlaps=""
overlaps=$(cat $file | while read line ; do
			echo "$(grepcidr -D $line $file | wc -l) $line\n"
		done | sort -r)
N=$(echo -e $overlaps | awk 'NR==1{print $1}')


# start with lowest N cidr with overlaps to highest in case they are nested.
for i in $(seq 2 $N) ; do
	echo -e $overlaps | grep "$i\s" | awk '{print$2}' | while read line ;do
		cidr_remove=$(grepcidr -D $line $file | sort -t "/" -k2 | tail -n+2 | sed -e 's/[]\/$*.^[]/\\&/g')
		for i in $cidr_remove ;do
			sed -i "/$i/d" $file
		done
	done

done

}
#cat "${blocklist_ipv4}" | GREP_CIDR_0_24  > "${cidr_ipv4_unmerge}"
cat "${blocklist_ipv4}" | GREP_CIDR_0_24 | sort -u  > "${cidr_ipv4}"
sanitize_cidr "${cidr_ipv4}"

cat "${blocklist_ipv4}" | GREP_CIDR_25_32 | while read line ; do
	prips $line
done | grepcidr -vf "${cidr_ipv4}"  > "${single_cidr_ipv4}"
cat "${blocklist_ipv4}" | GREP_IPV4_NO_CIDR | grepcidr -vf "${cidr_ipv4}" > "${single_ipv4}"

# hmm
cat "${nft_ipv4}" | GREP_IPV4 > "${nft_ipv4_list}"
cat "${nft_ipv4_list}" | GREP_CIDR_0_24  > "${cidr_nft_ipv4}"
cat "${nft_ipv4_list}" | GREP_CIDR_25_32 | while read line ; do
	prips $line
done | grepcidr -vf "${cidr_nft_ipv4}" > "${single_nft_ipv4}"
# another one for the ip range quirk now frequent for me with 224.0.0.0/3
# this is dodgy but fine after other rounds of grep regex.
cat "${nft_ipv4_list}" | grep -v "-" |GREP_IPV4_NO_CIDR |  grepcidr -vf "${cidr_nft_ipv4}" >> "${single_nft_ipv4}"

# ip ranges can somehow make it into the nft ipset, remove them
# thought to be an issue with auto-merge feature, can happen in interval sets

nft list set inet fw4 blackhole | GREP_IPV4_RANGE_NO_CIDR | while batch=$(readlines 10000); do
        echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
        nft delete element inet fw4 blackhole { $line }
        echo delete ipv4 ranges from nft set
        done
done
# make a new file with diff, "add ip" and "delete ip", one line per ip with diff
#DIFFER "${single_nft_ipv4}" "${single_ipv4}"  > "${diff_single_ipv4}"
#DIFFER "${cidr_nft_ipv4}" "${cidr_ipv4}"  > "${diff_cidr_ipv4}"
cat "${single_nft_ipv4}" "${cidr_nft_ipv4}" | sort -u > "${diff_input_nft_ipv4}"
cat "${single_ipv4}" "${cidr_ipv4}" | sort -u > "${diff_input_blocklist_ipv4}"
DIFFER "${diff_input_nft_ipv4}" "${diff_input_blocklist_ipv4}"  > "${diff_add_del_ipv4}"
DIFFER "${nft_ipv6_list}" "${blocklist_ipv6}" > "${diff_add_del_ipv6}"

# and we are fairly certain we only send valid IP's to nft
# slowest part outside of download

# add and delete ipv4 for ipset
echo Start of nft ipset operations $(date)
grep del "${diff_add_del_ipv4}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
        echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
        nft delete element inet fw4 blackhole { $line }
	echo iteration of nft ipv4 delete
        done
done
grep add "${diff_add_del_ipv4}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
	echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
	nft add element inet fw4 blackhole { $line }
	echo iteration of nft ipv4 add
	done
done

# add and del ipv6 from ipset
grep add "${diff_add_del_ipv6}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
        echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
        nft add element inet fw4 blackhole6 { $line }
	echo iteration of nft ipv6 add
        done
done
grep del "${diff_add_del_ipv6}" | cut -d ' ' -f 2 | while batch=$(readlines 10000); do
        echo $batch | awk '$1=$1' RS= OFS=", " | while read line ;do
        nft delete element inet fw4 blackhole6 { $line }
	echo iteration of nft ipv6 delete
        done
done

# keep the last raw blocklist
gzip -9n "${blocklist}" -c > /tmp//badhost/last_raw_blocklist.gz

echo "wrt-badhost.sh completed $(date)"
echo "total ipv4 elements in list: $(wc -l "${blocklist_ipv4}")"
echo "total ipv6 elements in list: $(wc -l "${blocklist_ipv6}")"
echo "Amount of ipv4 entries before changes: $(wc -l "${nft_ipv4_list}")"
echo "ipv4 added: $(grep add "${diff_add_del_ipv4}" | wc -l)"
echo "ipv4 removed: $(grep del "${diff_add_del_ipv4}" | wc -l)"
echo "ipv6 added: $(grep add "${diff_add_del_ipv6}" | wc -l)"
echo "ipv6 removed: $(grep del "${diff_add_del_ipv6}" | wc -l)"

if [ "$TMPDIR" = "/tmp/badhost/wrk" ]; then
	rm -rf $TMPDIR
#	nft list set inet fw4 blackhole | wc -l
	echo "wrt-badhost completed $(date)"
fi
# done!
