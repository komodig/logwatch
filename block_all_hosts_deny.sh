#!/bin/bash

iptables="/sbin/iptables"

for doom_ip in `cat /etc/hosts.deny |grep ^ALL:.*|sed 's/^ALL://g'`; do
    echo "blocking $doom_ip"
    existing_rule="`$iptables -L -n|grep $doom_ip\ `"
    #echo "$existing_rule"
    if [ -z "$existing_rule" ] ; then
        logger "+++ logwatch +++ blocking ip from from hosts.deny: $doom_ip"
        $iptables -t filter -I INPUT -s $doom_ip -j REJECT
    fi
done
