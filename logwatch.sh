#!/bin/bash

enable="False"
lock_file="/var/run/logwatch.lock"

if [ $UID -ne 0 ] ; then
    echo "sorry - must be root!"
    exit 0
fi

if [[ $enable == "False" ]] ; then
    logger "+++ logwatch +++ abort! (disabled by config file)"
    exit
fi

echo "activating venv..."
source venv/bin/activate

# Check if Lock File exists, if not create it and set trap on exit
if { set -C; 2>/dev/null >$lock_file; }; then
        trap "rm -f $lock_file" EXIT
else
        logger "+++ logwatch +++ aborting! Lock file exists!"
        exit
fi

logger "+++ logwatch +++ run"

python logwatch.py

#python $plogparse -f "/etc/hosts.deny" -s "ALL.*" -l $hosts_list
#    python $plogparse -f $iptables_rules -s "REJECT.*all.*icmp-port-unreachable" -l $iptables_list
#        logger "+++ logwatch +++ blocking ip: $doom_ip"
#        $iptables -t filter -I INPUT -s $doom_ip -j REJECT

#    python $plogparse -f $iptables_rules -s "DROP\ *all.*\d{1,3}\.\d{1,3}\.\d{1,3}\.0/24" -l $subnet_rules

#            $iptables -t filter -I INPUT -s "$subnet/255.255.255.0" -j DROP
#            log_msg "+++ logwatch +++ blocking subnet: $subnet"
#    for ban_ip in `cat $hosts_list`; do
#        echo "# added by logwatch at `date`" >> $tmpfile
#        echo "ALL:$ban_ip" >> $tmpfile

#        curl -iX POST "$api_url" \
#        -H "Accept: application/json" \
#        -H "Referer: rs-test" \
#        -H "Content-Type: application/json" \
#        -H "Authorization: Token $api_key" \
#        -d "{\"ip\": \"$ban_ip\", \"origin\": \"\"}"


#        cat $tmpfile | mail -s "logwatch reports: new blacklisted clients @ $host" $webmaster

echo "exit down venv"
deactivate