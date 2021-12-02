#!/bin/bash

. logwatch.conf

function log_msg {
    logger $1
    echo $1 >> $statfile
}

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
if { set -C; 2>/dev/null >/root/logwatch.lock; }; then
        trap "rm -f /root/logwatch.lock" EXIT
else
        logger "+++ logwatch +++ aborting! Lock file exists!"
        exit
fi

logger "+++ logwatch +++ run"

[ -e $logwatch_list ] && rm $logwatch_list
python $plogparse -f "/etc/hosts.deny" -s "ALL.*" -l $hosts_list
cp $hosts_list $logwatch_list
logger "started $logwatch_list with IPs from hosts.deny: `cat $logwatch_list|wc -l`"
[ -e $mail_log ] && python $plogwatch -f $mail_log -s "$sasl_filter" -x $sasl_limit -l $logwatch_list -n $subnets -d $debug


if [ -e $logwatch_list ] ; then
    logger "got `cat $logwatch_list|wc -l` bad ip addresses"
    [ -e $tmpfile ] && rm $tmpfile
    [ -e $statfile ] && rm $statfile
    [ -e $iptables_rules ] && rm $iptables_rules

    logger "managing iptables..."
    $iptables -L -n > $iptables_rules
    # use parser to filter IPs from iptables
    python $plogparse -f $iptables_rules -s "REJECT.*all.*icmp-port-unreachable" -l $iptables_list
    log_msg "IPs in iptables: `cat $iptables_list|wc -l`"
    # check what IPs are rejected already
    python $new_rules -t $iptables_list -l $logwatch_list  # NOTE: -t param is also output-file
    logger "new rules for iptables: `cat $iptables_list|wc -l`"

    # block single IPs
    for doom_ip in `cat $iptables_list`; do
        logger "+++ logwatch +++ blocking ip: $doom_ip"
        $iptables -t filter -I INPUT -s $doom_ip -j REJECT
    done

    logger "managing subnets..."
    # use parser to filter subnets from iptables
    python $plogparse -f $iptables_rules -s "DROP\ *all.*\d{1,3}\.\d{1,3}\.\d{1,3}\.0/24" -l $subnet_rules
    log_msg "subnets in iptables: `cat $subnet_rules|wc -l`"
    # check what subnets are blocked already
    python $new_rules -t $subnet_rules -l $subnets  # NOTE: -t param is also output-file
    logger "new subnets for iptables: `cat $subnet_rules|wc -l`"

    # block subnets
    if [ -e $subnet_rules ] ; then
        for subnet in `cat $subnet_rules`; do
            $iptables -t filter -I INPUT -s "$subnet/255.255.255.0" -j DROP
            log_msg "+++ logwatch +++ blocking subnet: $subnet"
        done
    fi

    logger "managing hosts.deny..."
    python $new_rules -t $hosts_list -l $iptables_list  # NOTE: -t param is also output-file
    logger "new rules for hosts.deny: `cat $hosts_list|wc -l`"
    for ban_ip in `cat $hosts_list`; do
        echo "# added by logwatch at `date`" >> $tmpfile
        echo "ALL:$ban_ip" >> $tmpfile
    done
    if [ -e $tmpfile ] ; then
    	logger "sending info mail..."
        logger "+++ logwatch +++ new blacklisted host(s) "
        cat $tmpfile >> /etc/hosts.deny

        echo "#" >> $tmpfile
        cat $statfile >> $tmpfile
        cat $tmpfile | mail -s "logwatch reports: new blacklisted clients @ $host" $webmaster
    fi
fi


