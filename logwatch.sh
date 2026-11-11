#!/bin/bash

enable="False"

lock_file="/var/run/logwatch.lock"

# location where you cloned logwatch.git

WORKSPACE="/root/logwatch"

if [ $UID -ne 0 ] ; then
    echo "sorry - must be root!"
    exit 0
fi

if [[ $enable != "True" ]] ; then
    logger "+++ logwatch +++ abort! (disabled by config file)"
    exit
fi

cd $WORKSPACE

source venv/bin/activate

# Check if Lock File exists, if not create it and set trap on exit
if { set -C; 2>/dev/null >$lock_file; }; then
        trap "rm -f $lock_file" EXIT
else
        logger "+++ logwatch +++ aborting! Lock file exists!"
        exit
fi

logger "running logwatch"
python logwatch.py $1

LOGWATCH_NOTIFICATION="/tmp/notification"
LOGWATCH_NOTIFICATION_HOSTS='/tmp/notification_hosts.json'

if [ -e $LOGWATCH_NOTIFICATION ] ; then
  . $LOGWATCH_NOTIFICATION
  logger "sending notification email to $LOGWATCH_EMAIL"
  echo "$LOGWATCH_MESSAGE" | mail -s "logwatch reports: new blacklisted clients @ $LOGWATCH_HOST" $LOGWATCH_EMAIL
  rm $LOGWATCH_NOTIFICATION
  rm $LOGWATCH_NOTIFICATION_HOSTS
fi

deactivate # venv
