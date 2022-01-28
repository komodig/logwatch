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

logger "activating venv..."
source venv/bin/activate

# Check if Lock File exists, if not create it and set trap on exit
if { set -C; 2>/dev/null >$lock_file; }; then
        trap "rm -f $lock_file" EXIT
else
        logger "+++ logwatch +++ aborting! Lock file exists!"
        exit
fi

logger "running logwatch"
python logwatch.py

LOGWATCH_NOTIFICATION="/tmp/notification"

if [ -e $LOGWATCH_NOTIFICATION ] ; then
  . $LOGWATCH_NOTIFICATION
  logger "sending notification email to $LOGWATCH_EMAIL"
  echo "$LOGWATCH_MESSAGE" | mail -s "logwatch reports: new blacklisted clients @ $LOGWATCH_HOST" $LOGWATCH_EMAIL
  rm $LOGWATCH_NOTIFICATION

logger "shutting down venv"
deactivate
