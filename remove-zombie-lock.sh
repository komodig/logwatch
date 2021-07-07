#!/bin/bash
# 
# useful in case of reboot while logwatch was running
# you may run this by /etc/rc.local

LOGWATCH_LOCK=/root/logwatch.lock

if [ -e $LOGWATCH_LOCK ]; then 
        rm -f $LOGWATCH_LOCK 
        logger "+++ logwatch +++ removed $LOGWATCH_LOCK after bootup!"
else
        logger "+++ logwatch +++ no $LOGWATCH_LOCK found after bootup - GOOD!"
fi
