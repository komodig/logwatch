# logwatch
yet another IDS/IPS system using iptables

run by crontab like this:

*/2 * * * * root   /root/logwatch/logwatch.sh
59 23 * * * root   /root/logwatch/logwatch.sh --sendmail
