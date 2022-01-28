import sys
import re
import yaml
import requests
import json
import subprocess
from syslog import syslog
from pathlib import Path

logwatch_config = 'config.yaml'

class INPUT_TYPE:
    LOG = 0
    IPTABLES = 1

def raw_input_generator(type_: int, arg: str):
    if type_ == INPUT_TYPE.LOG:
        for line in open(arg, 'r'):
            yield line
    elif type_ == INPUT_TYPE.IPTABLES:
        output = subprocess.check_output([arg, '-L', '-n'])
        for line in output.splitlines():
            yield line.decode('ascii')
    else:
        raise NotImplementedError

# parameter log is used to pass logfile-name or file path in case of iptables
# i.e. to parse log-files or iptables-rules
def grep_hosts(type_: int, hosts: list, log: str, pattern: str, limit: int) -> list:
    ip_hits = {}
    err_pattern = re.compile(pattern)
    ip_pattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    hosts_found = []

    for line in raw_input_generator(type_, log):
        if err_pattern.match(line):
            for hit in ip_pattern.finditer(line):
                ipaddr = hit.group()
                break    # just 1st ip if there are more in one line

            if ipaddr not in hosts and ipaddr not in hosts_found:
                if ipaddr in ip_hits.keys():
                    ip_hits[ipaddr] += 1
                else:
                    ip_hits[ipaddr] = 1

                if ip_hits[ipaddr] >= limit:
                    hosts_found.append(ipaddr)

    return hosts_found

def read_config(cfile: str) -> dict:
    try:
        with open(cfile, 'r') as lwconf:
            conf = yaml.safe_load(lwconf)
    except FileNotFoundError:
        syslog(f'config not found: {cfile}')
        sys.exit(1)

    return conf

def read_hosts_file(hfile: str) -> list:
    syslog('reading hosts from file')
    with open(hfile, 'r') as lwhosts:
        return json.load(lwhosts)['hosts']

def write_hosts_file(hfile: str, hosts: list):
    with open(hfile, 'w') as lwhosts:
        json.dump({"hosts": hosts}, lwhosts)

def read_hosts_api(url: str) -> list:
    syslog('requesting hosts from api')
    resp = requests.get(url)
    if not resp.status_code == 200:
        syslog(f"API request failed: {url}")

    return [host['ip'] for host in json.loads(resp.content)]

def sys_ban_ip(iptables: str, host: str):
    try:
        # $iptables -t filter -I INPUT -s $doom_ip -j REJECT
        output = subprocess.check_output([iptables, '-t', 'filter', '-I', 'INPUT', '-s', host, '-j', 'REJECT'])
    except subprocess.CalledProcessError as grepexc:
        syslog("subprocess error code: ", grepexc.returncode, grepexc.output)

def load_from_iptables(iptables: str) -> list:
    pattern=  "REJECT.*all.*icmp-port-unreachable"
    blacklisted = grep_hosts(INPUT_TYPE.IPTABLES, [], iptables, pattern, 1)
    print('blacklisted hosts from iptables: ' + str(blacklisted))
    return blacklisted

if __name__ == '__main__':
    conf = read_config(logwatch_config)
    hosts_blacklisted = load_from_iptables(conf['iptables'])
    hosts = None

    # TEST
    #sys_ban_ip(conf['iptables'], '118.195.145.14')

    if Path(conf['hosts-db']).exists():
        hosts = read_hosts_file(conf['hosts-db'])
    else:
        hosts = read_hosts_api(conf['api']['url'])
        write_hosts_file(conf['hosts-db'], hosts)

    for dir in conf['directives']:
        directive = conf['directives'][dir]
        hosts_found = grep_hosts(INPUT_TYPE.LOG, hosts, **directive)
        if not len(hosts_found):
            continue
        print("directive: " + dir + " found hosts: " + str(hosts_found))
