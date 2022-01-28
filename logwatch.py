import os
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
    detected_hosts = []

    for line in raw_input_generator(type_, log):
        if err_pattern.match(line):
            for hit in ip_pattern.finditer(line):
                ipaddr = hit.group()
                break    # just 1st ip if there are more in one line

            if ipaddr not in hosts and ipaddr not in detected_hosts:
                if ipaddr in ip_hits.keys():
                    ip_hits[ipaddr] += 1
                else:
                    ip_hits[ipaddr] = 1

                if ip_hits[ipaddr] >= limit:
                    detected_hosts.append(ipaddr)

    return detected_hosts

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
    if resp.status_code != 200:
        syslog(f"API submit failed: {resp.status_code}")
        return []

    return [host['ip'] for host in json.loads(resp.content)]

def sys_ban_ip(iptables: str, host: str):
    syslog("insert rule to reject access from: " + host)
    try:
        _ = subprocess.check_output([iptables, '-t', 'filter', '-I', 'INPUT', '-s', host, '-j', 'REJECT'])
    except subprocess.CalledProcessError as grepexc:
        syslog("subprocess error code: ", grepexc.returncode, grepexc.output)

def load_from_iptables(iptables: str) -> list:
    pattern = "REJECT.*all.*icmp-port-unreachable"
    blacklisted = grep_hosts(INPUT_TYPE.IPTABLES, [], iptables, pattern, 1)
    syslog(str(len(blacklisted)) + 'blacklisted hosts from iptables')
    return blacklisted

def submit_to_blacklistAPI(conf: dict, attacker: str, directive: str):
    headers = {"Content-Type": "application/json",
               "Accept": "application/json",
               "charset": "utf-8",
               "Authorization": "Token " + conf['api']['key']}
    payload = "{\"ip\": \"%s\", \"origin\": \"\", \"directive\": \"%s/%s\"}" % (attacker, conf['domain'], directive)
    resp = requests.post(conf['api']['url'], data=payload, headers=headers)
    if resp.status_code != 201:
        syslog(f"API submit failed: {resp.status_code}")

if __name__ == '__main__':
    conf = read_config(logwatch_config)
    new_hosts_detected = []
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
        detected_hosts = grep_hosts(INPUT_TYPE.LOG, hosts, **directive)
        if not len(detected_hosts):
            continue

        syslog(f"directive: {dir} detected {len(detected_hosts)} hosts")
        for attacker in detected_hosts:
            submit_to_blacklistAPI(conf, attacker, dir)

        new_hosts_detected += detected_hosts

    if len(new_hosts_detected):
        hosts_blacklisted = load_from_iptables(conf['iptables'])
        api_hosts = read_hosts_api(conf['api']['url'])
        hosts += new_hosts_detected
    else:
        syslog("no suspicious hosts detected")

    if len(api_hosts) > len(hosts):
        syslog(f"received {len(api_hosts) - len(hosts)} new hosts from api")

    hosts = api_hosts   # assume all local hosts are found in api hosts anyway

    for attacker in hosts:
        if attacker not in hosts_blacklisted:
            sys_ban_ip(conf['iptables'], attacker)

    if len(new_hosts_detected) and conf['notification']['send']:
        with open(conf['notification']['message'], 'w') as nfile:
            nfile.write(f"LOGWATCH_EMAIL={conf['notification']['email-to']}\n")
            nfile.write(f"LOGWATCH_HOST={conf['domain']}\n")
            nfile.write(f"LOGWATCH_MESSAGE=blacklisted: {str(new_hosts_detected)}\n")
