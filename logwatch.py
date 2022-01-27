import sys
import re
import yaml
import requests
import json
from syslog import syslog
from pathlib import Path

logwatch_config = 'config.yaml'

def _grep_hosts(hosts: list, log: str, pattern: str, limit: int) -> list:
    ip_hits = {}
    err_pattern = re.compile(pattern)
    ip_pattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    hosts_found = []

    with open(log, 'r') as inf:
        for line in inf:
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

def _read_config(cfile: str) -> dict:
    try:
        with open(cfile, 'r') as lwconf:
            conf = yaml.safe_load(lwconf)
    except FileNotFoundError:
        syslog(f'config not found: {cfile}')
        sys.exit(1)

    return conf

def _read_hosts_file(hfile: str) -> list:
    syslog('reading hosts from file')
    with open(hfile, 'r') as lwhosts:
        return json.load(lwhosts)['hosts']

def _write_hosts_file(hfile: str, hosts: list):
    with open(hfile, 'w') as lwhosts:
        json.dump({"hosts": hosts}, lwhosts)

def _read_hosts_api(url: str) -> list:
    syslog('requesting hosts from api')
    resp = requests.get(url)
    if not resp.status_code == 200:
        syslog(f"API request failed: {url}")

    return [host['ip'] for host in json.loads(resp.content)]

if __name__ == '__main__':
    conf = _read_config(logwatch_config)
    hosts = None

    if Path(conf['hosts-db']).exists():
        hosts = _read_hosts_file(conf['hosts-db'])
    else:
        hosts = _read_hosts_api(conf['api']['url'])
        _write_hosts_file(conf['hosts-db'], hosts)

    for dir in conf['directives']:
        directive = conf['directives'][dir]
        hosts_found = _grep_hosts(hosts, **directive)
        if len(hosts_found):
            print("directive: " + dir + " found hosts: " + hosts_found)