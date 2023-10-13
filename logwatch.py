import sys
import re
import yaml
import requests
import json
import subprocess
from pathlib import Path
import syslog

logwatch_config = 'config.yaml'


class INPUT_TYPE:
    LOG = 0
    IPTABLES = 1


def raw_input_generator(type_: int, path: str):
    if type_ == INPUT_TYPE.LOG:
        for line in open(path, 'r'):
            yield line
    elif type_ == INPUT_TYPE.IPTABLES:
        output = subprocess.check_output([path, '-L', '-n'])
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
        syslog.syslog(syslog.LOG_INFO, f'config not found: {cfile}')
        sys.exit(1)

    return conf


def read_hosts_file(hfile: str) -> list:
    with open(hfile, 'r') as lwhosts:
        hosts = json.load(lwhosts)['hosts']
        syslog.syslog(syslog.LOG_INFO, f'read {str(len(hosts))} hosts from file: {hfile}')
        return hosts


def write_hosts_file(hfile: str, hosts: list):
    syslog.syslog(syslog.LOG_INFO, f"saving {str(len(hosts))} hosts")
    with open(hfile, 'w') as lwhosts:
        json.dump({"hosts": hosts}, lwhosts)


def read_hosts_api(url: str) -> list:
    syslog.syslog(syslog.LOG_INFO, 'requesting hosts from api')
    resp = requests.get(url)
    if resp.status_code != 200:
        syslog.syslog(syslog.LOG_INFO, f"API retrieve failed: {resp.status_code}")
        return []

    hosts = [host['ip'] for host in json.loads(resp.content)]
    syslog.syslog(syslog.LOG_INFO, str(len(hosts)) + " hosts from api")
    return hosts


def sys_ban_ip(iptables: str, host: str, conf: dict):
    if host in conf['whitelist']:
        syslog.syslog(syslog.LOG_INFO, f"skip rule: {host} in whitelist")
        return

    syslog.syslog(syslog.LOG_INFO, "insert rule: reject access: " + host)
    try:
        _ = subprocess.check_output([iptables, '-t', 'filter', '-I', 'INPUT', '-s', host, '-j', 'REJECT'])
    except subprocess.CalledProcessError as grepexc:
        syslog.syslog(syslog.LOG_INFO, "subprocess error code: ", grepexc.returncode, grepexc.output)


def load_from_iptables(iptables: str) -> list:
    pattern = "REJECT.*all.*icmp-port-unreachable"
    blacklisted = grep_hosts(INPUT_TYPE.IPTABLES, [], iptables, pattern, 1)
    syslog.syslog(syslog.LOG_INFO, str(len(blacklisted)) + ' blacklisted in iptables')
    return blacklisted


def submit_to_blacklistAPI(conf: dict, attacker: str, directive: str):
    if attacker in conf['whitelist']:
        syslog.syslog(syslog.LOG_INFO, f"API submit canelled: {attacker} in whitelist")
        return

    headers = {"Content-Type": "application/json",
               "Accept": "application/json",
               "charset": "utf-8",
               "Authorization": "Token " + conf['api']['key']}
    payload = "{\"ip\": \"%s\", \"origin\": \"\", \"directive\": \"%s/%s\"}" % (attacker, conf['domain'], directive)
    resp = requests.post(conf['api']['url'], data=payload, headers=headers)
    if resp.status_code != 201:
        syslog.syslog(syslog.LOG_INFO, f"API submit failed: {resp.status_code} : {attacker}")
    else:
        syslog.syslog(syslog.LOG_INFO, f"API submit successful: {attacker}")


if __name__ == '__main__':
    syslog.openlog(ident='logwatch', facility=syslog.LOG_LOCAL1)

    new_hosts_detected = []
    hosts = None
    conf = read_config(logwatch_config)
    hosts_blacklisted = load_from_iptables(conf['iptables'])
    api_hosts = read_hosts_api(conf['api']['url'])

    # TEST
    #sys_ban_ip(conf['iptables'], '118.195.145.14')

    if Path(conf['hosts-db']).exists():
        hosts = read_hosts_file(conf['hosts-db'])
    else:
        hosts = api_hosts

    for dir in conf['directives']:
        directive = conf['directives'][dir]
        detected_hosts = grep_hosts(INPUT_TYPE.LOG, api_hosts, **directive)
        if not len(detected_hosts):
            continue

        syslog.syslog(syslog.LOG_INFO, f"directive: {dir} detected {len(detected_hosts)} hosts")
        for attacker in detected_hosts:
            submit_to_blacklistAPI(conf, attacker, dir)

        new_hosts_detected += detected_hosts

    hosts += [ nh for nh in new_hosts_detected if nh not in hosts ]

    if len(new_hosts_detected):
        # just use the event to check updates from API
        new_api_hosts = [ ah for ah in api_hosts if ah not in hosts ]
        syslog.syslog(syslog.LOG_INFO, f"received {str(len(new_api_hosts))} from api")
        hosts += new_api_hosts
    else:
        syslog.syslog(syslog.LOG_INFO, "no suspicious hosts detected")
        api_hosts = []

    for attacker in hosts:
        if attacker not in hosts_blacklisted:
            sys_ban_ip(conf['iptables'], attacker, conf)

    write_hosts_file(conf['hosts-db'], hosts)

    # TODO send mail with python (the following workaround prepares sendmail by shell)
    message = '/tmp/notification'  # hardcoded in shell script!
    if len(new_hosts_detected) and conf['notification']['send']:
        with open(message, 'w') as nfile:
            nfile.write(f"LOGWATCH_EMAIL=\"{conf['notification']['email-to']}\"\n")
            nfile.write(f"LOGWATCH_HOST=\"{conf['domain']}\"\n")
            nfile.write(f"LOGWATCH_MESSAGE=\"blacklisted: {str(new_hosts_detected)}\"\n")
