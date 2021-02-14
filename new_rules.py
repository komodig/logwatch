import os
from argparse import ArgumentParser


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-t', '--iptables-file', default='/tmp/iptables.lst')
    parser.add_argument('-l', '--logwatch-file', default='/tmp/logwatch.lst')
    args = parser.parse_args()
    
    iptables = []
    new_rules = []
    with open(args.iptables_file, 'r') as itf:
        for line in itf:
            line = line.replace('\n', '')
            iptables.append(line)

    with open(args.logwatch_file, 'r') as lwf:
        for line in lwf:
            line = line.replace('\n', '')
            if line not in iptables:
                new_rules.append(line)

    os.remove(args.iptables_file)
    with open(args.iptables_file, 'w') as ipfile:
        for ip in new_rules:
            if ip in ["0.0.0.0", ]:  # your backdoor-ip here
                continue
            ipfile.write(ip + '\n')
