from argparse import ArgumentParser
import re


def grep_ips(infile, pattern, ip_dict={}):
    err_pattern = re.compile(pattern)
    ip_pattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    with open(infile, 'r') as inf:
        for line in inf:
            if err_pattern.match(line):
                hits = ip_pattern.finditer(line)
                ipaddr = ''
                for hit in hits:
                    ipaddr = hit.group()
                    break    # just 1st ip if there are more in one line

                if ipaddr in ip_dict.keys():
                    ip_dict[ipaddr] += 1
                else:
                    ip_dict[ipaddr] = 1

    return ip_dict


def listed_ips(logwatch_list):
    blocked_ips = {}
    with open(logwatch_list, 'r') as ipf:
        for known_ip in ipf:
            known_ip = known_ip.replace('\n', '')
            blocked_ips[known_ip] = True

    return blocked_ips


if __name__ == '__main__':
    sasl_filter=".*warning:.*\\[.*\\]: SASL.*authentication failed:.*failure"

    parser = ArgumentParser()
    parser.add_argument('-f', '--input-file', default='/var/log/syslog')
    parser.add_argument('-s', '--filter-string', default=sasl_filter)
    parser.add_argument('-l', '--ip-file', default='/tmp/logwatch.lst')
    parser.add_argument('-n', '--subnets', default='/tmp/subnets.lst')
    parser.add_argument('-x', '--limit', default='3')
    parser.add_argument('-d', '--debug', default='True')

    args = parser.parse_args()

    if args.debug == 'True':
        args.debug = True
        print('\n:::: using file: \'%s\'' % args.input_file)
        print(':::: pattern: \'%s\'\n\n' % args.filter_string)

    ips = grep_ips(args.input_file, args.filter_string)
    try:
        ips = grep_ips(args.input_file + '.1', args.filter_string, ip_dict=ips)
    except IOError:
        pass

    blocked_ips = listed_ips(args.ip_file)
    with open(args.ip_file, 'a') as fout:
        for nasty_ip, occurences in ips.items():
            if args.debug is True:
                print('%s: %s x %d' % (args.input_file, nasty_ip, occurences))
            if occurences > int(args.limit) and nasty_ip not in blocked_ips.keys():
                fout.write(nasty_ip + '\n')
                blocked_ips[nasty_ip] = True

    # look for nasty subnets
    logged_ips = {}
    for new_ip in blocked_ips.keys():
        subn = re.sub('\.\d{1,3}$', '.0', new_ip)
        if subn in logged_ips.keys():
            logged_ips[subn] += 1
        else:
            logged_ips[subn] = 1

    # read subnet file to see what subnets are blocked
    blocked_subnets = {}
    try:
        with open(args.subnets, 'r') as fs:
            for subn in fs:
                subn = subn.replace('\n', '')
                blocked_subnets[subn] = 'blocked'
    except IOError:
        pass

    if args.debug is True:
        print('subnets blocked already: %s' % str(blocked_subnets.keys()))

    with open(args.subnets, 'a') as fout:
        for subn,v in logged_ips.items():
            if args.debug is True:
                print('%d ips in subnet: %s' % (v, subn))
            if v > 3 and subn not in blocked_subnets.keys():
                if args.debug is True:
                    print('new subnet to block: %s' % str(subn))
                fout.write(subn + '\n')
                blocked_subnets[subn] = 'new'

