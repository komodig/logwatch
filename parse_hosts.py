from logwatch import grep_ips
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-f', '--input-file', default='/etc/hosts.deny')
    parser.add_argument('-s', '--filter-string', default='ALL.*')
    parser.add_argument('-l', '--ip-file', default='/tmp/hosts.lst')
    args = parser.parse_args()
    
    ip_dict = grep_ips(args.input_file, args.filter_string)
    
    with open(args.ip_file, 'w') as ipfile:
        for ip in ip_dict.keys():
            ipfile.write(ip  + '\n')
