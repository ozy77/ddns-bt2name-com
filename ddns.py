import argparse
import json
import logging
import os
import re
from urllib import parse

import requests as rq
from bs4 import BeautifulSoup

BT_HOME_IP = '192.168.1.254'
API_TOKEN = os.environ['NAMECOM_API_TOKEN']
API_UN = os.environ['NAMECOM_USERNAME']
API_ENDPOINT = 'https://api.name.com'


def parse_wan_conn(raw):
    j = json.loads(raw.replace("'",'"'))
    d = [parse.unquote(l[0]).split(';') for l in j if l and l[0][0] != '0']
    return dict(zip(['exteral_ip', 'mask','default_gateway','primary_dns', 'secondary_dns'], d[0]))

def get_bt_ip():
    res = rq.get(f"http://{BT_HOME_IP}/nonAuth/wan_conn.xml")
    soup = BeautifulSoup(res.text, "html.parser")
    ipv4_data = parse_wan_conn(soup.ip4_info_list['value'])
    logging.info('Current External IP:  %s', ipv4_data['exteral_ip'])
    return ipv4_data['exteral_ip']

def get_all_domains():
    return rq.get(f'{API_ENDPOINT}/v4/domains', auth=(API_UN,API_TOKEN)).json()['domains']

def get_all_records(domain):
    return rq.get(f'{API_ENDPOINT}/v4/domains/{domain}/records', auth=(API_UN,API_TOKEN)).json()['records']

def get_record(domain, record_id):
    res = rq.get(f'{API_ENDPOINT}/v4/domains/{domain}/records/{record_id}', auth=(API_UN,API_TOKEN)).json()
    return {'host': res['host'], 'type': res['type'], 'answer': res['answer'], 'ttl': res['ttl']}

def create_dns_record(domain, host, ip):
    headers={'Content-Type': 'application/json'}
    payload={'host': host, "type":"A","answer": ip, "ttl":300}
    rq.post(
        f"{API_ENDPOINT}/v4/domains/{domain}/records",
        headers=headers,
        data=json.dumps(payload),
        auth=(API_UN,API_TOKEN)
    )

def update_dns_record(domain, host, ip, record_id):
    headers={'Content-Type': 'application/json'}
    payload={'host': host, "type":"A","answer": ip, "ttl":300}
    if payload != get_record(domain, record_id):
        logging.warning('Updating Existing Record with %s', payload)
        rq.put(
            f"{API_ENDPOINT}/v4/domains/{domain}/recods/{record_id}",
            headers=headers,
            data=json.dumps(payload),
            auth=(API_UN,API_TOKEN)
        )
    else:
        logging.info('Record is up to date for "%s.%s"', host, domain)

def handle_dns_records(data, ip):
    records = get_all_records(data['domain'])
    for host in data['hosts']:
        if host in [d['host'] for d in records if d['type'] == 'A']:
            record = next(d for d in records if d['type'] == 'A' and d['host'] == host)
            logging.info('Existing records found for "%s"', record['fqdn'])
            update_dns_record(data['domain'], host, ip, record['id'])
        else:
            logging.warning('No record found for "%s.%s", Creating new record.', host, data['domain'])
            create_dns_record(data['domain'], host, ip)

def main():
    ip = get_bt_ip()
    all_domains = get_all_domains()
    for data in data_list:
        if data['domain'] in [d['domainName'] for d in all_domains]:
            logging.info('Handling "%s"', data['domain'])
            handle_dns_records(data, ip)
        else:
            logging.warning('Cannot handle "%s". Domain is not in owned Domain list.', data['domain'])


if __name__ == '__main__':
    regex_check = "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,24}(?:\.[a-zA-Z]{2})?:(?:@|[a-zA-Z0-9][a-zA-Z0-9-]{0,61})(?:,(?:@|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}))*$"
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument(
        '--data', '-x', 
        help=(
            'Input domain host data '
            'Format: DOMAIN:HOST1,HOST2,... '
            'Example --data "example.com:www,@"'
        ),
        action='append', 
        required=True,
        type=lambda x: x if re.search(regex_check, x) else False
    )
    parser.add_argument(
        '--debug', '-d',
        help='Print debug level logs',
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING
    )
    parser.add_argument(
        '--verbose', '-v',
        help='Print info level logs',
        action="store_const",
        dest="loglevel",
        const=logging.INFO
    )
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel, format='%(asctime)s.%(msecs)03d %(levelname)s\t%(module)s - %(funcName)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    data_list = [dict(zip(['domain','hosts'], d.split(':'))) for d in args.data]
    data_list = [dict((k,v.split(',')) if k == 'hosts' else (k,v) for k,v in d.items()) for d in data_list]
    logging.warning('Running for %s', data_list)
    main()
    logging.warning('Finished')
