import requests
import urllib3
from urllib.parse import urljoin
import ipaddress
import argparse
from alive_progress import alive_bar
import os
from tabulate import tabulate
from termcolor import colored

def cmd_args():
    cmdline_parser = argparse.ArgumentParser(description="A script to retrieve the scans where specified IPs were analyzed")
    cmdline_parser.add_argument('-n', '-nessus', type=str, dest='nessus_url', help='Nessus URL (Web root)', required=True)
    cmdline_parser.add_argument('-file', '-in', '-i', type=str, dest='file', help='Valid CSV file [couple (domain,IP) for each line]', required=True)
    cmdline_parser.add_argument('-output', '-out', '-o', type=str, dest='output', help="Output CSV file (default 'results.csv')", default='results.csv')

    args = cmdline_parser.parse_args()

    return args.nessus_url, args.file, args.output

def is_valid_file(filename):
    while not (filename and os.path.isfile(filename) and filename.endswith('.csv')):
        filename = input("\nInsert the path of a valid TXT file [couple (domain,IP) for each line]:\n")

    return filename

def read_input(filename):
    with open(filename, 'r') as f:
        assets_list = [x.strip().split(",") for x in f.readlines()]
        assets_info_1 = [a[0].lower() for a in assets_list]
        assets_info_2 = [a[1].lower() for a in assets_list]

    return [assets_info_1, assets_info_2]

def login(nessus_url, username, password):
    nessus_login_url = urljoin(nessus_url,"/session")
    print(nessus_login_url)

    # Headers for the request
    headers = {
        "Content-Type": "application/json"
    }

    # Data for the login request
    login_data = {
        "username": username,
        "password": password
    }

    # Send the login request to Nessus
    response = requests.post(nessus_login_url, json=login_data, headers=headers, verify=False)

    token = ''
    # Check if login is successful
    if response.status_code == 200:
        # Extract the token from the response
        token = response.json()['token']
        print("Login successful, token:", token)
        return token
    else:
        print(f"Login failed with status code {response.status_code}: {response.text}")
        exit(1)

def search_assets_in_scans(nessus_url, token, assets_info, output_file):
    headers = {"X-Cookie":f"token={token}",}
    response = requests.get(urljoin(nessus_url,"/scans"), verify=False, headers=headers)
    scans = response.json()['scans']

    with open(output_file, 'w') as f, alive_bar(len(scans)) as bar:
        for scan in scans:
            response_scan = requests.get(urljoin(nessus_url,f"/scans/{scan['id']}"), headers=headers, verify=False)

            if 'hosts' in response_scan.json():
                for host in response_scan.json()['hosts']:
                    for i in range(2):
                        try:
                            index = assets_info[i].index(host['hostname'].lower())
                            scan_host_url = urljoin(nessus_url,f"/#/scans/reports/{scan['id']}/hosts/{host['host_id']}/vulnerabilities")
                            if i == 0:
                                f.write(f"{assets_info[i][index]},{assets_info[1][index]},{scan['name']},{scan['owner']},{scan_host_url}\n")
                            elif i == 1:
                                f.write(f"{assets_info[0][index]},{assets_info[i][index]},{scan['name']},{scan['owner']},{scan_host_url}\n")
                        except ValueError:
                            pass
                                            
            bar.text(f"{scan['name']}")        
            bar()


def main():
    nessus_url, filename, output_file = cmd_args()
    username = input(colored("Username: ", 'yellow'))
    password = input(colored("Password: ", 'yellow'))
    filename = is_valid_file(filename)
    assets_info = read_input(filename)

    params_info = [ ['Nessus URL',urljoin(nessus_url,"/")],
                    ['TXT file',filename],
                    ['Output', output_file]]

    print('')
    print(tabulate(params_info, headers=['Information', 'Value'], tablefmt='fancy_grid'), end='\n\n')

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    token = login(nessus_url, username, password)
    search_assets_in_scans(nessus_url, token, assets_info, output_file)

if __name__=='__main__':
    main()