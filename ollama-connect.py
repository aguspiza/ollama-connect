import nmap
import os
import requests
import json
import sys

def scan_network_for_port(network, port):
    nm = nmap.PortScanner()
    # change network when necessary. Pn is required if you do not execute with sudo
    nm.scan(hosts=network, arguments=f'-Pn -p T:{port} --max-retries 1 --open')
    hosts_with_port_open = []

    for host in nm.all_hosts():
        #print(host)
        if port in nm[host]['tcp'] and nm[host]['tcp'][port]['state'] == 'open':
            hosts_with_port_open.append(host)
    
    return hosts_with_port_open

def create_socat_tunnel(ip, port=11434, local_port=11434):
    command = f'socat TCP4-LISTEN:{local_port},fork TCP4:{ip}:{port}'
    os.system(command)

def main(network, model_name):
    port = 11434
    local_port = 11434
    hosts = scan_network_for_port(network, port)

    if not hosts:
        print(f'No ollama endpoints found at {port}.')
    else:
        for host in hosts:
            print(f"Host: {host}")
            resp = requests.get(f'http://{host}:{port}/api/tags')
            #print(resp.content)
            respj = json.loads(resp.content)
            obj = filter(lambda x: x["model"] == model_name, respj["models"])
            if len(list(obj)) > 0:
                print(f'Creating tunnel to {host}:{port}')
                create_socat_tunnel(host, port, local_port)
            else:
                print(f"Model {model_name} not available in {host}")

if __name__ == "__main__":
    model_name = "deepseek-coder:6.7b-base"
    network = '192.168.1.0/24'
    if len(sys.argv) > 1:
        model_name = sys.argv[1]

    if len(sys.argv) > 2:
        network = sys.argv[2]

    main(network, model_name)
