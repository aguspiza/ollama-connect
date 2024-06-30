import nmap
import os

def scan_network_for_port(port=11434):
    nm = nmap.PortScanner()
    # Cambia la red según sea necesario
    nm.scan(hosts='192.168.1.0/24', arguments=f'-p {port} --open')
    hosts_with_port_open = []

    for host in nm.all_hosts():
        if port in nm[host]['tcp'] and nm[host]['tcp'][port]['state'] == 'open':
            hosts_with_port_open.append(host)
    
    return hosts_with_port_open

def create_socat_tunnel(ip, port=11434, local_port=11434):
    command = f'socat TCP4-LISTEN:{local_port},fork TCP4:{ip}:{port}'
    os.system(command)

def main():
    port = 11434
    local_port = 11434
    hosts = scan_network_for_port(port)

    if not hosts:
        print(f'No se encontraron dispositivos con el puerto {port} abierto.')
    else:
        for host in hosts:
            print(f'Creando túnel hacia {host}:{port}')
            create_socat_tunnel(host, port, local_port)

if __name__ == "__main__":
    main()
