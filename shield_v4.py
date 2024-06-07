import argparse
import sys
import paramiko
import time
import socket
import logging
import msvcrt  # console reading module


def tcpdump_decode(data):
    lines = data.split("\r\n")
    result = []
    for line in lines:
        ip = ['', '']
        if len(line) > 0:
            d1 = line.split(" IP ")
            if len(d1) < 2:
                continue
            d2 = d1[1].split(":")
            if len(d2) < 2:
                continue
            d3 = d2[0].split(">")
            if len(d3) < 2:
                continue
            ip[0] = d3[0].strip()
            ip[1] = d3[1].strip()
            d4 = d2[1].find("ICMP")
            if d4 > -1:
                prot = 'ICMP'
            else:
                d4 = d2[1].find("UDP")
                if d4 > -1:
                    prot = 'UDP'
                else:
                    d4 = d2[1].find("Flags")
                    if d4 > -1:
                        prot = 'TCP'
                    else:
                        continue
            result.append((ip[0], ip[1], prot))
    return result


def remove_self(arr):
    new_arr = []
    if len(arr) == 0:
        return []

    for e in arr:
        if e[0] == '192.168.2.2' or e[0] == '192.168.2.2.0':
            continue
        else:
            new_arr.append(e)
    return new_arr


def count_by_type(result, arr):
    if len(arr) == 0:
        return result
    for e in arr:
        result[e[2]] += 1
    return result


def strip_port(ip):
    arr = ip.split('.')
    return '.'.join(arr[:4])


def count_by_ip(result, arr):
    if len(arr) == 0:
        return result
    for e in arr:
        e0 = strip_port(e[0])
        if e0 in result:
            result[e0] += 1
        else:
            result[e0] = 1
    return result


def count_by_port(result, arr):
    if len(arr) == 0:
        return result
    for e in arr:
        if e[2] == 'ICMP':
            if 'ICMP' in result:
                result['ICMP'] += 1
            else:
                result['ICMP'] = 1
        else:
            d = e[1].split('.')
            if len(d) < 2:
                continue
            else:
                if d[-1] in result:
                    result[d[-1]] += 1
                else:
                    result[d[-1]] = 1
    return result


def get_ip_block_list(dicr, n):
    if len(dicr) == 0:
        return []
    result = []
    for k in dicr:
        if dicr[k] > n:
            result.append(k)
    return result


def get_prot_block_list(dicr, n):
    result = []
    for p in dicr:
        if dicr[p] > n:
            result.append(p)
    return result


def get_port_block_list(dicr, n):
    result = []
    if len(dicr) > 0:
        for p in dicr:
            if dicr[p] > n:
                result.append(p)
    return result


class Shield:
    def __init__(self):
        self.sh3 = None
        self.sh2 = None
        self.sh1 = None
        self.cl = None

    # noinspection PyTypeChecker
    def connect(self, ip, username, password):
        self.cl = paramiko.SSHClient()
        self.cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.cl.connect(hostname=ip, username=username, password=password, timeout=1)
        self.sh1 = self.cl.invoke_shell()
        self.sh1.send("tcpdump -i ens36 \n")
        self.sh1.recv(60000)
        self.sh2 = self.cl.invoke_shell()
        self.sh2.send("tcpdump -i nflog \n")
        self.sh2.recv(60000)
        self.sh3 = self.cl.invoke_shell()
        self.sh3.recv(60000)
        time.sleep(0.5)

    # noinspection PyTypeChecker
    def get_traffic(self):
        self.sh1.settimeout(0.5)
        output = ""
        cnt = 0
        while True:
            if cnt > 20:
                break
            try:
                output += self.sh1.recv(2096).decode("utf-8")
                cnt += 1
            except socket.timeout:
                break
        return output

    def get_filtered_traffic(self):
        self.sh2.settimeout(0.5)
        output = ""
        cnt = 0
        while True:
            if cnt > 20:
                break
            try:
                output += self.sh2.recv(2096).decode("utf-8")
                cnt += 1
            except socket.timeout:
                break
        return output

    def block_by_ip(self, arr):
        if len(arr) == 0:
            return 0
        for ip in arr:
            self.cl.exec_command(f'iptables -I INPUT -s {ip} -j DROP \n')
            time.sleep(0.1)
        return 1

    def block_by_prot(self, arr):
        if len(arr) == 0:
            return 0
        for p in arr:
            self.cl.exec_command(f'iptables -I INPUT -i ens36 -p {p} -j DROP \n')
            time.sleep(0.1)
        return 1

    def block_by_port(self, arr):
        if len(arr) == 0:
            return 0
        for p in arr:
            self.cl.exec_command(f'iptables -I INPUT -i ens36 -p tcp --destination-port {p} -j DROP \n')
            time.sleep(0.1)
            self.cl.exec_command(f'iptables -I INPUT -i ens36 -p udp --destination-port {p} -j DROP \n')
            time.sleep(0.1)

    def unblock_rules(self):
        self.cl.exec_command("iptables -P INPUT ACCEPT")
        self.cl.exec_command("iptables -F")
        self.cl.exec_command("iptables -X")
        self.cl.exec_command(f'iptables -A INPUT -i ens36 -j NFLOG')

    def check_ssh(self):
        self.sh3.send("ss -p |grep ssh \n")
        self.sh3.settimeout(0.5)
        output = ""
        cnt = 0
        while True:
            if cnt > 5:
                break
            try:
                output += self.sh3.recv(1024).decode("utf-8")
                cnt += 1
            except socket.timeout:
                break
        lines = output.split("\r\n")
        for line in lines:  # N should always be at least 3
            line = ' '.join(line.split())
            d1 = line.split(' ')
            if len(d1) < 4:
                continue
            if d1[0] == 'tcp':
                ip_0 = d1[4]
                ip_1 = d1[5]
                print(ip_0, ip_1)
                ip_1_c = ip_1.split(":")[0]
                if ip_1_c != host_ip:
                    print('UnSanctioned Fuckers Here!')
                    print("Powering off...")
                    self.cl.exec_command(" shutdown -h now \n")
                    return False
        return True

    def disconnect(self):
        self.sh1.close()
        self.sh2.close()
        self.sh3.close()
        self.cl.close()
        self.sh1 = None
        self.sh2 = None
        self.sh3 = None
        self.cl = None


if __name__ == '__main__':
    mode = 0  # 0 - block ip, 1 - block protocol, 2 - block port
    shield_ip = "192.168.179.129"
    shield_login = "root"
    shield_password = "russia"
    host_ip = "192.168.179.1"

    parser = argparse.ArgumentParser(description="Activate Shield")
    parser.add_argument("--mode", type=int)
    parser.add_argument("--host")
    parser.add_argument("--dev")
    parser.add_argument("--login")
    parser.add_argument("--password")
    args = parser.parse_args()
    if args.mode:
        if mode < 3:
            mode = args.mode
    if args.host:
        host_ip = args.host
    if args.dev:
        shield_ip = args.dev
    if args.login:
        shield_login = args.login
    if args.password:
        shield_password = args.password
    sys.stdout.write("Shield Initializing:")
    sys.stdout.write("mode: " + str(mode) + "\n")
    sys.stdout.write("host: " + host_ip + "\n")
    sys.stdout.write("target:" + shield_ip + "\n")
    sys.stdout.write("login: " + shield_login + "\n")
    sys.stdout.write("password:  " + shield_password + "\n\n")

    logger = logging.getLogger("ShieldV4")

    logging.basicConfig(filename='shieldV4.log', level=logging.INFO)
    logger.info('Started')

    shield = Shield()
    shield.connect(shield_ip, shield_login, shield_password)
    time.sleep(1)

    start = time.time()

    ip_limit = 10
    type_limit = 200
    port_limit = 100

    while time.time() < start + 20:
        packs_by_type = {'ICMP': 0, 'UDP': 0, 'TCP': 0}
        packs_by_ip = {}
        packs_by_port = {}

        res = tcpdump_decode(shield.get_traffic())
        res = remove_self(res)

        packs_by_ip = count_by_ip(packs_by_ip, res)
        packs_by_port = count_by_port(packs_by_port, res)
        packs_by_type = count_by_type(packs_by_type, res)
        print(packs_by_type)
        print(packs_by_port)
        print(packs_by_ip)

        logger.info(f'time s: {int(time.time() - start)}')
        logger.info(f'packs_by_ip: {packs_by_ip}')
        logger.info(f'packs by protocol: {packs_by_type}')
        logger.info(f'packs by port: {packs_by_port}')

        shield.unblock_rules()
        if mode == 0:
            ip_block = get_ip_block_list(packs_by_ip, ip_limit)
            print("Blocking IP: ", ip_block)
            logger.info(f'Blocking IP: {ip_block}')
            shield.block_by_ip(ip_block)
        elif mode == 1:
            prot_block = get_prot_block_list(packs_by_type, type_limit)
            print("Blocking Protocol: ", prot_block)
            logger.info(f'Blocking Protocol: {prot_block}')
            shield.block_by_prot(prot_block)
        else:  # mode == 2
            port_block = get_port_block_list(packs_by_port, port_limit)
            print("Blocking Port: ", port_block)
            logger.info(f'Blocking Port: {port_block}')
            shield.block_by_port(port_block)
        print("received data:", len(shield.get_filtered_traffic()))
        logger.info(f'received data size: {len(shield.get_filtered_traffic())}')

        if not shield.check_ssh():
            logger.critical("Shut Down")
            break

        console_read = ""
        while msvcrt.kbhit():
            console_read += msvcrt.getch().decode("utf-8")
        if len(console_read) > 0:
            print("Typed: ", console_read)
            if console_read[0].isdigit():
                nmode = int(console_read[0])
                if -1 < nmode < 3:
                    mode = nmode
                    print("setting mode: ", mode)
        print()
        time.sleep(1)
    shield.disconnect()
    logger.info('Finished')
