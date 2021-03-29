import csv
import numpy as np
import subprocess

isColab = False

proto = {'tcp': 0, 'udp': 1, 'unas': 2, 'arp': 3, 'ospf': 4, 'sctp': 5, 'any': 6, 'gre': 7, 'swipe': 8, 'sun-nd': 9, 'pim': 10, 'mobile': 11, 'ipv6': 12, 'rsvp': 13, 'sep': 14, 'ib': 15, 'zero': 16, 'xtp': 17, 'wsn': 18, 'wb-mon': 19, 'wb-expak': 20, 'vrrp': 21, 'vmtp': 22, 'visa': 23, 'vines': 24, 'uti': 25, 'ttp': 26, 'tp++': 27, 'tlsp': 28, 'tcf': 29, 'stp': 30, 'srp': 31, 'sps': 32, 'sprite-rpc': 33, 'snp': 34, 'smp': 35, 'sm': 36, 'skip': 37, 'secure-vmtp': 38, 'sdrp': 39, 'scps': 40, 'sccopmce': 41, 'sat-mon': 42, 'sat-expak': 43, 'rvd': 44, 'qnx': 45, 'pvp': 46, 'ptp': 47, 'pri-enc': 48, 'pnni': 49, 'pipe': 50, 'pgm': 51, 'nsfnet-igp': 52, 'narp': 53, 'mtp': 54, 'micp': 55, 'mhrp': 56, 'mfe-nsp': 57, 'merit-inp': 58, 'larp': 59, 'l2tp': 60, 'kryptolan': 61, 'iso-ip': 62, 'isis': 63, 'ipx-n-ip': 64, 'ipv6-route': 65, 'ipv6-opts': 66, 'ipv6-no': 67, 'ipv6-frag': 68, 'ippc': 69, 'iplt': 70, 'ipip': 71, 'ipcv': 72, 'ipcomp': 73, 'i-nlsp': 74, 'il': 75, 'ifmp': 76, 'idrp': 77, 'idpr-cmtp': 78, 'idpr': 79, 'iatp': 80, 'gmtp': 81, 'fire': 82, 'fc': 83, 'etherip': 84, 'encap': 85, 'eigrp': 86, 'dgp': 87, 'ddx': 88, 'ddp': 89, 'crudp': 90, 'cpnx': 91, 'cphb': 92, 'compaq-peer': 93, 'cftp': 94, 'br-sat-mon': 95, 'bna': 96, 'ax.25': 97, 'aris': 98, 'a/n': 99, 'aes-sp3-d': 100, '3pc': 101, 'xns-idp': 102, 'xnet': 103, 'trunk-2': 104, 'trunk-1': 105, 'st2': 106, 'pup': 107, 'prm': 108, 'nvp': 109, 'mux': 110, 'leaf-2': 111, 'leaf-1': 112, 'iso-tp4': 113, 'irtp': 114, 'ipnip': 115, 'ip': 116, 'igp': 117, 'ggp': 118, 'emcon': 119, 'dcn': 120, 'crtp': 121, 'chaos': 122, 'cbt': 123, 'rdp': 124, 'netblt': 125, 'hmp': 126, 'egp': 127, 'bbn-rcc': 128, 'argus': 129, 'igmp': 130, 'icmp': 131, 'rtp': 132}
service = {'-': 0, 'dns': 1, 'http': 2, 'smtp': 3, 'ftp-data': 4, 'ftp': 5, 'ssh': 6, 'pop3': 7, 'dhcp': 8, 'snmp': 9, 'ssl': 10, 'irc': 11, 'radius': 12}

# ACC, CLO not in training set, default = 9
state = {'INT': 0, 'FIN': 1, 'CON': 2, 'REQ': 3, 'RST': 4, 'ECO': 5, 'URN': 6, 'PAR': 7, 'no': 8,'ACC':9, 'CLO':9}
label = {'Normal': 0, 'Generic': 1, 'Exploits': 2, 'Fuzzers': 3, 'DoS': 4, 'Reconnaissance': 5, 'Analysis': 6, 'Backdoor': 7, 'Shellcode': 8, 'Worms': 9}

def nomalize(X,Y):
    for i in range(0,len(y)):
        nomalize(x, y)

def nomalizeUNSW_NB15(x,y):
    x[1] = proto[x[1]]
    x[2] = service[x[2]]
    x[3] = state[x[3]]
    x = [float(element) for element in x]
    y = label[y]
    return x, y

if __name__ == '__main__':
    # commande = subprocess.Popen("cat UNSW_NB15_training-set.csv | awk -F ',' '{print $4}' | grep -v 'service' | sort | uniq -c | sort -rn | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    # commande = subprocess.Popen("cat UNSW_NB15_training-set.csv | awk -F ',' '{print $5}' | grep -v 'state' | sort | uniq -c | sort -rn | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    # commande = subprocess.Popen("cat UNSW_NB15_training-set.csv | awk -F ',' '{print $44}' | grep -v 'label' | sort | uniq -c | sort -rn | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    commande = subprocess.Popen("cat UNSW_NB15_training-set.csv | awk -F ',' '{print $3}' | grep -v 'proto' | sort | uniq -c | sort -rn | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    (resultat, ignorer) = commande.communicate()
    x = resultat.decode('utf-8').splitlines()
    count = 0
    sets = {}
    for i in x:
        sets[i] = count
        count+=1

    print(sets)
