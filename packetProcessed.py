import socket
from scapy.all import *

map_name_serv = {(109, 'tcp'):'pop_2', (1911, 'tcp'):'mtp',(143, 'tcp'):'imap4',(993, 'tcp'):'imap4', (2784, 'tcp'):'http_2784', (194, 'tcp'):'IRC',(8001, 'tcp'):'http_8001',(443, 'tcp'):'http_443', (53, 'udp'):'domain_u', (69, 'udp'):'tftp_u',(123, 'udp'):'ntp_u', (105, 'tcp'):'csnet_ns',(102, 'tcp'):'iso_tsap',(138, 'tcp'):'netbios_dgm',(137, 'tcp'):'netbios_ns',(139, 'tcp'):'netbios_ssn',(20, 'tcp'):'ftp_data',(110, 'tcp'):'pop_3',(80, 'tcp'): 'http', (25, 'tcp'): 'smtp', (23, 'tcp'): 'telnet', (79, 'tcp'): 'finger', (21, 'tcp'): 'ftp', (113, 'tcp'): 'auth', (540, 'tcp'): 'uucp', (530, 'tcp'): 'courier', (179, 'tcp'): 'bgp', (43, 'tcp'): 'whois', (37, 'tcp'): 'time', (53, 'tcp'): 'domain', (95, 'tcp'): 'supdup', (9, 'tcp'): 'discard', (13, 'tcp'): 'daytime', (70, 'tcp'): 'gopher', (11, 'tcp'): 'systat', (87, 'tcp'): 'link', (512, 'tcp'): 'exec', (101, 'tcp'): 'hostnames', (42, 'tcp'): 'name', (7, 'tcp'): 'echo', (543, 'tcp'): 'klogin', (513, 'tcp'): 'login', (389, 'tcp'): 'ldap', (111, 'tcp'): 'sunrpc', (15, 'tcp'): 'netstat', (22, 'tcp'): 'ssh', (544, 'tcp'): 'kshell', (119, 'tcp'): 'nntp', (515, 'tcp'): 'printer', (514, 'tcp'): 'shell', (5190, 'tcp'): 'aol'}

class realPacket:
    def __init__(self, arr_data_attributes):
        self.num_conn=arr_data_attributes[0]
        self.startTimet=arr_data_attributes[1]
        self.orig_pt=arr_data_attributes[2]
        self.resp_pt=arr_data_attributes[3] # port response
        self.orig_ht=arr_data_attributes[4] # not use MAC orig
        self.resp_ht=arr_data_attributes[5] # not use MAC resp
        self.duration=arr_data_attributes[6]
        self.protocol=arr_data_attributes[7]
        self.resp_pt=arr_data_attributes[8] # redundant + not use
        self.flag=arr_data_attributes[9]
        self.src_bytes=arr_data_attributes[10]
        self.dst_bytes=arr_data_attributes[11]
        self.land=arr_data_attributes[12]
        self.wrong_fragment=arr_data_attributes[13]
        self.urg=arr_data_attributes[14]
        self.hot=arr_data_attributes[15]
        self.num_failed_logins=arr_data_attributes[16]
        self.logged_in=arr_data_attributes[17]
        self.num_compromised=arr_data_attributes[18]
        self.root_shell=arr_data_attributes[19]
        self.su_attempted=arr_data_attributes[20]
        self.num_root=arr_data_attributes[21]
        self.num_file_creations=arr_data_attributes[22]
        self.num_shells=arr_data_attributes[23]
        self.num_access_files=arr_data_attributes[24]
        self.num_outbound_cmds=arr_data_attributes[25]
        self.is_hot_login=arr_data_attributes[26]
        self.is_guest_login=arr_data_attributes[27]
        self.count_sec=arr_data_attributes[28]
        self.srv_count_sec=arr_data_attributes[29]
        self.serror_rate_sec=arr_data_attributes[30]
        self.srv_serror_rate_sec=arr_data_attributes[31]
        self.rerror_rate_sec=arr_data_attributes[32]
        self.srv_error_rate_sec=arr_data_attributes[33]
        self.same_srv_rate_sec=arr_data_attributes[34]
        self.diff_srv_rate_sec=arr_data_attributes[35]
        self.srv_diff_host_rate_sec=arr_data_attributes[36]
        self.count_100=arr_data_attributes[37]
        self.srv_count_100=arr_data_attributes[38]
        self.same_srv_rate_100=arr_data_attributes[39]
        self.diff_srv_rate_100=arr_data_attributes[40]
        self.same_src_port_rate_100=arr_data_attributes[41]
        self.srv_diff_host_rate_100=arr_data_attributes[42]
        self.serror_rate_100=arr_data_attributes[43]
        self.srv_serror_rate_100=arr_data_attributes[44]
        self.rerror_rate_100=arr_data_attributes[45]
        self.srv_rerror_rate_100=arr_data_attributes[46]

class processedPacket:

    def __init__(self, realpacket):
        self.duration=realpacket.duration
        self.protocol_type=realpacket.protocol
        self.service=-1
        self.flag=realpacket.flag
        self.src_bytes=realpacket.src_bytes
        self.dst_bytes=realpacket.dst_bytes
        self.land=realpacket.land
        self.wrong_fragment=realpacket.wrong_fragment
        self.urgent=realpacket.urg # not sure
        self.hot=realpacket.hot
        self.num_failed_logins=realpacket.num_failed_logins
        self.logged_in=realpacket.logged_in
        self.num_compromised=realpacket.num_compromised
        self.root_shell=realpacket.root_shell
        self.su_attempted=realpacket.su_attempted
        self.num_root=realpacket.num_root
        self.num_file_creations=realpacket.num_file_creations
        self.num_shells=realpacket.num_shells
        self.num_access_files=realpacket.num_access_files
        self.num_outbound_cmds=realpacket.num_outbound_cmds
        self.is_host_login=realpacket.is_hot_login
        self.is_guest_login=realpacket.is_guest_login
        self.count=realpacket.count_sec
        self.srv_count=realpacket.srv_count_sec
        self.serror_rate=realpacket.serror_rate_sec
        self.srv_serror_rate=realpacket.srv_serror_rate_sec
        self.rerror_rate=realpacket.rerror_rate_sec
        self.srv_rerror_rate=realpacket.srv_error_rate_sec
        self.same_srv_rate=realpacket.same_srv_rate_sec
        self.diff_srv_rate=realpacket.diff_srv_rate_sec
        self.srv_diff_host_rate=realpacket.srv_diff_host_rate_sec
        self.dst_host_rate=realpacket.count_100
        self.dst_host_srv_count=realpacket.srv_count_100
        self.dst_host_diff_srv_rate=realpacket.diff_srv_rate_100
        self.dst_host_same_srv_rate=realpacket.same_srv_rate_100
        self.dst_host_same_srv_port_rate=realpacket.same_src_port_rate_100 # not sure
        self.dst_host_srv_diff_host_rate=realpacket.srv_diff_host_rate_100
        self.dst_host_serror_rate=realpacket.serror_rate_100
        self.dst_host_srv_serror_rate=realpacket.srv_serror_rate_100
        self.dst_host_rerror_rate=realpacket.rerror_rate_100
        self.dst_host_srv_rerror_rate=realpacket.srv_rerror_rate_100

        dport = int(realpacket.resp_pt)
        key_service = (dport, realpacket.protocol)
        # print(key_service)
        # print(key_service in map_name_serv)
        if key_service in map_name_serv:
            self.service = map_name_serv[key_service]
        elif ((realpacket.protocol == 'tcp') | (realpacket.protocol == 'udp')) & (49152 <= dport) & (dport <= 65535):
            self.service = "private"
        else:
            self.service = "other"

# i = 1
# keys = [*map_name_serv.keys()]
# print(keys)
# for j in range((len(keys) // 2) + 1):
#     key = keys[j]
#     if key == (143, 'tcp'):
#         continue
#     if j == ((len(keys) // 2)):
#         print(str(i) + " & " + map_name_serv[key] +  " & " +str(key[0]) +  " & " + str(key[1]) +
#               " & & & & " + " \\\\ \\hline")
#     else:
#         key2 = keys[j+(len(keys) // 2) + 1]
#         print(str(i) + " & " + map_name_serv[key] +  " & " +str(key[0]) +  " & " + str(key[1]) +
#               " & " +  str(i+ (len(keys) // 2) + 1) + " & " + map_name_serv[key2] +  " & " +str(key2[0]) +  " & " + str(key2[1]) + " \\\\ \\hline")
#     i+=1
