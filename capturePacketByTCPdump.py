import subprocess
from scapy.all import *
from packetProcessed import realPacket, processedPacket

column_realpacket = "num_conn, startTimet, orig_pt, resp_pt, orig_ht, resp_ht, duration, protocol, resp_pt, flag, src_bytes, dst_bytes, land, wrong_fragment, urg, hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_hot_login, is_guest_login, count_sec, srv_count_sec, serror_rate_sec, srv_serror_rate_sec, rerror_rate_sec, srv_error_rate_sec, same_srv_rate_sec, diff_srv_rate_sec, srv_diff_host_rate_sec, count_100, srv_count_100, same_srv_rate_100, diff_srv_rate_100, same_src_port_rate_100, srv_diff_host_rate_100, serror_rate_100, srv_serror_rate_100, rerror_rate_100, srv_rerror_rate_100"
column_KDD = ['duration', 'protocol_type','service', 'flag','src_bytes', 'dst_bytes','land', 'wrong_fragment','urgent', 'hot','num_failed_logins', 'logged_in','num_compromised', 'root_shell','su_attempted', 'num_root','num_file_creations', 'num_shells','num_access_files', 'num_outbound_cmds','is_host_login', 'is_guest_login','count', 'srv_count','serror_rate', 'srv_serror_rate','rerror_rate', 'srv_rerror_rate','same_srv_rate', 'diff_srv_rate','srv_diff_host_rate', 'dst_host_count','dst_host_srv_count', 'dst_host_same_srv_rate','dst_host_diff_srv_rate', 'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate', 'dst_host_serror_rate','dst_host_srv_serror_rate', 'dst_host_rerror_rate','dst_host_srv_rerror_rate']

def processGetData():
    p = subprocess.Popen("sudo tcpdump -c 1 -w transformation/capture.pcap -i enp3s0",shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    print(rs, err)

    p = subprocess.Popen("sudo bro -r transformation/capture.pcap BroCapture/darpa2gurekddcup.bro > transformation/conn.list",shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)
    p = subprocess.Popen("sort -n transformation/conn.list > transformation/conn_sort.list",shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)
    p = subprocess.Popen("./BroCapture/trafAld.out transformation/conn_sort.list",shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)

    file = open("trafAld.list", "r")
    count = 0
    for line in file.readlines():
        linedata = line.replace("\n","")
        arraydata = linedata.split(" ")
        realpacket = realPacket(arraydata)
        processedpacket = processedPacket(realpacket)
        count+=1
        # temp = vars(processedpacket)
        # for item in temp:
        #     print (item , ' : ' , temp[item])
        # print(processedPacket)
    print(count)

processGetData()

