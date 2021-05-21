import subprocess
from scapy.all import *
from packetProcessed import realPacket, processedPacket
import queue, numpy, os
from kdd_predict import predict_data,number_of_label,label_list

max_size_batch = 50
max_shown_ip = 20
packets = []
packets_queue = queue.Queue()

hmap_statical = {}


def processGetData():
    p = subprocess.Popen(
        "sudo bro -r transformation/capture.pcap BroCapture/darpa2gurekddcup.bro > transformation/conn.list",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)
    p = subprocess.Popen("sort -n transformation/conn.list > transformation/conn_sort.list", shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)
    p = subprocess.Popen("./BroCapture/trafAld.out transformation/conn_sort.list", shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    rs, err = p.communicate()
    # print(rs, err)

    file = open("trafAld.list", "r")
    count = 0
    X_predict = []
    list_ip = []

    for line in file.readlines():
        x_predict = []
        linedata = line.replace("\n", "")
        arraydata = linedata.split(" ")
        realpacket = realPacket(arraydata)
        processedpacket = processedPacket(realpacket)
        count += 1
        temp = vars(processedpacket)

        for item in temp:
            x_predict.append(temp[item])
        X_predict.append(x_predict)
        list_ip.append(realpacket.orig_ht)
    X_predict = numpy.array(X_predict)

    # Save results
    Y_result = predict_data(X_predict)

    for i in range(len(list_ip)):
        ip = list_ip[i]
        y_result = Y_result[i]

        if ip not in hmap_statical:
            hmap_statical[ip] = {y_result: 1}
            for label in label_list:
                if y_result != label:
                    hmap_statical[ip][label] = 0
        else:
            if y_result in hmap_statical[ip]:
                hmap_statical[ip][y_result] += 1
            else:
                hmap_statical[ip][y_result] = 1

    # print table results
    os.system('clear')
    if number_of_label == 5:
        most_statical = dict(sorted(hmap_statical.items(), key=lambda item: item[1]['dos'], reverse=True))
        print("%-40s %-10s %-10s %-10s %-10s %-10s" % ("IP", "normal", "dos", "probe", "u2r", "r2l"))
        count = 0
        for key in most_statical.keys():
            if count < max_shown_ip:
                results = hmap_statical[key]
                print("%-40s %-10s %-10s %-10s %-10s %-10s" % (
                key, results["normal"] if "normal" in results else 0, results["dos"] if "dos" in results else 0,
                results["probe"] if "probe" in results else 0, results["u2r"] if "u2r" in results else 0,
                results["r2l"] if "r2l" in results else 0))
                count+=1
            else:
                break
    else:
        most_statical = dict(sorted(hmap_statical.items(), key=lambda item: item[1]['abnormal'], reverse=True))
        print("%-40s %-10s %-10s" % ("IP", "normal", "abnormal"))
        count = 0
        for key in most_statical.keys():
            if count < max_shown_ip:
                results = hmap_statical[key]
                print("%-40s %-10s %-10s" % (
                key, results["normal"] if "normal" in results else 0, results["abnormal"] if "abnormal" in results else 0))
                count+=1
            else:
                break

def process_queue():
    while True:
        pkts = packets_queue.get()
        open("transformation/capture.pcap", "w").close()
        for pkt in pkts:
            wrpcap('transformation/capture.pcap', pkt, append=True)
        processGetData()

def capture_packet(packet):
    global packets, max_size_batch
    packets.append(packet)
    if len(packets) >= max_size_batch:
        packets_queue.put(packets)
        packets = []


threadProcessQueue = threading.Thread(name='threadProcessQueue', target=process_queue)
threadProcessQueue.start()
sniff(iface="enp3s0", prn=capture_packet)
#sniff(iface="wlo1",prn=capture_packet)
