import socket
# Service list has a list of application protocols
serviceList = ["http","private","domain_u","smtp","ftp_data","eco_i","private","ecr_i","other","telnet","other","finger","ftp","auth","Z39_50","uucp","courier","bgp","whois","uucp_path","iso_tsap","time","imap4","nnsp","vmnet","urp_i","domain","ctf","csnet_ns","supdup","discard","http_443","daytime","gopher","efs","systat","link","exec","hostnames","name","mtp","echo","klogin","login","ldap","netbios_dgm","sunrpc","netbios_ssn","netstat","netbios_ns",",ssh","kshell","nntp","pop_3","sql_net","IRC","ntp_u","rje","remote_job","pop_2","X11","printer","shell","urh_i","tim_i","red_i","pm_dump","tftp_u","http_8001","harvest","aol","http_2784"]
protocol = ["tcp","tcp","udp","tcp","tcp","icmp","udp","icmp","udp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","icmp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","tcp","udp","tcp","tcp","tcp","tcp","tcp","tcp","icmp","icmp","icmp","tcp","udp","tcp","tcp","tcp","tcp"]

service = [("http","tcp"),("private","tcp"),("domain_u","udp"),("smtp","tcp"),("ftp_data","tcp"),("eco_i","icmp"),("private","udp"),("ecr_i","icmp"),("other","udp"),("telnet","tcp"),("other","tcp"),("finger","tcp"),("ftp","tcp"),("auth","tcp"),("Z39_50","tcp"),("uucp","tcp"),("courier","tcp"),("bgp","tcp"),("whois","tcp"),("uucp_path","tcp"),("iso_tsap","tcp"),("time","tcp"),("imap4","tcp"),("nnsp","tcp"),("vmnet","tcp"),("urp_i","icmp"),("domain","tcp"),("ctf","tcp"),("csnet_ns","tcp"),("supdup","tcp"),("discard","tcp"),("http_443","tcp"),("daytime","tcp"),("gopher","tcp"),("efs","tcp"),("systat","tcp"),("link","tcp"),("exec","tcp"),("hostnames","tcp"),("name","tcp"),("mtp","tcp"),("echo","tcp"),("klogin","tcp"),("login","tcp"),("ldap","tcp"),("netbios_dgm","tcp"),("sunrpc","tcp"),("netbios_ssn","tcp"),("netstat","tcp"),("netbios_ns","tcp"),("ssh","tcp"),("kshell","tcp"),("nntp","tcp"),("pop_3","tcp"),("sql_net","tcp"),("IRC","tcp"),("ntp_u","udp"),("rje","tcp"),("remote_job","tcp"),("pop_2","tcp"),("X11","tcp"),("printer","tcp"),("shell","tcp"),("urh_i","icmp"),("tim_i","icmp"),("red_i","icmp"),("pm_dump","tcp"),("tftp_u","udp"),("http_8001","tcp"),("harvest","tcp"),("aol","tcp"),("http_2784","tcp")]

underlyingProtocol = "tcp"

def translateArray():
    hmap = {}
    strs = "["
    for serv in service:
        try:
            portNum = socket.getservbyname(serv[0], serv[1])
            # print("The service {} uses port number {} ".format(serv[0], portNum))
            strs += "(\"" + serv[0] + "\",\"" + serv[1] + "\"),"
            hmap[(portNum,serv[1])] = serv[0]
        except Exception as e:
            strs += "\n#(\"" + serv[0] + "\",\"" + serv[1] + "\"),\n"
            # hmap[(portNum,serv[1])] = "other"
    print(strs)
    print(hmap)
    print(len(hmap))

def translate(name, proto):
    portNum = socket.getservbyname(name, proto)
    print(str((portNum, proto))  + ":'" + str(name) + "'")

translate("pop-2","tcp")
# print(socket.getservbyport(109, "tcp"))


formatservice = [("http","tcp"),
("private","tcp"),
("domain_u","udp"),
("smtp","tcp"),
("ftp_data","tcp"),
#("eco_i","icmp"),
("private","udp"),
#("ecr_i","icmp"),
("other","udp"),
("telnet","tcp"),
("other","tcp"),
("finger","tcp"),("ftp","tcp"),("auth","tcp"),
#("Z39_50","tcp"),
("uucp","tcp"),("courier","tcp"),("bgp","tcp"),("whois","tcp"),
#("uucp_path","tcp"),
("iso_tsap","tcp"),
("time","tcp"),
("imap4","tcp"),
#("nnsp","tcp"),
#("vmnet","tcp"),
#("urp_i","icmp"),
("domain","tcp"),
#("ctf","tcp"),
("csnet_ns","tcp"),
("supdup","tcp"),("discard","tcp"),
("http_443","tcp"),
("daytime","tcp"),("gopher","tcp"),
#("efs","tcp"),
("systat","tcp"),("link","tcp"),("exec","tcp"),("hostnames","tcp"),("name","tcp"),
("mtp","tcp"),
("echo","tcp"),("klogin","tcp"),("login","tcp"),("ldap","tcp"),
("netbios_dgm","tcp"),
("sunrpc","tcp"),
("netbios_ssn","tcp"),
("netstat","tcp"),
("netbios_ns","tcp"),
("ssh","tcp"),("kshell","tcp"),("nntp","tcp"),
("pop_3","tcp"),
#("sql_net","tcp"),
("IRC","tcp"),
("ntp_u","udp"),
#("rje","tcp"),
#("remote_job","tcp"),
("pop_2","tcp"),
#("X11","tcp"),
("printer","tcp"),("shell","tcp"),
#("urh_i","icmp"),
#("tim_i","icmp"),
#("red_i","icmp"),
#("pm_dump","tcp"),
("tftp_u","udp"),
("http_8001","tcp"),
#("harvest","tcp"),
("aol","tcp"),
("http_2784","tcp")
]

####################################################################################################

formatservice = [("http","tcp"),
#("private","tcp"),
#("domain_u","udp"),
("smtp","tcp"),
#("ftp_data","tcp"),
#("eco_i","icmp"),
#("private","udp"),
#("ecr_i","icmp"),
#("other","udp"),
("telnet","tcp"),
#("other","tcp"),
("finger","tcp"),("ftp","tcp"),("auth","tcp"),
#("Z39_50","tcp"),
("uucp","tcp"),("courier","tcp"),("bgp","tcp"),("whois","tcp"),
#("uucp_path","tcp"),
#("iso_tsap","tcp"),
("time","tcp"),
#("imap4","tcp"),
#("nnsp","tcp"),
#("vmnet","tcp"),
#("urp_i","icmp"),
("domain","tcp"),
#("ctf","tcp"),
#("csnet_ns","tcp"),
("supdup","tcp"),("discard","tcp"),
#("http_443","tcp"),
("daytime","tcp"),("gopher","tcp"),
#("efs","tcp"),
("systat","tcp"),("link","tcp"),("exec","tcp"),("hostnames","tcp"),("name","tcp"),
#("mtp","tcp"),
("echo","tcp"),("klogin","tcp"),("login","tcp"),("ldap","tcp"),
#("netbios_dgm","tcp"),
("sunrpc","tcp"),
#("netbios_ssn","tcp"),
("netstat","tcp"),
#("netbios_ns","tcp"),
("ssh","tcp"),("kshell","tcp"),("nntp","tcp"),
#("pop_3","tcp"),
#("sql_net","tcp"),
#("IRC","tcp"),
#("ntp_u","udp"),
#("rje","tcp"),
#("remote_job","tcp"),
#("pop_2","tcp"),
#("X11","tcp"),
("printer","tcp"),("shell","tcp"),
#("urh_i","icmp"),
#("tim_i","icmp"),
#("red_i","icmp"),
#("pm_dump","tcp"),
#("tftp_u","udp"),
#("http_8001","tcp"),
#("harvest","tcp"),
("aol","tcp")
#("http_2784","tcp")
]
