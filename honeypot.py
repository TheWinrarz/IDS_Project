import socket
import sys
import datetime


hostip = "0.0.0.0"
#hostname = socket.gethostname()
#hostip = socket.gethostbyname(hostname)
port = 22 #int(sys.argv[1])
print(hostip)
print(port)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((hostip, port))
    while True:
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(addr)
            log = open("incident_log", "a+")
            string = "===============honeypot.py=============\n"
            string = string + "Time: " + str(datetime.datetime.now()) + "\n"
            string = string + "Source IP: " + addr[0] + " - Source Port: " + str(addr[1]) + "\n"
            log.write(string)
            log.close()
    s.shutdown(socket.SHUT_RD)
    s.close()

