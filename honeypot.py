import socket

host = '127.0.0.1'
port = 2222



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    while True:
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(addr)
            log = open("incident_log", "a+")
            string = "==============honeypot.py=============\n"
            string = string + "Source IP: " + addr[0] + " - Source Port: " + str(addr[1]) + "\n"
            log.write(string)
            log.close()
    s.shutdown(socket.SHUT_RD)
    s.close()
        #while True:
        #    data = conn.recv(1024)
        #    if not data:
        #        break
        #    conn.sendall(data)
