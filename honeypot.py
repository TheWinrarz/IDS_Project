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
    s.shutdown(socket.SHUT_RD)
    s.close()
        #while True:
        #    data = conn.recv(1024)
        #    if not data:
        #        break
        #    conn.sendall(data)
