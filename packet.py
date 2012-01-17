from pcapy import open_offline
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from impacket.ImpactPacket import TCPOption

pcap = open_offline("/Users/michaelb/Downloads/SlowchopCaptures/small3.cap")

decoder = EthDecoder()

def callback(hdr,data):
    packet = decoder.decode(data)
    l2 = packet.child()
    if isinstance(l2,IP):
        src_ip = l2.get_ip_src()
        dst_ip = l2.get_ip_dst()
        ip_ttl = l2.get_ip_ttl()
        ip_df = l2.get_ip_df()
        ip_hl = l2.get_ip_hl()
        l3 = l2.child()
        if isinstance(l3,TCP):
            if l3.get_SYN()==1 and l3.get_ACK()==0 and l3.get_FIN() == 0:

              tcp_dst_port = l3.get_th_sport()
              tcp_src_port = l3.get_th_dport()
              tcp_seq = l3.get_th_seq()
              tcp_flags = l3.get_th_flags()
              tcp_window = l3.get_th_win()
              tcp_header_size = l3.get_header_size()
              tcp_size = l3.get_size()
              tcp_syn_bit = l3.get_flag(2)


              option_layout = []
              for option in l3.get_options():
                   option_layout.append(option.get_kind())

                   if option.get_kind() == TCPOption.TCPOPT_EOL:
                       #TCP Option 0
                       print "tcp_eol"

                   if option.get_kind() == TCPOption.TCPOPT_NOP:
                       #TCP Option 1
                       print "nop"

                   if option.get_kind() == TCPOption.TCPOPT_MAXSEG:
                       #TCP Option 2
                       print "max_seg"
                       print "MSS: %s" % option.get_mss()

                   if option.get_kind() ==TCPOption.TCPOPT_WINDOW:
                       #TCP Option 3 - Window Scale
                       print "scale"
                       print option.get_len()

                   if option.get_kind() == TCPOption.TCPOPT_SACK_PERMITTED:
                       #TCP Option 4
                       print "sack_permitted"
                   
                   if option.get_kind() == TCPOption.TCPOPT_SACK:
                       #TCP Option 5
                       print "sack"

                   if option.get_kind() == TCPOption.TCPOPT_TIMESTAMP:
                       print option.get_ts()
                       print option.get_ts_echo()
                   
                   if option.get_kind() == TCPOption.TCPOPT_SIGNATURE:
                       #TCP Option 19
                       print "sig"

              print "%s -> %s(%s)" % (src_ip, dst_ip, tcp_dst_port)
              print "TTL:%s, DF:%s, Header Length: %s" % (ip_ttl, ip_df, ip_hl) 
              print "Seq: %s, Flags: %s, Window: %s" % (tcp_seq, tcp_flags,
                      tcp_window)
              print "Header Size: %s, Size: %s" % (tcp_header_size, tcp_size)
              print "Options: %s" % option_layout

           #print

pcap.loop(10,callback)

print "Finished"
