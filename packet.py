from pcapy import open_offline
from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP
from impacket.ImpactPacket import TCPOption

pcap = open_offline("/Users/michaelb/Downloads/SlowchopCaptures/small3.cap")

decoder = EthDecoder()
metrics = {}

def callback(hdr,data):
    packet = decoder.decode(data)
    l2 = packet.child()
    if isinstance(l2,IP):
        src_ip = l2.get_ip_src()
        dst_ip = l2.get_ip_dst()
        ip_version = l2.get_ip_v() 
        ip_ttl = l2.get_ip_ttl()
        ip_df = l2.get_ip_df() #16 bit field outputs 16384 if set
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

              signature = []
              #Set features to zero incase they are not set in the packet
              tcp_mss=0
              tcp_window=0
              tcp_scale=0
              tcp_olen=0

              option_layout = []
              option_numeric = []

              for option in l3.get_options():
                   option_numeric.append(option.get_kind())
                   tcp_olen = option.get_size()
                   if option.get_kind() == TCPOption.TCPOPT_EOL:
                       #TCP Option 0
                       option_layout.append('eol')

                   elif option.get_kind() == TCPOption.TCPOPT_NOP:
                       #TCP Option 1
                       option_layout.append('nop')

                   elif option.get_kind() == TCPOption.TCPOPT_MAXSEG:
                       #TCP Option 2
                       option_layout.append('mss')
                       tcp_mss = option.get_mss()

                   elif option.get_kind() ==TCPOption.TCPOPT_WINDOW:
                       #TCP Option 3 - Window Scale
                       option_layout.append('scale')
                       tcp_scale = option.get_shift_cnt()

                   elif option.get_kind() == TCPOption.TCPOPT_SACK_PERMITTED:
                       #TCP Option 4
                       option_layout.append('sok')

                   elif option.get_kind() == TCPOption.TCPOPT_SACK:
                       #TCP Option 5
                       option.layout.append('sack')

                   elif option.get_kind() == TCPOption.TCPOPT_TIMESTAMP:
                       #print option.get_ts()
                       option_layout.append('ts')
                       #print option.get_ts_echo()

                   elif option.get_kind() == TCPOption.TCPOPT_SIGNATURE:
                       #TCP Option 19
                       option.layout.append('sig')
                       print "sig"
               
              #Finish catch-all and add option number e.g. n?
              #Create dictionary for ip address and add metrics.
              # If the key exists don't add the metric
              # Print all IP's and metrics.

              signature.append(ip_version)
              signature.append(ip_ttl)
              signature.append(tcp_olen)
              signature.append(ip_hl)
              signature.append(tcp_mss)
              signature.append(tcp_window)
              signature.append(tcp_scale)
              signature.append(option_layout)


              if src_ip in metrics:
                 pass
              else:
                  metrics[src_ip] = signature 


pcap.loop(0,callback)
for k,v in metrics.items():
  print "%s,%s" % (k,v)

