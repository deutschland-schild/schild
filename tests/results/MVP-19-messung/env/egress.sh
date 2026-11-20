#!/bin/sh
# Runs in m19-tools: summarise every connection the ingress address opened
# (TCP SYN without ACK, UDP) and every DNS name it asked for, from the
# tcpdump capture of the shared netns (all phases: schild and stock Caddy).
P=${1:-/st/cap/ingress.pcap}
dst() { awk '{for(i=1;i<=NF;i++) if($i==">") {d=$(i+1); sub(/:$/,"",d); n=split(d,a,"."); print a[1]"."a[2]"."a[3]"."a[4]":"a[5]}}'; }
echo "TCP connection attempts from the ingress (dst ip:port, count):"
tcpdump -nn -r "$P" 'src host 10.219.19.10 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null | dst | sort | uniq -c
echo "UDP from the ingress (dst ip:port, count):"
tcpdump -nn -r "$P" 'src host 10.219.19.10 and udp' 2>/dev/null | dst | sort | uniq -c
echo "Loopback UDP to 127.0.0.11 (Docker DNS):"
tcpdump -nn -r "$P" 'dst host 127.0.0.11' 2>/dev/null | dst | sort | uniq -c
echo "DNS questions:"
tcpdump -nn -r "$P" 'port 53 or dst host 127.0.0.11' 2>/dev/null | grep -oE ' (A|AAAA)\? [^ ]+' | sort | uniq -c
echo "packets total: $(tcpdump -nn -r "$P" 2>/dev/null | wc -l)"
