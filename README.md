# localbreakout
## An opensource localbreakout solution for LTE networks

Use this small demo software to setup a localbreakout daemon on the node that
terminates the LTE air interface. It has been tested with OAI and srsLTE.

Download a short demo video here:

    http://netweb.ing.unibs.it/gringoli/localbreakoutvideo.mp4

In the video I followed the same naming conventions (IP addresses, interfaces)
as in this guide.

### Quick compilation guide:

To compile on ubuntu install first some required libraries and binaries on
on the node that will run the software (and that runs the **eNB**):

```
	sudo apt-get install libmnl-dev libnetfilter-queue-dev openvpn tshark
```

then run `make`.

- openvpn is needed to create the tunnel interface;
- tshark is used to sniff the GTP tunnel signalling ASN.1 traffic.

### Example topology

In the following description we assume the following topology:

- a working LTE network (addresses in the ipLTE line), with ENB and SPGW/MME
  sharing a datalink segment (addresses in the ipLAN line);

- an additional 'virtual' tun/tap network on the node running the eNB (address
  in the ipLB line).
  
```
ipLTE  :   192.168.200.2                                    192.168.200.1
       :
       :         UE                ENB+lbo                     SPGW/MME
       :          o--> air <--USRP----o-------ethernet LAN---------o
       :                              |
ipLAN  :                              |10.20.13.91      10.20.13.92             
       :                              |
       :                              |
       :                              |
ipLB   :                        172.21.20.100
```
Additionally we consider the following names for the interfaces:

- UE:   interface ppp0 (address 192.168.200.2);
- SPGW: interface gtp0 (address 192.168.200.1) and eth0 (address 10.20.13.92);
- eNB:  interface enp0s31f6 (address 10.20.13.91) and
        tun10 (address 172.21.20.100).

On UE the route for SPGW is the default of the ppp0 and points to 10.64.64.64.
UE traffic travels to/from SPGW embedded into GTP/UDP datagrams exchanged on the
ethernet segment.

### Running the local break out

To set up the local break out daemon run in the following order:

  - Create a tun interface on the eNB:

    We need to assign an address that is not used in this case 172.21.20.100.

    We need to tell the eNB where is the UE (usually the eNB does not directly
    exchange traffic with the UE, it acts as a sort of "proxy") so that it can
    reach it through this new interface.

    We have to intercept GTP traffic leaving the eNB and divert it to the
    localbreakout daemon with the help of netfilter/iptables. In this way the
    localbreakout daemon can decide which traffic should we forwarded to the
    SPGW/MME and which should be routed locally.

    On the **eNB** execute
    
```
        sudo openvpn --mktun --dev tun10
        sudo ip link set tun10 up
        sudo ip addr add 172.21.20.100/24 dev tun10

        sudo iptables -A OUTPUT -p udp --dst 10.20.13.92 \
                 --dport 2152 -j NFQUEUE --queue-num 0
        echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
        sudo route add -net 192.168.200.0 netmask 255.255.255.0 tun10
```

  - On the **SPGW** eth0 interface add 100ms artificial delay:

```
        sudo tc qdisc add dev eth0 root netem delay 100ms
```

    To test the delay, on the eNB try pinging the SPGW (you should see 100ms
    delay).

  - Start the localbreakout daemon on the **eNB**:

```
        sudo ./localbreakout -p 2152 -a 10.20.13.90 -i tun10 \
                 -q 0 -g enp0s31f6
```

  - Start the EPC/SPGW stuff, start eNB, start UE.

  - After LTE network is started, check on the localbreakout daemon there is a
    like similar to this one:

```
        Storing UE in table at row #0
        0: 00000001 00000000 00000000 1
        pkt from enodeb
        Adding UE info in table at row #0
        0: 00000001 CA6FE0DD 00000000 1
        UE not found, dropping packet
        learning new UE ip address
```

  - Once network works try pinging the SPGW from the UE, you should observe
    high latency because of the artificial delay. Run in the **UE**:

```
        ping 192.168.200.1
        PING 192.168.200.1 (192.168.200.1) 56(84) bytes of data.
        64 bytes from 192.168.200.1: icmp_seq=1 ttl=64 time=136 ms
```

  - Now tell the **UE** where the "local" address on the eNB tun10 is:

        `sudo route add 172.21.20.100 gw 10.64.64.64`

  - Try pinging the localbreakout from the **UE**, latency must be much smaller:

```
        ping 172.21.20.100
        PING 172.21.20.100 (172.21.20.100) 56(84) bytes of data.
        64 bytes from 172.21.20.100: icmp_seq=1 ttl=64 time=30.1 ms
```
