/*
 * https://git.netfilter.org/libnetfilter_queue/tree/examples/nf-queue.c
 * https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
 * sudo iptables -A OUTPUT -p udp --dst 192.168.42.111 --dport 2152 -j NFQUEUE --queue-num 0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netdb.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/wait.h>
#include <stdint.h>

void dumptable(void);

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

#define DEBUG

uint8_t enbip[4];

struct ue {
    uint8_t teidmme[4];
    uint8_t teidenb[4];
    uint8_t ip[4];
    int id;
};

int uenumber = 0;

#define MAXUE 10
struct ue ue_db[MAXUE];

int tunsoc = -1;

int tun_alloc(char *dev, int flags) {

    struct ifreq ifr;
    int fd, err; 
    char *clonedev = "/dev/net/tun";
    
    if( (fd = open(clonedev, O_RDWR)) < 0 ) {
        fprintf(stderr, "Cannot open clonedevice: %s\n", strerror(errno));
        return -1;
    }   
    
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = flags;
    
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        
    if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
        fprintf(stderr, "Cannot create tun device: %s\n", strerror(errno));
        close(fd);
        return -1;
    }   
    
    if( (err = ioctl(fd, TUNSETNOCSUM, 1)) < 0 ) {
        fprintf(stderr, "Cannot set checksum on device: %s\n", strerror(errno));
        close(fd);
        return -1;
    }   
    
    strcpy(dev, ifr.ifr_name);
    
    return fd;
}   

struct dl_thread_parameters
{
    pthread_t *thread;
    int dlsoc;
    int tunsoc;
    struct sockaddr_in remote;
    struct sockaddr_in local;
};

struct gtpsniffer_thread_parameters
{
    pthread_t *thread;
    int readfd;
};
 
// handles packets to the UE
void *dl_thread(void *ptr)
{
#define BUF_LEN 1600
    uint8_t buffer[BUF_LEN];

    struct dl_thread_parameters *dl_thread_pars = (struct dl_thread_parameters *) ptr;

    while(1) {
        int retc = read(dl_thread_pars->tunsoc, buffer + 8, BUF_LEN - 8);
        if(retc < 0) {
            fprintf(stderr, "Downlink: Cannot read from tun interface: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        } 
#ifdef DEBUG
        fprintf(stdout, "Downlink: received %d bytes\n", retc);
#endif // DEBUG
	uint8_t *ipdst = buffer + 8 + 16;
	int kk;
	for(kk = 0; kk < uenumber; kk ++) {
		if(!memcmp(&ue_db[kk].ip, ipdst, 4)) break;
	}
	if(kk == uenumber) {
		fprintf(stderr, "Downlink: UE not found, dropping packet\n");
		continue;
	}
        // uint8_t head[8] = {0x30, 0xff, 0x00, 0x00, 0xca, 0x6f, 0xe0, 0xdd};
        uint8_t head[8] = {0x30, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(head + 4, ue_db[kk].teidenb, 4);
        head[2] = (retc >> 8);
        head[3] = retc & 0xff;
        memcpy(buffer, head, 8);
        retc = sendto(dl_thread_pars->dlsoc, buffer, retc + 8, 0, (struct sockaddr*)&(dl_thread_pars->remote), sizeof(struct sockaddr_in));
    }
}

static struct mnl_socket *nl;

static struct nlmsghdr *
nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlh;
}

// handles packets from the UE
static void
nfq_send_verdict(int queue_num, uint32_t id, uint8_t *payload, int payload_length)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nlattr *nest;
    int drop = 0;

    if(payload_length >= 56) {
        if(payload[0] == 0x45 &&
           (payload[9] == 0x11 || payload[9] == 1) &&
           payload[28] == 0x30 &&
           payload[29] == 0xff) {
            int inlength = payload[30] << 8 | payload[31];
	    uint8_t teid[4];
#ifdef DEBUG
	    fprintf(stdout, "Uplink: received %d bytes\n", payload_length); 
#endif // DEBUG
	    memcpy(teid, payload + 32, 4);
            // int teid = payload[32] << 24 | payload[33] << 16 | payload[34] << 8 | payload[35];

	    // "fw rules"
	    // drop = 0 <= packet is going to the EPC
	    // drop = 1 <= packet is forwarded to the local interface
	    // ADD RULES BY CHANGING THE FOLLOWING CODE
            if(payload[52] == 172 &&
               payload[53] == 21 &&
               payload[54] == 20 &&
               payload[55] == 100) {
                drop = 1;
		uint8_t *ipsrc = payload + 36 + 12;
		int kk;
		for(kk = 0; kk < uenumber; kk ++) {
		    if(!memcmp(&ue_db[kk].teidmme, teid, 4)) break;
		}
		if(kk == uenumber) {
			fprintf(stderr, "Uplink: UE not found, dropping packet addressed to localbreakout!\n");
		} else {
#ifdef DEBUG
			fprintf(stdout, "Uplink: UE found, forwarding packet to localbreakout\n");
#endif // DEBUG
			memcpy(&ue_db[kk].ip, ipsrc, 4);
                        int retc = write(tunsoc, payload + 36, inlength);
			// dumptable();
		}
                // fprintf(stderr, "Uplink: dropping %d %d\n", inlength, teid);
            }

	    // d2d: whatever happens, copy the src address to the table
	    // if we also know the destination, then forward to the local interface
	    uint8_t *ip = payload + 36;
	    uint8_t *ipsrc = ip + 12;
	    uint8_t *ipdst = ip + 16;
	    if(ipdst[0] == 192 &&
	       ipdst[1] == 168 &&
	       ipdst[2] == 200) {
		int kk;
		for(kk = 0; kk < uenumber; kk ++) {
		    if(!memcmp(&ue_db[kk].teidmme, teid, 4)) break;
		}
		if(kk == uenumber) {
			fprintf(stderr, "Uplink: UE not found, forwarding to EPC\n");
		} else {
			uint8_t zero[4] = {0, 0, 0, 0};
#ifdef DEBUG
			fprintf(stdout, "Uplink: UE found\n");
#endif // DEBUG
			if(!memcmp(&ue_db[kk].ip, zero, 4)) {
				fprintf(stdout, "Uplink: learning new UE ip address\n");
			}
			memcpy(&ue_db[kk].ip, ipsrc, 4);
			int jj;
			for(jj = 0; jj < uenumber; jj ++) {
				if(!memcmp(&ue_db[jj].ip, ipdst, 4)) {
					drop = 1;
#ifdef DEBUG
					fprintf(stdout, "Uplink: forwarding to localbreakout\n");
#endif // DEBUG
					int retc = write(tunsoc, ip, inlength);
					break;
				}
			}
			if(jj == uenumber) {
				fprintf(stderr, "Uplink: dst UE not found, forwarding to EPC\n");
			}
		}
	    }
        }
    }

    nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
    if(drop == 0)
        nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
    else
        nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
    drop = (drop + 1) % 2;

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX+1] = {};
    uint32_t id = 0, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;


    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    uint8_t *payload = (char *) mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            fprintf(stderr, "packet was truncated ");
    }

    id = ntohl(ph->packet_id);

    nfq_send_verdict(ntohs(nfg->res_id), id, payload, plen);

    return MNL_CB_OK;
}

void dumptable()
{
  int kk;
  for(kk = 0; kk < uenumber; kk ++) {
    fprintf(stdout, "%d: %02hhX%02hhX%02hhX%02hhX %02hhX%02hhX%02hhX%02hhX %02hhX%02hhX%02hhX%02hhX %d\n",
	kk,
	ue_db[kk].teidmme[0],
	ue_db[kk].teidmme[1],
	ue_db[kk].teidmme[2],
	ue_db[kk].teidmme[3],
	ue_db[kk].teidenb[0],
	ue_db[kk].teidenb[1],
	ue_db[kk].teidenb[2],
	ue_db[kk].teidenb[3],
	ue_db[kk].ip[0],
	ue_db[kk].ip[1],
	ue_db[kk].ip[2],
	ue_db[kk].ip[3],
	ue_db[kk].id);
  }
}

void processline(char *buffer)
{
/*
  this is the order:
 	from MME: 192.168.42.11   00:00:00:01	4015
 	from ENB: 172.27.232.48   ca:6f:e0:dd	4015,4015
*/
        int id;
        uint8_t ip[4];
        uint8_t teid[4];
        if(sscanf(buffer, "%hhu.%hhu.%hhu.%hhu %hhX:%hhX:%hhX:%hhX %d", &ip[0], &ip[1], &ip[2], &ip[3], &teid[0], &teid[1], &teid[2], &teid[3], &id) == 9) {
		if(!memcmp(enbip, ip, 4)) {
			fprintf(stdout, "gtptunnel: pkt from enodeb\n");
			// a new UE was registered at the ENB, find if it's in the table addressed by its temp id
			int kk;
			for(kk = 0; kk < uenumber; kk ++) {
				if(id == ue_db[kk].id)
				break;
			}
			if(kk == uenumber) {
				fprintf(stderr, "gtptunnel: UE not found\n");
				return;
			}
			fprintf(stdout, "gtptunnel: Adding UE info in table at row #%d\n", kk);
			memcpy(&ue_db[kk].teidenb, teid, 4);
			dumptable();
		} else {
			// a new UE was registered at the MME, find if it's already in the table addressed by its teid number
			int kk;
			for(kk = 0; kk < uenumber; kk ++) {
				if(!memcmp(teid, &ue_db[kk].teidmme, 4)) {
					break;
				}
			}
			if(kk == uenumber && kk == MAXUE) {
				fprintf(stderr, "gtptunnel: TABLE FULL, error\n");
				return;
			}
			if(kk == uenumber) uenumber ++;
			fprintf(stdout, "gtptunnel: Storing UE in table at row #%d\n", kk);
			memset(&ue_db[kk], 0, sizeof(struct ue));
			memcpy(&ue_db[kk].teidmme, teid, 4);
			ue_db[kk].id = id;
			dumptable();
		}
        }
}

void *gtpsniffer_thread(void *gtpsniffer_pars)
{
    struct gtpsniffer_thread_parameters *gtpsniffer_thread_pars = (struct gtpsniffer_thread_parameters *) gtpsniffer_pars;
    int readfd = gtpsniffer_thread_pars->readfd;
    int pos = 0;
    char linebuffer[80];
    while(1) {
        char buffer[1];
        int retc = read(readfd, buffer, 1);
        if(retc <= 0) break;
        linebuffer[pos] = buffer[0];
        if(buffer[0] == '\n') {
          linebuffer[pos] = 0;
          processline(linebuffer);
          pos = 0;
        }
        else {
            pos ++;
            if(pos > 78) pos = 78;
        }
    }
}

void waithandler(int num)
{
    sigset_t set, oldset;
    pid_t pid;
    int status, exitstatus;

    fprintf(stdout, "handler entered in pid %d\n", getpid());

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigprocmask(SIG_BLOCK, &set, &oldset);

    while((pid = waitpid((pid_t)-1, &status, WNOHANG)) > 0) {
        if(WIFEXITED(status)) {
            exitstatus = WEXITSTATUS(status);
            fprintf(stderr,
                    "Child exited, pid=%d, exit status=%d\n",
                    (int)pid, exitstatus);
        }
        else if(WIFSIGNALED(status)) {
            exitstatus = WTERMSIG(status);
            fprintf(stderr,
                    "Child terminated by signal %d, pid = %d\n",
                    exitstatus, (int) pid);
        }
        else if(WIFSTOPPED(status)) {
            exitstatus = WSTOPSIG(status);
            fprintf(stderr,
                    "Child stopped by signal %d, pid = %d\n",
                    exitstatus, (int) pid);
        }
        else {
            fprintf(stderr,
                    "Child died magically, pid = %d\n",
                    (int) pid);
        }
    }

    signal(SIGCHLD, waithandler);
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &set, &oldset);
}

#define SOURCE_NAME "localbreakout"
void usage()
{
    char *usage_str =
        "server version 0.0.1\n"
        "     Usage: " SOURCE_NAME " [hp]\n"
        "                   -h print this message\n"
        "                   -p enodeb udp port\n"
        "                   -a enodeb ip address\n"
        "                   -i tunnel interface\n"
        "                   -g gtp tunnel interface\n"
        "                   -q queue number\n"
        "\n";
    fprintf(stdout, "%s\n", usage_str);

}

int main(int argc, char *argv[])
{
    char *enodeb_udp_port_string = NULL;
    char *enodeb_ip_address_string = NULL;
    char *tunnel_interface_string = NULL;
    char *queue_number_string = NULL;
    char *gtp_tunnel_interface_string = NULL;
    char loc_iface_string[IFNAMSIZ];
    int c;
    int dlsoc = -1;
    struct hostent* converte;
    int udpport;
    struct dl_thread_parameters dl_thread_pars;
    struct gtpsniffer_thread_parameters gtpsniffer_thread_pars;

    while((c = getopt(argc, argv, "hp:a:i:g:q:") ) != EOF ) {
        switch( c ) {
            case 'h':
                usage();
                return -1;

            case 'p':
                enodeb_udp_port_string = optarg;
                break;

            case 'a':
		enodeb_ip_address_string = optarg;
                break;

            case 'i':
                tunnel_interface_string = optarg;
                break;

            case 'q':
                queue_number_string = optarg;
                break;

            case 'g':
                gtp_tunnel_interface_string = optarg;
                break;
                
            default:
		fprintf(stderr, "Invalid parameter\n");
		exit(EXIT_FAILURE);
        }
    }

    if(!gtp_tunnel_interface_string) {
        fprintf(stderr, "Missing gtp tunnel interface\n");
        exit(EXIT_FAILURE);
    }

    if(!tunnel_interface_string) {
        fprintf(stderr, "Missing tunnel interface\n");
        exit(EXIT_FAILURE);
    }
    strncpy(loc_iface_string, tunnel_interface_string, IFNAMSIZ);
    tunsoc = tun_alloc(loc_iface_string, IFF_TUN | IFF_NO_PI);
    if(tunsoc < 0) {
        fprintf(stderr, "Cannot allocate tunnel interface: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    dlsoc = socket(PF_INET, SOCK_DGRAM, 0);
    if(dlsoc == -1) {
        fprintf(stderr, "Cannot create downlink udp socket to the eNodeB: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    dl_thread_pars.local.sin_family = AF_INET;
    dl_thread_pars.local.sin_port = htons(0);
    dl_thread_pars.local.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(dlsoc, (struct sockaddr*) &(dl_thread_pars.local), sizeof(struct sockaddr_in)) == -1) {
        close(dlsoc);
        fprintf(stderr, "Cannot bind downlink udp socket to the eNodeB: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if(!enodeb_ip_address_string) {
        fprintf(stderr, "Missing enode address\n");
        exit(EXIT_FAILURE);
    }
    converte = gethostbyname(enodeb_ip_address_string);
    if(!converte) {
        fprintf(stderr, "Error during enodeb name resolution: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if(!enodeb_udp_port_string) {
        fprintf(stderr, "Missing enode udp port\n");
        exit(EXIT_FAILURE);
    }
    udpport = atoi(enodeb_udp_port_string);
    dl_thread_pars.remote.sin_family = AF_INET;
    dl_thread_pars.remote.sin_port = htons(udpport);
    dl_thread_pars.remote.sin_addr = *(struct in_addr*) converte->h_addr_list[0];

    memcpy(enbip, (uint8_t *) &(dl_thread_pars.remote.sin_addr), 4);

    dl_thread_pars.dlsoc = dlsoc;
    dl_thread_pars.tunsoc = tunsoc;

    // largest possible packet payload, plus netlink data overhead:
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid, queue_num;

    if(!queue_number_string) {
        fprintf(stderr, "Missing queue number\n");
	exit(EXIT_FAILURE);
    }
    queue_num = atoi(queue_number_string);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if(nl == NULL) {
        fprintf(stderr, "Error in mnl_socket_open: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        fprintf(stderr, "Error in mnl_socket_bind: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    char *buf = malloc(sizeof_buf);
    if(!buf) {
        fprintf(stderr, "Error in allocate receive buffer: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* PF_(UN)BIND is not needed with kernels 3.8 and later */
    nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_UNBIND);
    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "Error in mnl_socket_send: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_BIND);
    if(mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "Error in mnl_socket_send: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "Error in mnl_socket_send: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        fprintf(stderr, "Error in mnl_socket_send: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */
    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    signal(SIGCHLD, waithandler);
    int sp[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
        fprintf(stderr, "Cannot create socket pair\n");
        exit(EXIT_FAILURE);
    }

    int tshark_pid = fork();
    if(tshark_pid < 0) {
        fprintf(stderr, "Cannot fork gtp-sniffer\n");
        exit(EXIT_FAILURE);
    }

    if(tshark_pid == 0) {
        dup2(sp[1], STDOUT_FILENO);
        dup2(sp[1], STDERR_FILENO);
        close(sp[0]);
        close(sp[1]);

#define CMDPATH "/bin/bash"
        char cmdstring[128] = "";
        sprintf(cmdstring, "tshark -l -n -i %s -Y \"s1ap.gTP_TEID\" -T \"fields\"  -e \"ip.src\" -e \"s1ap.gTP_TEID\" -e \"s1ap.MME_UE_S1AP_ID\"", gtp_tunnel_interface_string);
        char *nargv[] = {CMDPATH, "-c", NULL, NULL};
        nargv[2] = cmdstring;
        execve(CMDPATH, nargv, NULL);
        fprintf(stderr, "Cannot execute sniffer\n");
        exit(EXIT_FAILURE);
    }

    close(sp[1]);
    gtpsniffer_thread_pars.readfd = sp[0];

    if(pthread_create((void *) &(dl_thread_pars.thread), NULL, dl_thread, (void *) &dl_thread_pars) != 0) {
        fprintf(stderr, "Cannot create downlink thread\n");
        exit(EXIT_FAILURE);
    }

    if(pthread_create((void *) &(gtpsniffer_thread_pars.thread), NULL, gtpsniffer_thread, (void *) &gtpsniffer_thread_pars) != 0) {
        fprintf(stderr, "Cannot create gtp sniffer thread\n");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) {
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
        }

        ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
        if (ret < 0){
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
        }
    }

    mnl_socket_close(nl);

    return 0;
}
