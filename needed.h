#pragma once
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <map>
#include <vector>
#include <utility>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "common-threads.h"
#include "ethhdr.h"
#include "arphdr.h"

#define ETHER_HDR_LEN 14
#define MAC_LEN 17
#define IP_LEN 15
#define PERIOD 11

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef enum _status
{
    OK,NO,P,NP
}STATUS;

#pragma pack(push, 1)
typedef struct _rarg
{
    pcap_t * handle;
    Mac a_mac;
    Ip a_ip;
    Ip ip;
    Mac* ans;
}Resolve_arg;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _sarg
{
    //arp_infection(pcap_t *handle, Mac s_mac, Ip s_ip, Ip t_ip, Mac a_mac)
    pcap_t * handle;
    Mac s_mac;
    Ip s_ip;
    Ip t_ip;
    Mac a_mac;
    STATUS status;
}Spoof_arg;
#pragma pack(pop)

typedef struct _ryarg
{
    pcap_t* handle;
    EthArpPacket p;
}Relay_arg;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;
int chk_val = 1;

using std::string;
using std::cout;
using std::endl;
using std::map;
using std::vector;
using std::pair;