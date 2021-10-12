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
#include "iphdr.h"

#define ETHER_HDR_LEN 14
#define IP_HDR_LEN 20
#define MAC_LEN 17
#define IP_LEN 15
#define PERIOD 3

using std::string;
using std::cout;
using std::endl;
using std::map;
using std::vector;
using std::pair;

typedef enum _status
{
    OK,NO,P,NP
}STATUS;

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push,1)
struct EthIpPacket final
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

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
    pcap_t * handle;
    map<Ip,Mac> *table;
    Mac s_mac;
    Mac t_mac;
    Ip s_ip;
    Ip t_ip;
    Mac a_mac;
    STATUS status;
}Spoof_arg;
#pragma pack(pop)

typedef struct _rcarg
{
    pcap_t* handle;
    EthArpPacket p;
}Recover_arg;

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
sem_t sem;
sem_t s;
int chk_val = 1;