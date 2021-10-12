# arp-spoof

These are what I done with the code. :)

1. Resolve both MAC addr of sender and target
2. Infect both arp table of sender and target
3. Relay reqeusts and replies
4. Do not modify CAM table of L2 switch (even in wireless environment!)
5. Infect arp table of sender and target PERIODICALLY AND NON-PERIODICALLY (non-periodically means it sends arp infection packets only when it has to).
6. Send Recover packets to both sender and target when program exits
7. Use threads for above operations

![mine-2021-10-13-03-11-28](https://user-images.githubusercontent.com/31784008/137011186-cbb1e5b0-3bc6-4f35-a9bc-7cacf22483c3.png)
![mine-2021-10-13-03-34-38](https://user-images.githubusercontent.com/31784008/137011194-d86cafba-6284-483d-8f69-46a15667d3d1.png)
