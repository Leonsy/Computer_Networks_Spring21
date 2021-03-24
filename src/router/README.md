# README for Assignment 2: Router

Name: Siyang Piao

JHED: spiao2

---

****DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE****

  

This will be worth 10% of the assignment grade.
  

Some guiding questions:

- What files did you modify (and why)?

- What helper method did you write (and why)?

- What logic did you implement in each file/method?

- What problems or challenges did you encounter?

---
  
## README
In this assignment, I have modified 3 files. They are `sr_router.c`, `sr_router.h` and `sr_arpcache.c`.

### sr_router.c
`sr_router.c` contains the majority of the logic. `sr_handlepacket` is the main entry point for handling the request we received. 

**Helper functions**
`sr_send_icmp_t3`: This function contains logic to send ICMP request for all cases except type 0. It creates a new packet by  `malloc`. By passing different type and code as input, this function can send different ICMP request respectively. 

`sr_send_icmp_t0`: This function only handles the ICMP type 0. As for ICMP type 0, we need to reuse the incoming Ping request packet. Instead of create the packet from scratch, this function modifies the original reuqest. 

`longest_prefix_match`: This function finds the entry in our routing table that has the longest prefix match with the input ip address. And returns the interface of the matched entry. 


**Main logic**
Base on the `ethertype`, I created two function to handle ip and arp request respectively. 

For ARP case, `handle_arp` handles both the scenario for ARP request and APR reply. There is also logic to check if the  ARP request  is for our router. ARP request case is stright forward, we only need to send the reply. For ARP reply, we need to cache the request and send IP packets that were waiting on this ARP reply. In addition, we also  need to remove corresponding ARP request from queue.

For IP case, the main logic contains in the `handle_ip` function. This function does basic check to make sure the request packet is valid. I also put logic to find the interface in our router that connects to the source of the ip request, as it will be used in multiple places later. A loop has been inplemented to check if the request is targeting one of our interface. If yes, we send different types of reply by calling the `sr_send_icmp_t3` and `sr_send_icmp_t0` helper functions. If the target is not us, we will forward the packet to the next hop.  Before that, we also reduce and check the ttl. If we have cached the MAC of the next hop, we forward the request directly. If not, we put the request  into the queue and call the `handle_arpreq`.


### sr_router.h
In this file, I defined the helper functions (`sr_send_icmp_t3`, `longest_prefix_match`) that need to be called elsewhere. 

### sr_arpcache
In this file, I implemented the 2 functions which are `sr_arpcache_sweepreqs` and `handle_arpreq`. 

`sr_arpcache_sweepreqs`: This function iterate the queued request, and call the `handle_arpreq` to process them.

`handle_arpreq`: We first check if the request has been sent less than 1 second before. Then, we check how many times the request has been sent. If it has been sent for 5 times, we will send an ICMP message to the original sender. 
If the request does not satisfy the above case, we will send a new ARP request, and count how many times we sent it. 

## Challenges
The most challenging part of this assignment is to figure out how to create different requests, and what is the value of different fields. For example, I set the ICMP message to a wrong type and it caused the ICMP request failed. We have no way to easily figure out what is happening, as the only feedback we have is the request cannot reach the mininet client.
