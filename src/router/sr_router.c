/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


#define DEFAULT_TTL 64
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_send_icmp_t3(
        struct sr_instance *sr,
        uint8_t * packet,
        uint8_t type,
        uint8_t code,
        struct sr_if *interface)
{
    sr_ethernet_hdr_t *original_ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
    uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)new_packet;
    sr_ip_hdr_t *ipHeader = (sr_ip_hdr_t *) new_packet + sizeof(sr_ethernet_hdr_t);
    sr_icmp_t3_hdr_t *icmpHeader = (sr_icmp_t3_hdr_t *) new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    
    // Ethernet header
    ethernet_hdr->ether_type = original_ethernet_header->ether_type;
    memcpy(ethernet_hdr->ether_dhost, original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    // ip header
    ipHeader->ip_tos = 0;
    ipHeader->ip_id = original_ip_header->ip_id;
    ipHeader->ip_off = htons(IP_DF);
    ipHeader->ip_p = ip_protocol_icmp;
    ipHeader->ip_dst = original_ip_header->ip_src;
    ipHeader->ip_src = interface->ip;
    ipHeader->ip_ttl = DEFAULT_TTL;
    ipHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // ICMP header
    icmpHeader->icmp_type = type;
    icmpHeader->icmp_code = code;
    icmpHeader->icmp_sum = 0;
    memcpy((uint8_t *) icmpHeader + sizeof(sr_icmp_t3_hdr_t) - ICMP_DATA_SIZE, packet, ICMP_DATA_SIZE);
    icmpHeader->icmp_sum = 0;
    icmpHeader->icmp_sum = cksum(icmpHeader, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface->name);
    fprintf(stderr, "ICMP Packet sent.\n");
    /*clean up*/
    free(new_packet);
}

struct sr_if* longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip){
    struct sr_rt *curr_match = 0;
    struct sr_rt *entry = sr->routing_table;
    unsigned long longest_mask = 0;
    
    while(entry){
        /*ip matches the entry address*/
        if (((entry->mask.s_addr & entry->dest.s_addr) == (dest_ip & entry->mask.s_addr))) {
            /*the mask is longer than the currently matched one*/
            if (longest_mask <= entry->mask.s_addr) {
                curr_match = entry;
                longest_mask = entry->mask.s_addr;
            }
        }
        entry = entry->next;
    }
    
    return sr_get_interface(sr, curr_match->interface);
}

void handle_ip_forwarding(struct sr_instance* sr,
                          uint8_t * packet/* lent */,
                          unsigned int len,
                          char* interface/* lent */)
{
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* current_interface = sr_get_interface(sr, interface);
    
    struct sr_if *matched_interface = longest_prefix_match(sr, ip_header->ip_dst);
    
    // No matched entry in routing table
    if(matched_interface ==NULL ){
        sr_send_icmp_t3(sr, packet, 0x03, 0x00, current_interface);
        return;
    }
    
    struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
    
    // If correspond MAC is in cache
    if(entry != NULL){
        memcpy(ethernet_header->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);

        /* since we had decrement the ttl in handle IP, we have to recompute the check sum */

        /* forward the packet to the next hop */
        sr_send_packet(sr, packet, len, matched_interface->name);
        free(entry);
        return;
    }
    
    /* we need to put the packet on the queue */
    struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, matched_interface->name);
    /* call handle arp request method */
    handle_arpreq(sr, arpreq);
    return;
    
}

void handle_arp(struct sr_instance* sr,
                uint8_t * packet/* lent */,
                unsigned int len,
                char* interface/* lent */)
{
    if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t))) {
      fprintf(stderr, "Dropping ARP packet, too small \n");
      return;
    }
    
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) packet;
    
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
    struct sr_if* receiving_interface = sr_get_interface(sr, interface);

    // Chcek the request is for me Leon
    struct sr_if *if_ptr, *if_i;
    for(if_i = sr_get_interface(sr, interface); if_i; if_i = if_i->next) {
      // Find the interface in router match the arp request
      if(if_i->ip == arp_header->ar_tip) {
        if_ptr = if_i;
        break;
      }
    }

    if(!if_ptr) {
      fprintf(stderr, "ARP packet not for me.\n");
      return;
    }

    uint16_t ARP_OPcode = ntohs(arp_header->ar_op);
    
    /* Handle ARP Request */
    if(ARP_OPcode == arp_op_request) {
        
        uint8_t *request_pointer = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
        /*create the ethernet header and arp header*/
        sr_ethernet_hdr_t* ethernet_hdr_new = (sr_ethernet_hdr_t*)request_pointer;
        sr_arp_hdr_t*       arp_hdr_new = (sr_arp_hdr_t*)(request_pointer+sizeof(sr_ethernet_hdr_t));
        
        /*copy all the ethernet header to the new packet ethernet header
         * ether_type, dhost, shost
         */
        ethernet_hdr_new->ether_type = ethernet_header->ether_type;
        memcpy(ethernet_hdr_new->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet_hdr_new->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);

        /*change the arp header
         * sender ip becomes current interface's ip
         * sender mac address becomes current interface's mac address
         * destination ip becomes the previous sender ip
         * destination mac address becomes the previous sender mac address
         * the rest stay the same
         */
        arp_hdr_new->ar_hrd = arp_header->ar_hrd;
        arp_hdr_new->ar_pro = arp_header->ar_pro;
        arp_hdr_new->ar_hln = arp_header->ar_hln;
        arp_hdr_new->ar_pln = arp_header->ar_pln;
        arp_hdr_new->ar_op = htons(arp_op_reply);
        memcpy(arp_hdr_new->ar_sha, receiving_interface->addr, ETHER_ADDR_LEN);
        arp_hdr_new->ar_sip = receiving_interface->ip;
        memcpy(arp_hdr_new->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        arp_hdr_new->ar_tip = arp_header->ar_sip;

        /*reply the arp request packet*/
        sr_send_packet(sr, request_pointer, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), receiving_interface->name);
        fprintf(stderr, "ARP sent.\n");
    }

    /* Handle ARP Reply */
    else if(ARP_OPcode == arp_op_reply) {
        
        /*insert the entry into APR cache using method in sr_arpache*/
        struct sr_arpreq *ar_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
        
        // If there is no pending request on it, return
        if(ar_req == NULL){
            return;
        }
      
        /* Send outstanding packets */
        struct sr_packet* tmp_pkt = ar_req->packets;
        while(tmp_pkt) {
            
            /*get the raw ethernet frame*/
            uint8_t* queued_p = tmp_pkt->buf;
            /*create the ethernet header and arp header*/
            sr_ethernet_hdr_t* e_hdr_new = (sr_ethernet_hdr_t*)queued_p;
            sr_ip_hdr_t*    ip_hdr_new = (sr_ip_hdr_t*)(queued_p+sizeof(sr_ethernet_hdr_t));

            /*give the value to ethernet destination mac address using the reply ARP's sourse mac address
             *since the ARP is a reply, the source mac address of that ARP will be the destination where
             *we want to send the outstanding packets
             */
            memcpy(e_hdr_new->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
            memcpy(e_hdr_new->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);

            /*recompute the checksum of the entire packet*/
            ip_hdr_new->ip_sum = 0;
            ip_hdr_new->ip_sum = cksum(ip_hdr_new, sizeof(sr_ip_hdr_t));

            /*send the outstanding packet*/
            sr_send_packet(sr, queued_p, tmp_pkt->len, receiving_interface->name);
            fprintf(stderr, "Outstanding packet sent.\n");

            /*move the pointer to next entry in the queue*/
            tmp_pkt = tmp_pkt->next;
        }

      sr_arpreq_destroy(&(sr->cache), ar_req);
    }
}

void handle_ip(struct sr_instance* sr,
                uint8_t * packet/* lent */,
                unsigned int len,
               char* interface/* lent */){
    
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) packet;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* current_interface = sr_get_interface(sr, interface);
    
    /* Check for valid len */
    if(len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "Dropping IP packet: too small.\n");
      return;
    }
    
    uint16_t old_check_sum = ip_header->ip_sum;
    
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    
    
    if(old_check_sum != ip_header->ip_sum){
        fprintf(stderr, "Dropping IP packet: Invalid checksum \n");
        return;
    }
    
    /*get the interface list*/
    struct sr_if* if_i = sr->if_list;
    
    /*loop through all interface and check if there is a match, ie. "it is for me" */
    while(if_i)
    {
        /*if the request is not for this interface*/
        if(ip_header->ip_dst != if_i->ip)
        {
            if_i = if_i->next;
            continue;
        }
        // If it is not ICMP packet
        if(ip_header->ip_p!=ip_protocol_icmp){
            //Send ICMP port unreachable (type 3, code 3)
            sr_send_icmp_t3(sr, packet, 0x03, 0x03, if_i);
            return;
        }
        
        sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        /* Drop if not ICMP 8*/
        if(icmp_header->icmp_type != 0x08)
        {
            fprintf(stderr, "Dropping IP packet: Not ICMP 8 \n");
            return;
        }
        else {
            sr_send_icmp_t3(sr, packet, 0x00, 0x00, if_i);
            return;
        }
    }
    
    // Handle the case that the request is not for us
    if(ip_header->ip_ttl <= 1)
    {
      // TTL expired
      sr_send_icmp_t3(sr, packet, 0x0b, 0x00, current_interface);
      return;
    }
    
    ip_header->ip_ttl--;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    
    handle_ip_forwarding(sr, packet, len, interface);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
    
  // Handle ARP packet
    if(ethertype(packet) == ethertype_arp) {
        // Check valid?
        handle_arp(sr, packet, len, interface);
    }
    else if(ethertype(packet) == ethertype_ip) {
        
        handle_ip(sr, packet, len, interface);
    }

} /* end sr_handlepacket */


/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
