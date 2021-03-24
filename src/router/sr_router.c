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


#define DEFAULT_TTL 255
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

    // New packet
    uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*)new_packet;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    // Ethernet header
    ethernet_header->ether_type = htons(ethertype_ip);
    memcpy(ethernet_header->ether_dhost, original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);

    // ip header
    memcpy(ip_header, original_ip_header, sizeof(sr_ip_hdr_t));
    ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    ip_header->ip_p = ip_protocol_icmp;
    ip_header->ip_dst = original_ip_header->ip_src;
    ip_header->ip_src = interface->ip;
    ip_header->ip_ttl = DEFAULT_TTL;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    // ICMP header
    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;

    // ipHeader->ip_off = IP_DF;
    memcpy(icmp_header->data, original_ip_header, ICMP_DATA_SIZE);
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));

    sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), interface->name);
    free(new_packet);
}

void sr_send_icmp_t0(
        struct sr_instance *sr,
        uint8_t * packet,
        uint8_t type,
        uint8_t code,
        struct sr_if *interface,
        unsigned int len
        )
{
    sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    // Update the thernet header
    memcpy(ethernet_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);

    // Ip
    ip_header->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    ip_header->ip_p = ip_protocol_icmp;
    
    uint32_t temp = ip_header->ip_dst;
    ip_header->ip_dst = ip_header->ip_src;
    ip_header->ip_src = temp;
    ip_header->ip_ttl = DEFAULT_TTL;
    ip_header->ip_sum = 0;
    ip_header->ip_id = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    // ICMP
    icmp_header->icmp_type = 0x00;
    icmp_header->icmp_code = 0x00;
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));

    sr_send_packet(sr, packet, len, interface->name);
}

struct sr_if* longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip){
    struct sr_rt *curr_match = 0;
    struct sr_rt *entry = sr->routing_table;
    unsigned long longest_mask = 0;
    
    while(entry){
        if (((entry->mask.s_addr & entry->dest.s_addr) == (dest_ip & entry->mask.s_addr))) {
            if (longest_mask <= entry->mask.s_addr) {
                curr_match = entry;
                longest_mask = entry->mask.s_addr;
            }
        }
        entry = entry->next;
    }
    if(curr_match == 0){
        return NULL;
    }
    return sr_get_interface(sr, curr_match->interface);
}

void handle_arp(struct sr_instance* sr,
                uint8_t * packet/* lent */,
                unsigned int len,
                char* interface/* lent */)
{
    if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t))) {
      fprintf(stderr, "Too small. Drop it! \n");
      return;
    }
    
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*) packet;
    
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    
    struct sr_if* receiving_interface = sr_get_interface(sr, interface);

    // Chcek the request is for me
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
    
    if(ARP_OPcode == arp_op_request) {
        
        uint8_t *request_pointer = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
        sr_ethernet_hdr_t* ethernet_header_new = (sr_ethernet_hdr_t*)request_pointer;
        sr_arp_hdr_t*       arp_header_new = (sr_arp_hdr_t*)(request_pointer+sizeof(sr_ethernet_hdr_t));
        
        ethernet_header_new->ether_type = ethertype_arp;
        memcpy(ethernet_header_new->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethernet_header_new->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);
        
        arp_header_new->ar_hrd = arp_hrd_ethernet;
        arp_header_new->ar_pro = ethertype_ip;
        arp_header_new->ar_hln = arp_header->ar_hln;
        arp_header_new->ar_pln = arp_header->ar_pln;
        arp_header_new->ar_op = htons(arp_op_reply);
        memcpy(arp_header_new->ar_sha, receiving_interface->addr, ETHER_ADDR_LEN);
        arp_header_new->ar_sip = receiving_interface->ip;
        memcpy(arp_header_new->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
        arp_header_new->ar_tip = arp_header->ar_sip;

        sr_send_packet(sr, request_pointer, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), receiving_interface->name);
        fprintf(stderr, "ARP sent.\n");
        free(request_pointer);
    }

    else if(ARP_OPcode == arp_op_reply) {
        
        // Insert it to cache, check if there is pending request
        struct sr_arpreq *ar_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
        
        // If there is no pending request on it, return
        if(ar_req == NULL){
            return;
        }
      
        struct sr_packet* pending_packet = ar_req->packets;
        while(pending_packet) {
            
            uint8_t* packet_pointer = pending_packet->buf;
            sr_ethernet_hdr_t* e_hdr_new = (sr_ethernet_hdr_t*)packet_pointer;
            sr_ip_hdr_t*    ip_hdr_new = (sr_ip_hdr_t*)(packet_pointer+sizeof(sr_ethernet_hdr_t));

            memcpy(e_hdr_new->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
            memcpy(e_hdr_new->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);

            ip_hdr_new->ip_sum = 0;
            ip_hdr_new->ip_sum = cksum(ip_hdr_new, sizeof(sr_ip_hdr_t));

            sr_send_packet(sr, packet_pointer, pending_packet->len, receiving_interface->name);

            pending_packet = pending_packet->next;
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
    
    if(len < sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "IP packet: too small. Drop it! \n");
      return;
    }
    
    uint16_t old_check_sum = ip_header->ip_sum;
    
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    
    
    if(old_check_sum != ip_header->ip_sum){
        fprintf(stderr, "Invalid checksum. Drop it! \n");
        return;
    }
    
    // Find the interface that connect to the sourse of the request
    struct sr_if* reply_interface = longest_prefix_match(sr, ip_header->ip_src);
    
    // Drop the request if we cannot event connect to the requset source, which should not happen
    if(reply_interface == NULL)
    {
      fprintf(stderr, "We cannot connect to the source \n");
      return;
    }
    
    struct sr_if* if_i = sr->if_list;
    
    // Find if the request is targesting one of our interface
    while(if_i)
    {
        // Skip if it is not matched
        if(ip_header->ip_dst != if_i->ip)
        {
            if_i = if_i->next;
            continue;
        }
        // For us, but it is not ICMP packet
        if(ip_header->ip_p!=ip_protocol_icmp){
            //Send ICMP port unreachable (type 3, code 3)
            fprintf(stderr, "Not ICMP \n");
            sr_send_icmp_t3(sr, packet, 0x03, 0x03, reply_interface);
            return;
        }
        
        sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        // We can only handle icmp 8
        if(icmp_header->icmp_type != 0x08)
        {
            fprintf(stderr, "Not ICMP 8. Drop it! \n");
            return;
        }
        else {
            sr_send_icmp_t0(sr, packet, 0x00, 0x00, reply_interface,len);
            return;
        }
    }
    
    // Handle the case that the request is not for us
    if(ip_header->ip_ttl <= 1)
    {
      // TTL expired
      sr_send_icmp_t3(sr, packet, 0x0b, 0x00, reply_interface);
      return;
    }
    
    ip_header->ip_ttl--;
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    
    struct sr_if *matched_interface = longest_prefix_match(sr, ip_header->ip_dst);
    
    // No matched entry in routing table
    if(matched_interface == NULL ){
        fprintf(stderr, "Not in route table \n");
        sr_send_icmp_t3(sr, packet, 0x03, 0x00, current_interface);
        return;
    }
    
    struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
    
    // If correspond MAC is in cache
    if(entry != NULL){
        memcpy(ethernet_header->ether_shost, matched_interface->addr, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                
        sr_send_packet(sr, packet, len, matched_interface->name);
        return;
    }
    
    // Put it into the Queue
    struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet, len, matched_interface->name);
    //  Send the arp request
    handle_arpreq(sr, arpreq);
    return;
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
        
        fprintf(stderr, "ARP \n");
        handle_arp(sr, packet, len, interface);
    }
    else if(ethertype(packet) == ethertype_ip) {
        fprintf(stderr, "IP \n");
        handle_ip(sr, packet, len, interface);
    }

} /* end sr_handlepacket */


/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
