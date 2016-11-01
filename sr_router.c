/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h> 

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

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

	/* Add initialization code here! */

} /* -- sr_init -- */


struct packetcaching *head = NULL;
static int requestcount;
struct arpcache *start = NULL;
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
	

	printf("\n*** -> Received packet of length %d \n", len);
	struct sr_ethernet_hdr *ethhdr = (struct sr_ethernet_hdr*)packet;

	if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP)
	{
		struct sr_arphdr *arphdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
		if (arphdr->ar_op == ntohs(ARP_REQUEST))
		{
			arpcaching(arphdr);
			sendarpreply(sr, packet, len, interface);
			return;
		}
		else if (arphdr->ar_op == ntohs(ARP_REPLY))
		{
			requestcount = --requestcount;
			arpcaching(arphdr);
			sendfromqueue(sr, arphdr->ar_sip);
			return;
		}
	}
	else if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP) 
	{
		struct ip *iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
		printf("Sender IP Address %s\n", inet_ntoa(iphdr->ip_src));
		printf("Receiver IP Address %s\n", inet_ntoa(iphdr->ip_dst));
		if(iphdr->ip_v!=4)
		{
			printf("verification of ip version failed\n");
			return;
		}
		if(iphdr->ip_sum)
		{
			uint16_t check = iphdr->ip_sum;
			iphdr->ip_sum = 0;
			iphdr->ip_sum = checksum((uint16_t*)iphdr, sizeof(struct ip));
			if(check == iphdr->ip_sum)
			{
				printf("Correct Checksum\n");
			}
		}
		struct sr_if* dest = sr->if_list;
		while (dest) 
		{
			if (dest->ip == iphdr->ip_dst.s_addr) 
			{
				if(iphdr->ip_p == IPPROTO_ICMP)
				{
					struct icmphdr* icmphdr = (struct icmphdr*)(packet + (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));
					struct in_addr temp;
					temp.s_addr = iphdr->ip_src.s_addr;
					iphdr->ip_src = iphdr->ip_dst;
					iphdr->ip_dst = temp;					
					icmphdr->type = 0;
					icmphdr->code = 0;
					icmphdr->checksum = 0;
					icmphdr->checksum = checksum((uint16_t*)icmphdr, 64);
					sendtogateway(sr, packet, len);
					return;
				}
				if (iphdr->ip_p == TCP || iphdr->ip_p == UDP) 
				{
					sendicmp(sr, packet, 3, 3);
					return;
				}
			}
			dest = dest->next;
		}
		if (iphdr->ip_ttl == 1) 
		{
			printf("TTL=0 Time expired in transit\n");
			sendicmp(sr, packet, 11, 0);
			return;
		}
		forwardippacket(sr, packet, len, interface);
		return;
	}
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sendarprequest
 *used to send request to the nexthops to find their mac address.
 *
 *---------------------------------------------------------------------*/
void sendarprequest(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t dstip) 
{
	struct ip *iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	if(iphdr->ip_p != UDP)
	{	
		requestcount = ++requestcount;
		if(requestcount > 5)
		{
			requestcount = 0;
			deletefromqueue();
			sendicmp(sr, packet, 3, 1);
			return;
		}
	}
	int len_new = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
	uint8_t* pkt =  malloc(len_new * sizeof(uint8_t));
	if(pkt != NULL)
	{
		memset(pkt, 0, len_new * sizeof(uint8_t));
		struct sr_ethernet_hdr* ethhdr = (struct sr_ethernet_hdr*)pkt;
		struct sr_arphdr* arphdr = (struct sr_arphdr*)(pkt + sizeof(struct sr_ethernet_hdr));
		struct sr_if* mac = sr->if_list;
	
		ethhdr->ether_type = ntohs(ETHERTYPE_ARP);
		arphdr->ar_hrd = ntohs(1);
		arphdr->ar_pro = ntohs(ETHERTYPE_IP);
		arphdr->ar_op = ntohs(ARP_REQUEST);
		arphdr->ar_hln = ETHER_ADDR_LEN;
		arphdr->ar_pln = 4;
		arphdr->ar_tip = dstip;
	
		int i;
		for(i = 0; i<ETHER_ADDR_LEN; i++) 
		{
			ethhdr->ether_dhost[i] = 255;
			arphdr->ar_tha[i] = 255;
		}
		while(mac)
		{
			if (strcmp(mac->name, interface) == 0)
			{
				for (i = 0; i<ETHER_ADDR_LEN; i++) 
				{
					arphdr->ar_sha[i] = mac->addr[i];
					ethhdr->ether_shost[i] = mac->addr[i];
				}
				break;
			}
			mac = mac->next;
		}
		arphdr->ar_sip = mac->ip;
		printf("ARP Request Sent \n");
		sr_send_packet(sr, pkt, len_new, mac->name);
		if(pkt!=NULL){
		free(pkt);}
	}
	else
	{
		printf("malloc failed in send arp request\n");
	}
}

/*---------------------------------------------------------------------
 * Method: sendarpreply
 *Used to send arp reply to the incoming arp requests.
 *---------------------------------------------------------------------*/
void sendarpreply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) 
{
	struct sr_ethernet_hdr *ethhdr = (struct sr_ethernet_hdr*)packet;
	struct sr_arphdr *arphdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_if *mac = sr_get_interface(sr, interface);

	ethhdr->ether_type = htons(ETHERTYPE_ARP); 
	memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, sizeof(ethhdr->ether_dhost));
	memcpy(arphdr->ar_tha, arphdr->ar_sha, sizeof(arphdr->ar_tha));
	
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) 
	{
		arphdr->ar_sha[i] = mac->addr[i];
		ethhdr->ether_shost[i] = mac->addr[i];
	}
	arphdr->ar_pro = htons(ETHERTYPE_IP);
	arphdr->ar_hrd = htons(ARPHDR_ETHER);
	arphdr->ar_hln = ETHER_ADDR_LEN;
	arphdr->ar_pln = 4;
	arphdr->ar_op = htons(ARP_REPLY);

	uint32_t temp;
	temp = arphdr->ar_sip;
	arphdr->ar_sip = arphdr->ar_tip;
	arphdr->ar_tip = temp;
	sr_send_packet(sr, packet, len, interface);
}

/*---------------------------------------------------------------------
 * Method: forwardippacket
 * forwards the incoming ip packet.
 *
 *---------------------------------------------------------------------*/
 void forwardippacket(struct sr_instance* sr, uint8_t *packet, int len, char* interface)
 {
 		struct ip *iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
 		if (iphdr)
 		{
 			struct sr_rt* rtentry = routingtablelookup(iphdr->ip_dst.s_addr, sr);
			if (rtentry != NULL) 
			{
				sendtoserver(sr, packet, len, rtentry->interface);
				return;
			}
			else 
			{
				sendtogateway(sr, packet, len);
				return;
			}
		}
 }
 
 /*---------------------------------------------------------------------
 * Method: sendtoserver
 *This method is used to route the packet to the server.
 *---------------------------------------------------------------------*/

void sendtoserver(struct sr_instance* sr, uint8_t* packet, int len, char* interface) 
{
	struct sr_ethernet_hdr* ethhdr = (struct sr_ethernet_hdr*)packet;
	struct ip *iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));

	if (checkcache(iphdr->ip_dst.s_addr) == 1) 
	{
		ethhdr->ether_type = htons(ETHERTYPE_IP);
		int i;
		if (iphdr->ip_p == IPPROTO_ICMP) 
		{
			struct icmphdr *icmphdr = (struct icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
			if (icmphdr->type == ECHO_REQUEST) 
			{
				icmphdr->checksum = 0;
				icmphdr->checksum = checksum((uint16_t*)icmphdr, 64);
			}
		}
		struct arpcache *temp = start;
		while (temp) {
			if (temp->ip == iphdr->ip_dst.s_addr)
			{
				for (i = 0; i < ETHER_ADDR_LEN; i++) 
				{
					ethhdr->ether_dhost[i] = temp->mac[i];
				}
				break;
			}
			temp = temp->next;
		}		
		struct sr_if* interf = sr->if_list;
		while (interf)
		{
			if (strcmp(interf->name, interface) == 0)
			{
				int j;
				for (j = 0; j < ETHER_ADDR_LEN; j++) 
				{
					ethhdr->ether_shost[j] = interf->addr[j];
				}
				break;
			}
			interf = interf->next;
		}
		iphdr->ip_ttl = iphdr->ip_ttl - 1;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t*)iphdr, sizeof(struct ip));
		sr_send_packet(sr, packet, len, interface);
	}
	else 
	{
		addtoqueue(packet, len);
		sendarprequest(sr, packet, len, interface, iphdr->ip_dst.s_addr);
		return;
	}
}

/*---------------------------------------------------------------------
 * Method: sendtogateway
 * Sends the packets back to lectura
 *
 *---------------------------------------------------------------------*/
void sendtogateway(struct sr_instance *sr, uint8_t *packet, int len) 
{
	struct sr_ethernet_hdr *ethhdr = (struct sr_ethernet_hdr *)packet;
	struct ip *iphdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	char* interface;
	struct sr_rt *routingtable = sr->routing_table;
	while (routingtable)
	{
		if ((routingtable->dest.s_addr) == 0)
		{
			interface = routingtable->interface;
			break;
		}
		routingtable = routingtable->next;
	}
	if (checkcache(routingtable->gw.s_addr) == 1)
	{
		struct arpcache *temp = start;
		int i;
		while (temp) 
		{
			if (temp->ip == routingtable->gw.s_addr)
			{
				for (i = 0; i < ETHER_ADDR_LEN; i++) 
				{
					ethhdr->ether_dhost[i] = temp->mac[i];
				}
				break;
			}
			temp = temp->next;
		}
		struct sr_if* mac = sr->if_list;
		while (mac)
		{
			if (strcmp(mac->name, interface) == 0)
			{
				for (i = 0; i < ETHER_ADDR_LEN; i++)
				{
					ethhdr->ether_shost[i] = mac->addr[i];
				}
				break;
			}
			mac = mac->next;
		}
		iphdr->ip_ttl = iphdr->ip_ttl - 1;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t*)iphdr, sizeof(struct ip));
		sr_send_packet(sr, packet, len, interface);
	}
	else
	{
		addtoqueue(packet, len);
		sendarprequest(sr, packet, len, interface, routingtable->gw.s_addr);
		return;
	}
}

/*---------------------------------------------------------------------
 * Method: sendicmp
 *used to send icmp host port unreachable and time exceeded messages.
 *
 *---------------------------------------------------------------------*/
void sendicmp(struct sr_instance * sr, uint8_t* packet, uint8_t type, uint8_t code)
{
	char* interface;
	int len = (sizeof(struct sr_ethernet_hdr)) + (2 * (sizeof(struct ip))) + (4 * (sizeof(struct icmphdr)));
	uint8_t* newpacket = malloc(len * sizeof(uint8_t));
	if (newpacket == NULL) 
	{
		printf("Memory allocation failed for sendicmp\n");
		exit(-1);
	}
	memset(newpacket, 0, 70 * sizeof(uint8_t));
	
	struct sr_ethernet_hdr* ethhdr = (struct sr_ethernet_hdr*)packet;
	struct ip* iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct sr_ethernet_hdr* newethhdr = (struct sr_ethernet_hdr*)newpacket;
	struct ip* newiphdr = (struct ip*)(newpacket + sizeof(struct sr_ethernet_hdr));
	struct icmphdr* newicmphdr = (struct icmphdr*)(newpacket + (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));
	uint8_t* newip2 = (newpacket + (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + (2 * (sizeof(struct icmphdr)))));

	memcpy(newethhdr->ether_dhost, ethhdr->ether_shost , sizeof(newethhdr->ether_dhost));
	memcpy(newethhdr->ether_shost, ethhdr->ether_dhost, sizeof(newethhdr->ether_shost));
	newethhdr->ether_type = htons(ETHERTYPE_IP);
	memcpy(newip2, iphdr, (sizeof(struct ip) + (2*(sizeof(struct icmphdr)))));

	newicmphdr->type = type;
	newicmphdr->code = code;
	newicmphdr->checksum = 0;
	newicmphdr->checksum = checksum((uint16_t*)newicmphdr, 36);
	uint8_t* p = (uint8_t*) newiphdr;
	*p = 0x45;
	newiphdr->ip_tos = 0;
	newiphdr->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
	newiphdr->ip_id = 0; 
	newiphdr->ip_off = htons(IP_DF);
	newiphdr->ip_ttl = 128;
	newiphdr->ip_p = IPPROTO_ICMP;

	struct sr_rt *routingtable = sr->routing_table;
	while (routingtable)
	{
		if ((routingtable->dest.s_addr) == 0)
		{
			interface = routingtable->interface;
			break;
		}
		routingtable = routingtable->next;
	}
	if(interface!=NULL)
	{
		struct sr_if* routerip = sr_get_interface(sr, interface);
		newiphdr->ip_src.s_addr = routerip->ip;
		newiphdr->ip_dst = iphdr->ip_src;
		newiphdr->ip_sum = 0;
		newiphdr->ip_sum = checksum((uint16_t*)newiphdr, sizeof(struct ip));
		sr_send_packet(sr, newpacket, len, interface);
		if(newpacket!=NULL)
		{
			free(newpacket);
		}
	}
}

/*---------------------------------------------------------------------
 * Method: routingtablelookup
 *Used to find the ip address and interface of the destination from rt
 *
 *---------------------------------------------------------------------*/

struct sr_rt* routingtablelookup(uint32_t dest, struct sr_instance* sr) {
	struct sr_rt *routingtable = sr->routing_table;
	while (routingtable)
	{
		if ((routingtable->dest).s_addr != 0)
		{
			uint32_t destmasked = dest & ((routingtable->mask).s_addr);
			uint32_t tablemasked = ((routingtable->dest).s_addr) & ((routingtable->mask).s_addr);

			if (destmasked == tablemasked)
			{
				return routingtable;
			}
		}
		routingtable = routingtable->next;
	}
	return NULL;
}

/*---------------------------------------------------------------------
 * Method: arpcaching
 *Caches the arp request and response.
 *---------------------------------------------------------------------*/
void arpcaching(struct sr_arphdr* arphdr) 
{
	if (checkcache(arphdr->ar_sip) == 1)
	{
		printf("Mac Address Exists\n");
	}
	else
	{
		struct arpcache* temp = (struct arpcache*)malloc(sizeof(struct arpcache));
		if(temp!=NULL)
		{
			int i;
			temp->ip = arphdr->ar_sip;
			for (i = 0; i < ETHER_ADDR_LEN; i++)
			{
				temp->mac[i] = arphdr->ar_sha[i];
			}
			temp->next = start;
			start = temp;		
		}
		else
		{
			printf("malloc in arpcaching failed\n");
			exit(-1);
		}
	}
}

/*---------------------------------------------------------------------
 * Method: checkcache
 * Used to check whether there is a entry in cache.
 *---------------------------------------------------------------------*/
int checkcache(uint32_t ipAddr)
{	
	struct arpcache *temp = start;
	while (temp) {
		if (temp->ip == ipAddr)
		{
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

/*---------------------------------------------------------------------
 * Method: removefromcache
 *clear the arp cache
 *---------------------------------------------------------------------*/
/*void removefromcache() 
{
	struct arpcache *temp = start;
	while (temp)
	{
		struct arpcache *nxt = temp->next;
		free(temp);
		temp = nxt;
	}
}
*/
 /*---------------------------------------------------------------------
 * Method: addtoqueue
 * Adds the packet, its instance and length of the packet in queue.
 *
 *---------------------------------------------------------------------*/
void addtoqueue(uint8_t* pkt, int length) 
{
		struct packetcaching *temppacket = (struct packetcaching *)malloc(sizeof(struct packetcaching));
		uint8_t* pkt1 = malloc(length *sizeof(uint8_t));
		memcpy(pkt1, pkt, length);
		struct ip* iphdr = (struct ip*)(pkt + sizeof(struct sr_ethernet_hdr));
		if(temppacket == NULL)
		{
			printf("Memory allocation failed\n");
			exit(-1);
		}
		else
		{
			temppacket->validator = 1;
			temppacket->packet = pkt1;
			temppacket->len = length;
			temppacket->ip = iphdr->ip_dst.s_addr;
			temppacket->next = head;
			head = temppacket;
		}
		printf("IP packets queued\n");
}

/*---------------------------------------------------------------------
 * Method:deletefromqueue
 *removes the ip packets from queue
 *
 *---------------------------------------------------------------------*/
void deletefromqueue() 
{
	struct packetcaching *temp = head;
	if (temp == NULL)
	{
		return;
	}
	else
	{
		head = NULL;
	}
}

/*---------------------------------------------------------------------
 * Method: sendfromqueue
 * Sends the stored packets in the queue to the server or back.
 *
 *---------------------------------------------------------------------*/
void sendfromqueue(struct sr_instance* sr, uint32_t ipaddr)
{
	struct packetcaching* cached = head;
	if(cached == NULL)
	{
		printf("Queue Empty\n");
		exit(-1);
	}
	else
	{
		while (cached != NULL) 
		{
			if(cached->packet != NULL)
			{
				if (cached->validator == 1)
				{
					struct sr_rt* rtentry = routingtablelookup(cached->ip, sr);
					if (rtentry != NULL)
					{	
						sendtoserver(sr, cached->packet, cached->len, rtentry->interface);
						cached->validator = 0;
					}
					else
					{
						sendtogateway(sr, cached->packet, cached->len);
						cached->validator = 0;
					}
				}
			}
			cached = cached->next;
		}
	}
}

/*---------------------------------------------------------------------
 * Method: checksum
 * Computes checksum for ip and icmp
 *---------------------------------------------------------------------*/

uint16_t checksum(uint16_t* ip, int len)
{
	register uint32_t final = 0;
	while (len > 1) 
	{
		final += *ip++;
		len -= 2;
	}
	if (len > 0)
	{
		final += *((uint8_t*)ip);
	}
	while (final >> 16)
	{
		final = (final & 0xffff) + (final >> 16);
	}
	return (~final);
}
