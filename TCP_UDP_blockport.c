#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
static struct nf_hook_ops *nfho = NULL;
char sipaddr[16];
char target[16]="192.168.232.2";
struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
u16 tcp_dest_port;
u16 udp_dest_port;
static unsigned int hfunc(unsigned int hooknum,
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
	{

    sock_buff = (struct sk_buff *) skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
	udp_header = (struct udphdr *)skb_transport_header(sock_buff);
	snprintf(sipaddr, 16, "%pI4", &ip_header->saddr);
	tcp_dest_port=ntohs(tcp_header->dest);
	udp_dest_port=ntohs(udp_header->dest);	
        if(!sock_buff) 
	{ 
		return NF_ACCEPT;
	}
	if (ip_header->protocol == 6) {	
		if (tcp_dest_port==4444)
		{	   
			printk("Drop TCP packet port 4444");
                	return NF_DROP;
		}
	}
	if (ip_header->protocol == 17) {
		if (udp_dest_port==5555)
		{	
			printk("Drop UDP packet port 5555");
                	return NF_DROP;
		}
	}
	if (ip_header->protocol == 1) 
	{
		if (strcmp(target,sipaddr)==0)
			{
				printk("Block ICMP packet from client 1");
				return NF_DROP;
			}
		
	}
	return NF_ACCEPT;
	
}

static int __init rule_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	
	nfho->hook 	= (nf_hookfn*)hfunc;	
	nfho->hooknum 	= NF_INET_FORWARD;		
	nfho->pf 	= PF_INET;			
	nfho->priority 	= NF_IP_PRI_FIRST;		
	nf_register_net_hook(&init_net, nfho);
return 0;
}

static void __exit rule_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(rule_init);
module_exit(rule_exit);
