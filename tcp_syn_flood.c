
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
static struct nf_hook_ops *nfho = NULL;
char sipaddr[16];
struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
char list[100][1];
int list_num = 0;
int check_num = 0;
unsigned long IP_check [100];
int numNull=0;
int numSyn=0;
int numFin=0;
int numAck=0;


static unsigned int hfunc(unsigned int hooknum,
                  struct sk_buff **skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
	{

    sock_buff = (struct sk_buff *) skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	snprintf(sipaddr, 16, "%pI4", &ip_header->saddr);
	unsigned long ip_num=ip_header->saddr;
	tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
        if(!sock_buff) 
	{ 
		return NF_ACCEPT;
	}
	int i;
	for(i=0;i<=list_num;i++)
	{
		if( !strcmp(sipaddr ,list[i]))
		{
			printk("Block IP %s in black list",&sipaddr);
			return NF_DROP;
		}
	}
	if (ip_header->protocol == 6) 
	{	
		
		if (tcp_header->syn == 1
                    && tcp_header->ack == 0
                    && tcp_header->urg == 0
                    && tcp_header->rst == 0
                    && tcp_header->fin == 0
                    && tcp_header->psh == 0)
		    {
			numSyn++;
			if (numSyn>50)
			{
                        	printk("SYN Flood Attack!");
				list_num++;
				strncpy(list[list_num],sipaddr,16);
				printk("Add %s to blacklist",&sipaddr);
				numSyn=0;
				return NF_DROP;
			}
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