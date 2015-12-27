//For any packets that comes, check the ip header and the protocol field. If the protocol is 17(UDP), log it, and drop it.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;
struct udphdr *udp_header;
struct iphdr *ip_header;

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
		       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  /* //printk("Hello kernel world!");
  sock_buff = skb; //get the socket
  ip_header = (struct iphdr *)skb_network_header(sock_buff);//grab the network header using accessor
  if(!sock_buff) return NF_ACCEPT; // accept the package. it is not a UDP packet(and we couldn't read socket...)
  if(ip_header->protocol == 17) // if we have a UDP packet
    {
      udp_header = (struct udphdr *)skb_transport_header(sock_buff);//read the udp header
      printk("got UDP header\n");
      return NF_DROP;//drop the package
      }*/
  return NF_QUEUE; // the socket was read, but the package was not UDP, accept it

}

  
int init_module(void)
{
  nfho.hook = hook_func;
  nfho.hooknum = 1;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho);
  return 0;
}

void cleanup_module(void)
{
  nf_unregister_hook(&nfho);
}
