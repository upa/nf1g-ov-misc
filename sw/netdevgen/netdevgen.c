/*
 * netdev gen
 */


#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/net_namespace.h>


MODULE_AUTHOR ("upa@haeena.net");
MODULE_DESCRIPTION ("netdevgen");
MODULE_LICENSE ("GPL");

static bool ndg_thread_running;
static struct task_struct * ndg_tsk;

static int pktlen = 50;
//static __be32 srcip = 0x01010A0A; /* 10.10.1.1 */
//static __be32 dstip = 0x02010A0A; /* 10.10.1.2 */

static __be32 srcip = 0x010010AC; /* 172.16.0.1 */
static __be32 dstip = 0x020010AC; /* 172.16.0.2 */


static int
netdevgen_thread (void * arg)
{
	struct sk_buff * skb, * pskb;
	struct iphdr * ip;
	struct flowi4 fl4;
	struct rtable * rt;
	struct net * net = get_net_ns_by_pid (1);

	ndg_thread_running = true;

	if (!net) {
		printk ("failed to get netns by pid 1\n");
		goto err_out;
	}

	memset (&fl4, 0, sizeof (fl4));
	fl4.saddr = srcip;
	fl4.daddr = dstip;

	rt = ip_route_output_key (net, &fl4);
	if (IS_ERR (rt)) {
		printk ("no route to %pI4\n", &dstip);
		goto err_out;
	}

	/* alloc and build skb */
	skb = alloc_skb_fclone (2048, GFP_KERNEL);
	skb->protocol = htons (ETH_P_IP);
	skb_put (skb, pktlen);
	skb_set_network_header (skb, 0);

	ip = (struct iphdr *) skb_network_header (skb);
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = pktlen;
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 12;
	ip->protocol = IPPROTO_UDP;	
	ip->check = 0;
	ip->saddr = srcip;
	ip->daddr = dstip;

	skb_dst_drop (skb);
	skb_dst_set (skb, &rt->dst);

	while (!kthread_should_stop ()) {
		pskb = skb_clone (skb, GFP_KERNEL);
		if (!pskb) {
			printk (KERN_ERR "failed to clone skb\n");
			continue;
		}

		ip_local_out (pskb);
	}

	ndg_thread_running = false;

	while (!skb_cloned(skb))
		kfree_skb (skb);

	return 0;

err_out:
	ndg_thread_running = false;
	return -1;
}

static int __init
netdevgen_init (void)
{
	printk (KERN_INFO "start thread\n");

	ndg_tsk = kthread_run (netdevgen_thread, NULL, "netdevgen");

	if (IS_ERR (ndg_tsk)) {
		printk (KERN_ERR "failed to run netdevgen thread\n");
		return -1;
	}

	printk (KERN_INFO "netdevgen loaded\n");
		
	return 0;
}

static void __exit
netdevgen_exit (void)
{
	if (ndg_tsk && ndg_thread_running)
		kthread_stop (ndg_tsk);
	else {
		printk (KERN_INFO "thread is already done\n");
	}

	printk (KERN_INFO "netdevgen unloaded\n");

	return;
}

module_init (netdevgen_init);
module_exit (netdevgen_exit);
