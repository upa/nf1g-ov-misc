/*
 * netdev gen
 */


#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <asm/atomic.h>
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


#define PROC_NAME "driver/netdevgen"

static atomic_t start;



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

	memset (&fl4, 0, sizeof (fl4));
	fl4.saddr = srcip;
	fl4.daddr = dstip;
	rt = ip_route_output_key (net, &fl4);
	if (IS_ERR (rt)) {
		printk ("no route to %pI4\n", &dstip);
		goto err_out;
	}
	skb_dst_drop (skb);
	skb_dst_set (skb, &rt->dst);


	while (!kthread_should_stop ()) {

		if (atomic_read (&start) == 0) {
			break;
		}

		pskb = skb_clone (skb, GFP_KERNEL);
		if (!pskb) {
			printk (KERN_ERR "failed to clone skb\n");
			continue;
		}

		ip_local_out (pskb);
	}

err_out:
	//kfree_skb (skb);
	ndg_thread_running = false;

	printk (KERN_INFO "netdevgen thread finished\n");

	return 0;
}


static void
start_stop (void)
{
	if (atomic_read (&start)) {
		printk ("netdevgen: start -> stop\n");
		atomic_set (&start, 0);
	} else {
		printk ("netdevgen: stop -> start\n");
		atomic_set (&start, 1);
	}

	if (atomic_read (&start)) {
		printk (KERN_INFO "restart thread\n");
		ndg_tsk = kthread_run (netdevgen_thread, NULL, "netdevgen");
	}
}

static ssize_t
proc_read(struct file *fp, char *buf, size_t size, loff_t *off)
{
	printk (KERN_INFO "proc read\n");

	//copy_to_user (buf, "stop!\n", size);
	start_stop ();
	return size;
}

static ssize_t
proc_write(struct file *fp, const char *buf, size_t size, loff_t *off)
{
        printk("proc write\n");
	start_stop ();
        return size;
}

static const struct file_operations proc_file_fops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write,
};

static int __init
netdevgen_init (void)
{
	struct proc_dir_entry * ent;

        ent = proc_create(PROC_NAME, S_IRUGO | S_IWUGO | S_IXUGO,
			  NULL, &proc_file_fops);
        if (ent == NULL)
                return -ENOMEM;


	atomic_set (&start, 0);

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
	remove_proc_entry (PROC_NAME, NULL);

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
