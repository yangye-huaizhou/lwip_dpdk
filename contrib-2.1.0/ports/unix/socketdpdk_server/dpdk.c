#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/prctl.h>


#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include "dpdk.h"

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define NB_MBUF   8192

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

struct arg_pass {
	int coreid;
	void * args;
};

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_eth_dev_tx_buffer *l2fwd_tx_buffer;

/* ethernet addresses of ports */
static struct ether_addr l2fwd_port_eth_addr;

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics;

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;


//dpdk receive function, receive from mbuf and call tcpip_input to send to protocol stack
static void dpdk_input(struct rte_mbuf* m, struct netif* netif) {
	
	struct pbuf *p;
	uint16_t len;
	len = rte_pktmbuf_pkt_len(m);
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);

	if (p != NULL) {
		/*assuming 2048 bytes is enough for independent data packets*/
		//p->payload = rte_pktmbuf_mtod(m, void *);	
		pbuf_take(p, rte_pktmbuf_mtod(m, void *), len);
		if(netif->input(p, netif) != ERR_OK) {
			LWIP_DEBUGF(NETIF_DEBUG, ("dpdk_input: input error\n"));
			pbuf_free(p);
		}
	    rte_pktmbuf_free(m);
	}
	else {
		//pbuf_free(p); /*memp uses an array with varying size interval inside the array to allocate memory (this array is in heap), seems to just reset the index so that the array can be written over*/
		rte_pktmbuf_free(m); 
		LWIP_DEBUGF(NETIF_DEBUG, ("dpdk_input: packet drop, pbuf allocation failed.\n")); 
		//printf("Packet Dropped\n");
	}

}

static err_t dpdk_output(struct netif *netif, struct pbuf *p) {
	LWIP_UNUSED_ARG(netif);

	struct pbuf *q;

	struct rte_mbuf *m;
	int sent = 0;
	m=rte_pktmbuf_alloc(l2fwd_pktmbuf_pool);

	if (p->tot_len > rte_pktmbuf_tailroom(m)) {
       perror("tapif: packet too large");
       return ERR_IF;
  	}

	u64_t offset=0;
	  //assuming only one packet in pbuf *p, if there is something wrong, change here.
	for(q = p; q != NULL; q = q->next) {
	    rte_memcpy(rte_pktmbuf_mtod_offset(m, void *,offset),
		   	(void *)q->payload,q->len);
      	m->pkt_len+=q->len;
      	m->data_len+=q->len;
      	offset+=q->len;
    }
      
	/* signal that packet should be sent(); */
	sent = rte_eth_tx_buffer(0, 0, l2fwd_tx_buffer, m);
    if (sent)
		port_statistics.tx += sent;

//	pbuf_free(p);
	return ERR_OK;
}

static void dpdk_rx_thread(void *arg) {
	prctl(PR_SET_NAME,"dpdk rx thread");
	//unsigned lcore_id = rte_lcore_id();
	RTE_LOG(INFO, L2FWD, "dpdk_rx_thread entering main loop\n");

	unsigned i, nb_rx;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct netif* netif = (struct netif *) arg;

	while (1) {
		nb_rx = rte_eth_rx_burst(0, 0,
					pkts_burst, MAX_PKT_BURST);
		port_statistics.rx += nb_rx;

		//port_statistics[portid].rx += nb_rx;

		for (i = 0; i < nb_rx; i++) {
			dpdk_input(pkts_burst[i], netif); 
		}
	}
	

}

static void dpdk_tx_thread(void *arg) {
	LWIP_UNUSED_ARG(arg);
	prctl(PR_SET_NAME,"dpdk tx thread");
	//unsigned lcore_id = rte_lcore_id();
	RTE_LOG(INFO, L2FWD, "dpdk_tx_thread entering main loop\n");
	int sent;

	while (1) {
		sent = rte_eth_tx_buffer_flush(0, 0, l2fwd_tx_buffer);
	    if (sent)
		port_statistics.tx += sent;
	}
}




err_t dpdk_device_init(struct netif* netif) {
	//struct lcore_queue_conf *qconf;
	//unsigned lcore_id = rte_lcore_id();
	//qconf = &lcore_queue_conf[lcore_id];
	//struct lcore_conf *qconf;
	//unsigned lcoreid = rte_lcore_id();
	//qconf = &lcore_conf[lcoreid-START_CORE];
	//if (!qconf) {
	//	return ERR_MEM;
	//}
	//netif->state = &lcore_queue_conf[0];
	netif->name[0] = 'd';
	netif->name[1] = 'k';
	netif->output = etharp_output; /*this might need to change since we statically coded the ip-ether addr pairing */
	netif->linkoutput = dpdk_output;
	netif->mtu = 1500;
	netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP; /*Not enabling ETHARP on this, so might need to change netif->output */


	netif->hwaddr[0]=l2fwd_port_eth_addr.addr_bytes[0];
	netif->hwaddr[1]=l2fwd_port_eth_addr.addr_bytes[1];
	netif->hwaddr[2]=l2fwd_port_eth_addr.addr_bytes[2];
	netif->hwaddr[3]=l2fwd_port_eth_addr.addr_bytes[3];
	netif->hwaddr[4]=l2fwd_port_eth_addr.addr_bytes[4];
	netif->hwaddr[5]=l2fwd_port_eth_addr.addr_bytes[5];
	netif->hwaddr_len = 6;

	netif_set_link_up(netif);
	//rte_eal_mp_remote_launch(dpdk_thread, (int *)netif, CALL_MASTER);

	struct arg_pass tmparg1;
    tmparg1.coreid = 1;
    tmparg1.args = (void *)netif;
    
 	struct arg_pass tmparg2;
    tmparg2.coreid = 4;
    tmparg2.args = (void *)netif;
    
    sys_thread_new("dpdk-rx-thread", dpdk_rx_thread, &tmparg1, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

	sys_thread_new("dpdk-tx-thread", dpdk_tx_thread, &tmparg2, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
	
	
	return ERR_OK;
	
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_port_link_status(void)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t count, port_up, print_flag = 0;
	struct rte_eth_link link;

	printf("Checking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		port_up = 1;
		
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(0, &link);
		/* print link status if flag set */
		if (print_flag == 1) {
			if (link.link_status)
				printf(
				"Port 0 Link Up. Speed %u Mbps - %s\n",
					link.link_speed,
			(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex\n"));
			else
				printf("Port 0 Link Down\n");
		}
		/* clear all_ports_up flag if any link down */
		if (link.link_status == ETH_LINK_DOWN) {
			port_up = 0;
			break;
		}
		
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (port_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (port_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
init_dpdk(int argc, char **argv)
{
	struct rte_eth_dev_info dev_info;
	int ret;
	uint16_t nb_ports;
	unsigned rx_lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* create the mbuf pool */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	/*
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	rte_eth_dev_info_get(0, &dev_info);

	rx_lcore_id = 0;

	/* Initialize the port/queue configuration of each logical core */
	while (rte_lcore_is_enabled(rx_lcore_id) == 0) {
		rx_lcore_id++;
	}
	printf("Lcore %u: RX port 0\n", rx_lcore_id);

	//nb_ports_available = nb_ports;

	/* init port 0 */
	printf("Initializing port 0 ... \n");
	fflush(stdout);
	ret = rte_eth_dev_configure(0, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=0\n", ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot adjust number of descriptors: err=%d, port=0\n", ret);

		rte_eth_macaddr_get(0,&l2fwd_port_eth_addr);

	/* init one RX queue */
	fflush(stdout);
	ret = rte_eth_rx_queue_setup(0, 0, nb_rxd,
					   rte_eth_dev_socket_id(0),
					   NULL,
					   l2fwd_pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=0\n", ret);

	/* init one TX queue on each port */
	fflush(stdout);
	ret = rte_eth_tx_queue_setup(0, 0, nb_txd, rte_eth_dev_socket_id(0), NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=0\n", ret);

		/* Initialize TX buffers */

	l2fwd_tx_buffer = (struct rte_eth_dev_tx_buffer *)rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(0));
		
	if (l2fwd_tx_buffer == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port 0\n");

	rte_eth_tx_buffer_init(l2fwd_tx_buffer, MAX_PKT_BURST);

	ret = rte_eth_tx_buffer_set_err_callback(l2fwd_tx_buffer,
			rte_eth_tx_buffer_count_callback,
			&port_statistics.dropped);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Cannot set error callback for tx buffer on port 0\n");

	/* Start device */
	ret = rte_eth_dev_start(0);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=0\n",
				ret);

	printf("done: \n");

	rte_eth_promiscuous_enable(0);

	printf("Port 0, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
			l2fwd_port_eth_addr.addr_bytes[0],
			l2fwd_port_eth_addr.addr_bytes[1],
			l2fwd_port_eth_addr.addr_bytes[2],
			l2fwd_port_eth_addr.addr_bytes[3],
			l2fwd_port_eth_addr.addr_bytes[4],
			l2fwd_port_eth_addr.addr_bytes[5]);

		/* initialize port stats */
	memset(&port_statistics, 0, sizeof(port_statistics));

	check_port_link_status();

	ret = 0;
	/* launch per-lcore init on every lcore */
//	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	//RTE_LCORE_FOREACH_SLAVE(lcore_id) {
	//	if (rte_eal_wait_lcore(lcore_id) < 0) {
	//		ret = -1;
	//		break;
	//	}
	//}
/*
	for (portid = 0; portid < nb_ports; portid++) {
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");
*/
	return ret;
}

