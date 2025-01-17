/* Created 2024 by David de Andres Hernandez @ imdea.org */
#include<unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_lcore.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_LCORES RTE_MAX_LCORE

#define RTE_LOGTYPE_FLOWGEN RTE_LOGTYPE_USER1


// Array to track TX queue ID for each lcore
uint16_t lcore_to_tx_queue[MAX_LCORES];
// Array to track TX packets for each lcore
static uint64_t lcore_pkt_counts[RTE_MAX_LCORE] = {0};
// int to track the number of tx workers
uint16_t nb_tx_lcores;
static uint16_t stats_worker_id;


static const struct rte_ether_addr dst_mac = {
    .addr_bytes = {0xf8, 0x8e, 0xa1, 0x12, 0xf8, 0xe1} //
};

static uint16_t dst_port_start = 1024;
static uint16_t num_flows = 100;
static uint16_t src_port = 12345;
static uint32_t src_ip = RTE_IPV4(192, 168, 1, 1);
static uint32_t dst_ip = RTE_IPV4(192, 168, 1, 2);


static volatile bool keep_running = true;

// Signal handler for graceful shutdown
static void handle_sigint(const int sig) {
	if (sig == SIGINT) {
		keep_running = false;
	}
	RTE_LOG(INFO, FLOWGEN,"Received SIGINT. Shutting down...\n");
}

static void setup_packet(uint16_t portid, uint16_t dst_port, struct rte_mbuf *pkts[32], int i) {
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
	rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr); // Destination MAC address
	rte_eth_macaddr_get(portid, &eth_hdr->src_addr); // Source MAC address
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->hdr_checksum = 0;
	ip_hdr->src_addr = rte_cpu_to_be_32(src_ip);
	ip_hdr->dst_addr = rte_cpu_to_be_32(dst_ip);

	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	udp_hdr->src_port = rte_cpu_to_be_16(src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr));
	udp_hdr->dgram_cksum = 0;

	pkts[i]->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
	pkts[i]->pkt_len = pkts[i]->data_len;
}

static void generate_packets(struct rte_mempool *mbuf_pool) {
	uint16_t portid;
    uint16_t dst_port = dst_port_start;

	// Get the core id
	unsigned lcore_id = rte_lcore_id();
	uint16_t tx_queue_id = lcore_to_tx_queue[lcore_id];

	// Each lcore generates packets for its unique set of flows

	// v1
	// uint16_t lcore_offset = lcore_id * (num_flows / rte_lcore_count());
	// uint16_t dst_port = dst_port_start + lcore_offset;
	// uint16_t dst_port_end_lcore = dst_port_start + lcore_offset + (num_flows / rte_lcore_count());

	//v2
	// uint16_t flows_per_lcore = num_flows / rte_lcore_count();
	// uint16_t dst_port_start_lcore = dst_port_start + lcore_id * flows_per_lcore;
	// uint16_t dst_port_end_lcore = dst_port_start_lcore + flows_per_lcore;
	// uint16_t dst_port = dst_port_start_lcore;

	while (keep_running) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (!rte_eth_dev_is_valid_port(portid)) {
				continue;
			}
			struct rte_mbuf *pkts[BURST_SIZE];
			int nb_pkts = rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE);

			if (nb_pkts < 0) {
				printf("Failed to allocate %d mbufs\n", BURST_SIZE);
				continue;
			}
			for (int i = 0; i < BURST_SIZE; i++) {
				setup_packet(portid, dst_port, pkts, i);
				// Increase dst_port to generate more flows
				dst_port++;
				if (dst_port >= dst_port_start + num_flows) {
					dst_port = dst_port_start;
				}
			}

			uint16_t to_send = BURST_SIZE;
			uint16_t nb_tx = 0;
			int sent;
			do {
				sent = rte_eth_tx_burst(portid, tx_queue_id, pkts, to_send);
				to_send -= sent;
				nb_tx += sent;
			} while (to_send > 0);

			lcore_pkt_counts[lcore_id] += nb_tx;
		}
	}
	RTE_LOG(INFO, FLOWGEN, "Stopping packet transmission on lcore %u\n", rte_lcore_id());
}

// Packet sending function for each core
static int send_packets_on_lcore(__attribute__((unused)) void *arg) {
	u_int16_t lcore_id = rte_lcore_id();

	RTE_LOG(INFO, FLOWGEN,"Lcore %u transmitting on TX queue %u\n", lcore_id, lcore_to_tx_queue[lcore_id]);

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;  // Using the same mbuf pool

	// Sending packets
	generate_packets(mbuf_pool);

	return 0;
}

/* Main functional part of port initialization. 8< */
static int port_init(uint16_t port) {
	struct rte_eth_conf port_conf;
	const uint16_t tx_rings = rte_lcore_count()-2;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, 0, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, NULL, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 TX queue per Ethernet port. */
	unsigned lcore_id;
	uint16_t tx_queue_id = 0; // Sequential TX queue ID
	bool launched_stats_worker = false;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!launched_stats_worker) {
			launched_stats_worker = true;
			continue;
		}
		if (tx_queue_id >= tx_rings) {
			rte_exit(EXIT_FAILURE, "Not enough TX queues for all lcores\n");
		}

		// Map lcore to TX queue
		lcore_to_tx_queue[lcore_id] = tx_queue_id;
		nb_tx_lcores++;

		txconf = dev_info.default_txconf;
		txconf.offloads = port_conf.txmode.offloads;
		retval = rte_eth_tx_queue_setup(port, tx_queue_id, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)	{
			return retval;
		}
		tx_queue_id++;
	}
	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	RTE_LOG(INFO, FLOWGEN, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	return 0;
}
/* >8 End of main functional part of port initialization. */


// Function to print statistics periodically
static int stats_monitoring_lcore(__attribute__((unused)) void *arg) {
	// uint16_t port_id = *(uint16_t *)arg;
	uint16_t port_id = 0;
	struct rte_eth_stats stats;
	struct rte_eth_dev_info dev_info;

	// Retrieve device information to get the number of TX queues
	if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
		printf("Failed to get device info for port %u\n", port_id);
		return -1;
	}

	uint16_t nb_tx_queues = dev_info.nb_tx_queues;
	unsigned lcore_id;

	while (keep_running) {
		rte_eth_stats_get(port_id, &stats);
		struct rte_eth_txq_info txq_info;

		// Move the cursor up by the total number of lines we will overwrite
		printf("\033[%dF", 1 + nb_tx_queues + nb_tx_lcores); // Move up: 1 (port stats) + tx queues + tx lcores

		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			if (lcore_id == stats_worker_id) {
				continue;
			}
			printf("Lcore %u - TX packets: %" PRIu64 "              \n", lcore_id, lcore_pkt_counts[lcore_id]);
		}

		// Print port-level statistics (overwriting the same line)
		printf("Port %u - RX packets: %" PRIu64 ", TX packets: %" PRIu64
			   ", RX errors: %" PRIu64 ", TX errors: %" PRIu64 "       \n",
			   port_id, stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors);

		// Print queue-level statistics (overwriting the same lines for each queue)
		for (uint16_t q = 0; q < nb_tx_queues; q++) {
			rte_eth_tx_queue_info_get(port_id, q, &txq_info);
			printf("  Queue %u - TX packets: %" PRIu64 ", TX bytes: %" PRIu64 ", nb_desc: %u       \n",
				   q, stats.q_opackets[q], stats.q_obytes[q], txq_info.nb_desc);
		}

		// Wait for 1 second
		sleep(1);
	}

	RTE_LOG(INFO, FLOWGEN, "Exiting statistics monitoring...\n");
	return 0;
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

	// Set stdout to unbuffered
	setbuf(stdout, NULL);

	// Register signal handler for SIGINT
	signal(SIGINT, handle_sigint);

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    /* Check the number of ports to send on. */
    nb_ports = rte_eth_dev_count_avail();

    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, (int) rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    RTE_LOG(DEBUG, FLOWGEN, "Created mbuf pool\n");
    /* >8 End of allocating mempool to hold mbuf. */

	/* Initializing port. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_is_valid_port(portid);
		if (!ret) {
			printf("Invalid port_id=%u\n", portid);
			continue;
		}
		if (port_init(portid) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
		}
		RTE_LOG(INFO, FLOWGEN,"Configured port %"PRIu16 "\n", portid);
	}
	/* >8 End of initializing all ports. */

	RTE_LOG(INFO, FLOWGEN, "Starting packet forwarding. [Ctrl+C to quit]\n");
	// Launch the packet sending function on multiple lcores
	unsigned lcore_id;
	bool launched_stats_worker = false;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!launched_stats_worker) {
			stats_worker_id = lcore_id;
			if (rte_eal_remote_launch(stats_monitoring_lcore, NULL, lcore_id) < 0) {
				rte_exit(EXIT_FAILURE, "Failed to launch stats monitoring\n");
			}
			launched_stats_worker = true;
		}
		if (rte_lcore_is_enabled(lcore_id)) {
			RTE_LOG(INFO, FLOWGEN, "Starting lcore %u\n", lcore_id);
			rte_eal_remote_launch(send_packets_on_lcore, mbuf_pool, lcore_id);
		}
	}

	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(portid) {
		if (!rte_eth_dev_is_valid_port(portid)) {
			continue;
		}
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		RTE_LOG(INFO, FLOWGEN, "Port %u stopped and closed\n", portid);
	}
	RTE_LOG(INFO, FLOWGEN, "Application exiting\n");
    return 0;
}
