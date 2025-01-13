/* Created 2024 by David de Andres Hernandez @ imdea.org */

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_ether_addr dst_mac = {
    .addr_bytes = {0xf8, 0x8e, 0xa1, 0x12, 0xf8, 0xe1} //
};

static uint16_t dst_port_start = 1024;
static uint16_t num_flows = 100;
static uint16_t src_port = 12345;
static uint32_t src_ip = RTE_IPV4(192, 168, 1, 1);
static uint32_t dst_ip = RTE_IPV4(192, 168, 1, 2);

static void generate_packets(struct rte_mempool *mbuf_pool) {
	uint16_t portid;
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t dst_port = dst_port_start;

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	while (1) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (!rte_eth_dev_is_valid_port(portid)) {
				continue;
			}
			for (int i = 0; i < BURST_SIZE; i++) {
				pkts[i] = rte_pktmbuf_alloc(mbuf_pool);
				if (pkts[i] == NULL) {
					printf("Failed to allocate mbuf\n");
					return;
				}

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

				dst_port++;
				if (dst_port >= dst_port_start + num_flows) {
					dst_port = dst_port_start;
				}
			}

			uint16_t nb_tx = rte_eth_tx_burst(portid, 0, pkts, BURST_SIZE);
			// printf("Transmitted %u packets\n", nb_tx);

			for (int i = nb_tx; i < BURST_SIZE; i++) {
				rte_pktmbuf_free(pkts[i]);
			}
		}
	}
}

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t tx_rings = 1;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
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
	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
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

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	return 0;
}
/* >8 End of main functional part of port initialization. */

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    /* Check the number of ports to send on. */
    nb_ports = rte_eth_dev_count_avail();

    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    printf("Created mbuf pool\n");
    /* >8 End of allocating mempool to hold mbuf. */

    /* Initializing port. 8< */
	// portid = 0;
	RTE_ETH_FOREACH_DEV(portid) {
		ret = rte_eth_dev_is_valid_port(portid);
		if (!ret) {
			printf("Invalid port_id=%u\n", portid);
			continue;
		}
		if (port_init(portid, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
		}
		printf("Configured port %"PRIu16 "\n", portid);
	}
    /* >8 End of initializing all ports. */


    generate_packets(mbuf_pool);
	RTE_ETH_FOREACH_DEV(portid) {
		if (!rte_eth_dev_is_valid_port(portid)) {
			continue;
		}
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
    return 0;
}
