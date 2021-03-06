#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dpif.h"
#include "dpif-netdev.h"
#include "dpif-provider.h"
#include "dynamic-string.h"
#include "openflow/openflow.h"
#include "odp-util.h"
#include "simap.h"
#include "state-table.h"
#include "util.h"

static void openstate_add_flow(struct dpif *, const char *, const char *);
static void openstate_add_if(struct dpif *, const char *, odp_port_t *);
static void openstate_dump_flows(struct dpif *);

int main(int argc, char *argv[])
{
    struct dpif *dpif;
    odp_port_t port_A = ODPP_NONE;
    odp_port_t port_B = ODPP_NONE;
    uint32_t output_port;
    const char *key_s01 = "state(0), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749,dst=5123)";
    const char *key_s10 = "state(1), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749/0xff,dst=0/0x0)";
    const char *key_s12 = "state(1), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749,dst=6234)";
    const char *key_s20 = "state(2), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749/0xff,dst=0/0x0)";
    const char *key_s23 = "state(2), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749,dst=7345)";
    const char *key_s30 = "state(3), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749/0xff,dst=0/0x0)";
    const char *key_s34 = "state(3), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749,dst=8456)";
    const char *key_s44 = "state(4), "
                         "in_port(1), "
                         "eth(src=08:00:27:26:E3:BF,"
                             "dst=08:00:27:20:6C:59), "
                         "eth_type(0x0800), "
                         "ipv4(src=10.0.0.1,"
                              "dst=10.0.0.2,"
                              "proto=0x11,"
                              "tos=0,"
                              "ttl=64,"
                              "frag=no), "
                         "udp(src=48749,dst=22)";

    const char *actions_s01 = "set_state(1)";
    const char *actions_s10 = "set_state(0)";
    const char *actions_s12 = "set_state(2)";
    const char *actions_s20 = "set_state(0)";
    const char *actions_s23 = "set_state(3)";
    const char *actions_s30 = "set_state(0)";
    const char *actions_s34 = "set_state(4)";

    const char actions_s44[15];
    struct key_extractor read_key, write_key;

    if(argc != 1) {
        fprintf(stderr, "Usage: %s (no arguments)\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Inizializzo il bridge. */

    dpif_create_and_open("dp_openstate", "netdev", &dpif);
    printf("Created datapath with name: %s, and type: %s\n", 
           dpif->base_name, dpif->dpif_class->type);
    
    openstate_add_if(dpif, "eth1", &port_A);
    openstate_add_if(dpif, "eth2", &port_B);

    output_port = odp_to_u32(port_B);
    sprintf(actions_s44, "%u", output_port);
    
    read_key.field_count = 1;
    read_key.fields[0] = OFPXMT12_OFB_IPV4_SRC;
    write_key.field_count = 1;
    write_key.fields[0] = OFPXMT12_OFB_IPV4_SRC;

    /* Setto il key extractor sulla state table */
    dpif_set_extractor(dpif, &read_key, 0);
    dpif_set_extractor(dpif, &write_key, 1);


    /**
     * Implemento il port knocking, come definito nel paper su OpenState.
     */

    openstate_add_flow(dpif, key_s01, actions_s01);
    printf("Added flow 01\n");
    openstate_add_flow(dpif, key_s12, actions_s12);
    printf("Added flow 12\n");
    openstate_add_flow(dpif, key_s23, actions_s23);
    printf("Added flow 23\n");
    openstate_add_flow(dpif, key_s34, actions_s34);
    printf("Added flow 34\n");
    openstate_add_flow(dpif, key_s44, actions_s44);
    printf("Added flow 44\n");
    openstate_add_flow(dpif, key_s10, actions_s10);
    printf("Added flow 10\n");
    openstate_add_flow(dpif, key_s20, actions_s20);
    printf("Added flow 20\n");
    openstate_add_flow(dpif, key_s30, actions_s30);
    printf("Added flow 30\n");

    printf("Dumping flows.\n");
    openstate_dump_flows(dpif);

    printf("Running bridge.\n");
    for(;;) {
        dpif_run(dpif);
    }

    //on_exit
    exit(EXIT_SUCCESS);
}

static void openstate_add_flow(struct dpif *dpif, const char *key_s, 
                               const char *actions_s)
{
    struct ofpbuf key, mask, actions;
    int error;
    struct simap port_names;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct dpif_flow_stats stats;

    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }
    
    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);

    error = odp_flow_from_string(key_s, &port_names, &key, &mask);
    if (error) {
        ovs_error(error, "Failed to convert key string %s", key_s);
    }

    simap_destroy(&port_names);
    
    ofpbuf_init(&actions, 0);
    error = odp_actions_from_string(actions_s, NULL, &actions);
    if (error) {
        ovs_error(error, "Failed to convert actions string %s", actions_s);
    }

    error = dpif_flow_put(dpif, DPIF_FP_CREATE, 
                          ofpbuf_data(&key), ofpbuf_size(&key), 
                          ofpbuf_size(&mask) == 0 ? NULL : ofpbuf_data(&mask),
                          ofpbuf_size(&mask), 
                          ofpbuf_data(&actions), ofpbuf_size(&actions), 
                          &stats);
    if (error) {
        ovs_error(error, "Failed to insert flow");
    }

    ofpbuf_uninit(&key);
    ofpbuf_uninit(&mask);
    ofpbuf_uninit(&actions);
}

static void openstate_add_if(struct dpif *dpif, const char *name, 
                             odp_port_t *port_no)
{
    struct netdev *netdev = NULL;
    int error;

    error = netdev_open(name, dpif_port_open_type("netdev", "system"), &netdev);
    if (error) {
        fprintf(stderr, "Error in opening netdev\n");
        exit(EXIT_FAILURE);
    }

    error = dpif_port_add(dpif, netdev, port_no);
    if (error) {
        fprintf(stderr, "Error %d adding port.\n", error);
        netdev_close(netdev);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }

    error = netdev_turn_flags_on(netdev, NETDEV_UP, NULL);
    if (error) {
        fprintf(stderr, "Error %d setting flags.\n", error);
        netdev_close(netdev);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }

    netdev_close(netdev);
    printf("Added port %u to datapath.\n", *port_no);
}

static void openstate_dump_flows(struct dpif *dpif)
{
    const struct dpif_flow_stats *stats;
    const struct nlattr *actions;
    struct dpif_flow_dump flow_dump;
    const struct nlattr *key;
    const struct nlattr *mask;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct hmap portno_names;
    struct simap names_portno;
    size_t actions_len;
    size_t key_len;
    size_t mask_len;
    struct ds ds;
    void *state = NULL;
    int error;
    int verbosity = 1;


    hmap_init(&portno_names);
    simap_init(&names_portno);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        odp_portno_names_set(&portno_names, dpif_port.port_no, dpif_port.name);
        simap_put(&names_portno, dpif_port.name,
                  odp_to_u32(dpif_port.port_no));
    }


    ds_init(&ds);
    error = dpif_flow_dump_start(&flow_dump, dpif);
    if (error) {
        goto exit;
    }
    dpif_flow_dump_state_init(dpif, &state);
    while (dpif_flow_dump_next(&flow_dump, state, &key, &key_len,
                               &mask, &mask_len, &actions, &actions_len,
                               &stats)) {
        ds_clear(&ds);
        odp_flow_format(key, key_len, mask, mask_len, &portno_names, &ds,
                        verbosity);
        ds_put_cstr(&ds, ", ");

        dpif_flow_stats_format(stats, &ds);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len);
        printf("%s\n", ds_cstr(&ds));
    }
    dpif_flow_dump_state_uninit(dpif, state);
    error = dpif_flow_dump_done(&flow_dump);

exit:
    if (error) {
        ovs_fatal(error, "Failed to dump flows from datapath");
    }
    odp_portno_names_destroy(&portno_names);
    hmap_destroy(&portno_names);
    simap_destroy(&names_portno);
    ds_destroy(&ds);
}
