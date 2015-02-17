#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dpif.h"
#include "dpif-netdev.h"
#include "dpif-provider.h"
#include "openflow/openflow.h"
#include "odp-util.h"
#include "simap.h"
#include "state-table.h"
#include "util.h"

static void openstate_add_flow(struct dpif *, struct simap *, 
                               struct dpif_flow_stats *, const char *, 
                               const char *);

int main(int argc, char *argv[])
{
    struct dpif *dpif;
    odp_port_t port_A, port_B;
    struct netdev *netdev_A, *netdev_B;
    struct dpif_flow_stats stats0, stats1;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct simap port_names;
    uint32_t output_port;
    int error;

    const char *key_s0 = "state(0), " 
                         "eth(src=08:00:27:9f:08:b8/00:00:00:00:00:00,"
                             "dst=08:00:27:9f:08:b8/00:00:00:00:00:00), "
                         "eth_type(0xffff/0), in_port(10000)";
    const char *key_s1 = "state(1), " 
                         "eth(src=08:00:27:9f:08:b8/00:00:00:00:00:00,"
                             "dst=08:00:27:9f:08:b8/00:00:00:00:00:00), "
                         "eth_type(0xffff/0)";
    const char *actions_s0 = "set_state(1)";
    const char actions_s1[15];
    struct key_extractor read_key, write_key;

    if(argc != 1) {
        fprintf(stderr, "Usage: %s (no arguments)\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Inizializzo il bridge. */

    dpif_create_and_open("dp_openstate", "netdev", &dpif);
    printf("Created datapath with name: %s, and type: %s\n", 
           dpif->base_name, dpif->dpif_class->type);
    
    if (netdev_open("eth1", dpif_port_open_type("netdev", "system"), 
                    &netdev_A)) {
        fprintf(stderr, "Error in opening netdev\n");
        exit(EXIT_FAILURE);
    }

    if (netdev_open("eth2", dpif_port_open_type("netdev", "system"), 
                    &netdev_B)) {
        fprintf(stderr, "Error in opening netdev\n");
        exit(EXIT_FAILURE);
    }


    error = dpif_port_add(dpif, netdev_A, &port_A);
    if (error) {
        fprintf(stderr, "Error %d adding port.\n", error);
        netdev_close(netdev_A);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }
    error = netdev_turn_flags_on(netdev_A, NETDEV_UP, NULL);
    if (error) {
        fprintf(stderr, "Error %d setting flags.\n", error);
        netdev_close(netdev_A);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }
    netdev_close(netdev_A);
    printf("Added port %u to datapath.\n", port_A);


    error = dpif_port_add(dpif, netdev_B, &port_B);
    if (error) {
        fprintf(stderr, "Error %d adding port.\n", error);
        netdev_close(netdev_B);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }
    error = netdev_turn_flags_on(netdev_B, NETDEV_UP, NULL);
    if (error) {
        fprintf(stderr, "Error %d setting flags.\n", error);
        netdev_close(netdev_B);
        dpif_close(dpif);
        exit(EXIT_FAILURE);
    }
    netdev_close(netdev_B);
    printf("Added port %u to datapath.\n", port_B);


    output_port = odp_to_u32(port_B);
    sprintf(actions_s1, "%u", output_port);
    
    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }
    read_key.field_count = 1;
    read_key.fields[0] = OFPXMT12_OFB_IPV4_SRC;
    write_key.field_count = 1;
    write_key.fields[0] = OFPXMT12_OFB_IPV4_SRC;

    /* Setto il key extractor sulla state table */
    dpif_set_extractor(dpif, &read_key, 0);
    dpif_set_extractor(dpif, &write_key, 1);


    /**
     * Implemento una semplice macchina a stati. Se lo stato del flusso è 0,
     * la set state lo impone a 1, se è 1 lo impone a 0.  Quindi la chiave
     * su cui viene effettuato il match è composta dal solo state.
     * Nome flusso      key         azione
     * 0                0           set_state(1)
     * 1                1           set_state(0)
     */

    openstate_add_flow(dpif, NULL, &stats0, key_s0, actions_s0);
    printf("Added flow 0\n");
    openstate_add_flow(dpif, NULL, &stats1, key_s1, actions_s1);
    printf("Added flow 1\n");    

    printf("Running bridge.\n");
    for(;;) {
        dpif_run(dpif);
    }

    //on_exit
    exit(EXIT_SUCCESS);
}

static void openstate_add_flow(struct dpif *dpif, struct simap *port_names,
                               struct dpif_flow_stats *stats,
                               const char *key_s, const char *actions_s)
{
    struct ofpbuf key, mask, actions;
    int error;

    ofpbuf_init(&key, 0);
    ofpbuf_init(&mask, 0);
    ofpbuf_init(&actions, 0);

    error = odp_flow_from_string(key_s, port_names, &key, &mask);
    if (error) {
        ovs_error(error, "Failed to convert key string %s", key_s);
    }
    
    error = odp_actions_from_string(actions_s, NULL, &actions);
    if (error) {
        ovs_error(error, "Failed to convert actions string %s", actions_s);
    }

    error = dpif_flow_put(dpif, DPIF_FP_CREATE, 
                          ofpbuf_data(&key), ofpbuf_size(&key), 
                          ofpbuf_size(&mask) == 0 ? NULL : ofpbuf_data(&mask),
                          ofpbuf_size(&mask), 
                          ofpbuf_data(&actions), ofpbuf_size(&actions), 
                          stats);
    if (error) {
        ovs_error(error, "Failed to insert flow");
    }

    ofpbuf_uninit(&key);
    ofpbuf_uninit(&mask);
    ofpbuf_uninit(&actions);
}
