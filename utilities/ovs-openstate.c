#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dpif.h"
#include "dpif-provider.h"
#include "openflow/openflow.h"
#include "odp-util.h"
#include "simap.h"
#include "state-table.h"
#include "util.h"

static int PORT = 80;
static char *DEV_NAME = "eth0";

static void openstate_add_flow(struct dpif *, struct simap *, 
                               struct dpif_flow_stats *, const char *, 
                               const char *);

int main(int argc, char *argv[])
{
    struct dpif *dpif;
    odp_port_t port_no;
    struct netdev *netdev;
    struct dpif_flow_stats stats0, stats1;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct simap port_names;
    const char *key_s0 = "state(0), " 
			 "eth(src=00:11:22:33:44:55/00:00:00:00:00:01,"
                             "dst=00:11:22:33:44:55/00:00:00:00:00:11), "
                         "eth_type(0x6ff/0x0)";
    const char *key_s1 = "state(1), " 
			 "eth(src=00:11:22:33:44:55/00:00:00:00:00:01,"
                             "dst=00:11:22:33:44:55/00:00:00:00:00:11), "
                         "eth_type(0x6ff/0x0)";;
    const char *actions_s0 = "set_state(1)";
    const char *actions_s1 = "set_state(0)";
    struct key_extractor read_key, write_key;

    if(argc != 1) {
        fprintf(stderr, "Usage: %s (no arguments)\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Inizializzo il bridge. */
    port_no = PORT;
    if (netdev_open(DEV_NAME, dpif_port_open_type("netdev", "system"), 
                    &netdev)) {
        fprintf(stderr, "Error in opening netdev\n");
        exit(EXIT_FAILURE);
    }

    dpif_create_and_open("dp_openstate", "netdev", &dpif);
    printf("Created datapath with name: %s, and type: %s\n", 
           dpif->base_name, dpif->dpif_class->type);

    dpif_port_add(dpif, netdev,  &port_no);
    printf("Datapath bound to port %u\n", port_no);


    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }
    read_key.field_count = 1;
    read_key.fields[0] = OFPXMT12_OFB_IN_PORT;
    write_key.field_count = 1;
    write_key.fields[0] = OFPXMT12_OFB_IN_PORT;

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
    netdev_close(netdev);
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
