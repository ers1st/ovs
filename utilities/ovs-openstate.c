#include <config.h>
#include <stdlib.h>
#include <unistd.h>

#include "dpif.h"
#include "dpif-provider.h"
#include "netdev-provider.h"
#include "odp-util.h"
#include "simap.h"
#include "state-table.h"
#include "util.h"

static int PORT = 80;
static char *DEV_NAME = "eth0";

int main(int argc, char *argv[])
{
    struct dpif *dpif;
    odp_port_t port_no;
    struct netdev *device;
    struct ofpbuf key0, key1, mask0, mask1, actions0, actions1;
    struct dpif_flow_stats stats0, stats1;
    struct dpif_port dpif_port;
    struct dpif_port_dump port_dump;
    struct simap port_names;
    const char *key_s0 = "state(0)";
    const char *key_s1 = "state(1)";
    const char *actions_s0 = "set_state(1)";
    const char *actions_s1 = "set_state(0)";
    struct key_extractor read_key, write_key;

    int error;

    if(argc != 1) {
        fprintf(stderr, "Usage: %s (no arguments)\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Inizializzo il bridge. */
    port_no = PORT;
    device = netdev_from_name(DEV_NAME);

    dpif_create_and_open("dp_openstate", "netdev", &dpif);
    printf("Created datapath with name: %s, and type: %s\n", 
           dpif->base_name, dpif->dpif_class->type);

    dpif_port_add(dpif, device,  &port_no);
    printf("Datapath bound to port %u\n", port_no);


    simap_init(&port_names);
    DPIF_PORT_FOR_EACH (&dpif_port, &port_dump, dpif) {
        simap_put(&port_names, dpif_port.name, odp_to_u32(dpif_port.port_no));
    }
    read_key.field_count = 1;
    read_key.fields[0] = OFPXMT13_OFB_STATE;
    write_key.field_count = 1;
    write_key.fields[0] = OFPXMT13_OFB_STATE;

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

    ofpbuf_init(&key0, 0);
    ofpbuf_init(&key1, 0);
    ofpbuf_init(&mask0, 0);
    ofpbuf_init(&mask1, 0);
    ofpbuf_init(&actions0, 0);
    ofpbuf_init(&actions1, 0);
    error = odp_flow_from_string(key_s0, &port_names, &key0, &mask0);
    if (error) {
        ovs_error(error, "Failed to convert key0 string");
    }

    error = odp_flow_from_string(key_s1, &port_names, &key1, &mask1);
    if (error) {
        ovs_error(error, "Failed to convert key1 string");
    }
    
    error = odp_actions_from_string(actions_s0, NULL, &actions0);
    if (error) {
        ovs_error(error, "Failed to convert actions0 string");
    }
    
    error = odp_actions_from_string(actions_s1, NULL, &actions1);
    if (error) {
        ovs_error(error, "Failed to convert action1 string");
    }

    error = dpif_flow_put(dpif, DPIF_FP_CREATE, 
                  ofpbuf_data(&key0), ofpbuf_size(&key0), 
                  ofpbuf_size(&mask0) == 0 ? NULL : ofpbuf_data(&mask0),
                  ofpbuf_size(&mask0), 
                  ofpbuf_data(&actions0), ofpbuf_size(&actions0), 
                  &stats0);
    if (error) {
        ovs_error(error, "Failed to insert flow 0");
    }

    error = dpif_flow_put(dpif, DPIF_FP_CREATE, 
                  ofpbuf_data(&key1), ofpbuf_size(&key1), 
                  ofpbuf_size(&mask1) == 0 ? NULL : ofpbuf_data(&mask1),
                  ofpbuf_size(&mask1), 
                  ofpbuf_data(&actions1), ofpbuf_size(&actions1), 
                  &stats1);
    if (error) {
        ovs_error(error, "Failed to insert flow 1");
    }

    ofpbuf_uninit(&key0);
    ofpbuf_uninit(&key1);
    ofpbuf_uninit(&mask0);
    ofpbuf_uninit(&mask1);
    ofpbuf_uninit(&actions0);
    ofpbuf_uninit(&actions1);

    /* Faccio dump flows per vedere i flussi inseriti. */
    // TODO

    /**
     * Processo i pacchetti; ogni volta che un pacchetto viene processato devo 
     * avere una stampa della condizione attuale della state table.
     */
    //TODO
    //on_exit
    netdev_close(device);
    exit(EXIT_SUCCESS);
}