#include <config.h>
#include "state-table.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "flow.h"
#include "jhash.h"
#include "hmap.h"
#include "openflow/openflow.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(state_table); /* Should be removed after debugging. */

/**
 * Porting notes.
 *
 * When reusing this code for dpif-linux datapath implementation, replace:
 *      jhash_words()       with        arch_fast_hash2()
 */
static void extract_key__(uint32_t **, uint32_t *, struct key_extractor *, 
                          struct miniflow *);
static inline uint32_t *miniflow_get_values_writable(struct miniflow *);
static inline uint32_t *miniflow_get_u32_values_writable(struct miniflow *);


struct state_table *state_table_create(void) 
{
    struct state_table *table = xmalloc(sizeof(struct state_table));

    memset(table, 0, sizeof(*table));
     
    table->state_entries = (struct hmap) 
        HMAP_INITIALIZER(&table->state_entries);

    table->default_state_entry.state = STATE_DEFAULT;
    
    return table;
}

void state_table_destroy(struct state_table *table) 
{
    hmap_destroy(&table->state_entries);
    free(table);
}

static void extract_key__(uint32_t **key, uint32_t *size, 
                          struct key_extractor *extractor, 
                          struct miniflow *flow)
{
    /** 
     * TODO: Inserire controlli sul protocollo effettivo del pacchetto.  Alcuni
     * campi sono in comune tra più protocolli, se viene settato il key
     * extractor in modo errato si potrebbero avere problemi.
     */
    const int OXM_VECTOR_SIZE = extractor->field_count + 
        OXM_VECTOR_ADDITIONAL_SIZE;
    uint32_t *oxm_vector = xmalloc(sizeof(uint32_t) * OXM_VECTOR_SIZE);
    int i, j, k;

    for (i = 0; i < extractor->field_count && j < OXM_VECTOR_SIZE; i++, j++) {
        switch (extractor->fields[i]) {
        case OFPXMT12_OFB_IN_PORT:
            oxm_vector[j] = MINIFLOW_GET_U32(flow, in_port);
            break;

        case OFPXMT12_OFB_IN_PHY_PORT:
            //TODO_fede

        case OFPXMT12_OFB_METADATA: {
            ovs_be64 metadata = miniflow_get_metadata(flow);
            memcpy(oxm_vector + j, &metadata, sizeof metadata);
            j++;
            break;
        }

        case OFPXMT12_OFB_ETH_DST:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, dl_dst));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, dl_dst) + 4);
            break;

        case OFPXMT12_OFB_ETH_SRC:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, dl_src));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, dl_src) + 4);
            break;   
        
        case OFPXMT12_OFB_ETH_TYPE:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, dl_type));
            break;      
        
        case OFPXMT12_OFB_VLAN_VID:
            oxm_vector[j] = (uint32_t) miniflow_get_vid(flow);
            break;

        case OFPXMT12_OFB_VLAN_PCP:
            oxm_vector[j] = (uint32_t) vlan_tci_to_pcp(MINIFLOW_GET_BE16(flow, 
                vlan_tci));
            break;
        
        case OFPXMT12_OFB_IP_DSCP:
            oxm_vector[j] = (uint32_t) (MINIFLOW_GET_U8(flow, nw_tos) & 0x3);
            break;
        
        case OFPXMT12_OFB_IP_ECN:
            oxm_vector[j] = (uint32_t) (MINIFLOW_GET_U8(flow, nw_tos) & !0x3);
            break;     
        
        case OFPXMT12_OFB_IP_PROTO:
        case OFPXMT12_OFB_ARP_OP:
            oxm_vector[j] = (uint32_t) MINIFLOW_GET_U8(flow, nw_proto);
            break;    
        
        case OFPXMT12_OFB_IPV4_SRC:
            oxm_vector[j] = (uint32_t) ntohl(MINIFLOW_GET_BE32(flow, nw_src));
            break; 
        
        case OFPXMT12_OFB_IPV4_DST:
            oxm_vector[j] = (uint32_t) ntohl(MINIFLOW_GET_BE32(flow, nw_dst));
            break;  
        
        case OFPXMT12_OFB_TCP_SRC:
        case OFPXMT12_OFB_UDP_SRC:
        case OFPXMT12_OFB_SCTP_SRC:  
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
            break;     
        
        case OFPXMT12_OFB_TCP_DST:
        case OFPXMT12_OFB_UDP_DST:
        case OFPXMT12_OFB_SCTP_DST:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
            break;         
        
        case OFPXMT12_OFB_ICMPV4_TYPE:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
            break; 
        
        case OFPXMT12_OFB_ICMPV4_CODE:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
            break; 
        
        case OFPXMT12_OFB_ARP_SPA:
            oxm_vector[j] = (uint32_t) ntohl(MINIFLOW_GET_BE32(flow, nw_src));
            break;
        
        case OFPXMT12_OFB_ARP_TPA:
            oxm_vector[j] = (uint32_t) ntohl(MINIFLOW_GET_BE32(flow, nw_dst));
            break;  
        
        case OFPXMT12_OFB_ARP_SHA:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, arp_sha));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, arp_sha) + 4);
            break; 
        
        case OFPXMT12_OFB_ARP_THA:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, arp_tha));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, arp_tha) + 4);
            break;  
        
        case OFPXMT12_OFB_IPV6_SRC:
            for (k = 0; k < 4; k++) {
                oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, ipv6_src) + k * 4);
                if (k != 3) {
                    j++;
                }
            }
            break;
        
        case OFPXMT12_OFB_IPV6_DST:
            for (k = 0; k < 4; k++) {
                oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, ipv6_dst) + k * 4);
                if (k != 3) {
                    j++;
                }
            }
            break;  
        
        case OFPXMT12_OFB_IPV6_FLABEL:
            oxm_vector[j] = (uint32_t) ntohl(MINIFLOW_GET_BE32(flow, ipv6_label));
            break;
        
        case OFPXMT12_OFB_ICMPV6_TYPE:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
            break; 
        
        case OFPXMT12_OFB_ICMPV6_CODE:
            oxm_vector[j] = (uint32_t) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
            break; 
        
        case OFPXMT12_OFB_IPV6_ND_TARGET:
            for (k = 0; k < 4; k++) {
                oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, nd_target) + k * 4);
                if (k != 3) {
                    j++;
                }
            }
            break;              
        
        case OFPXMT12_OFB_IPV6_ND_SLL:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, arp_sha));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, arp_sha) + 4);
            break;
        
        case OFPXMT12_OFB_IPV6_ND_TLL:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, arp_tha));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, arp_tha) + 4);
            break;   
        
        case OFPXMT12_OFB_MPLS_LABEL:
            oxm_vector[j] = mpls_lse_to_label(MINIFLOW_GET_BE32(flow, mpls_lse));
            break;
        
        case OFPXMT12_OFB_MPLS_TC:
            oxm_vector[j] = (uint32_t) mpls_lse_to_tc(MINIFLOW_GET_BE32(flow, mpls_lse));
            break;
        
        case OFPXMT13_OFB_MPLS_BOS:
            oxm_vector[j] = (uint32_t) mpls_lse_to_bos(MINIFLOW_GET_BE32(flow, mpls_lse));
            break;   
        
        case OFPXMT13_OFB_PBB_ISID:
            //TODO_fede   
        
        case OFPXMT13_OFB_TUNNEL_ID:
            oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
                offsetof(struct flow, tunnel));
            oxm_vector[++j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, tunnel) + 4);
            break;  
        
        case OFPXMT13_OFB_IPV6_EXTHDR:
            //TODO_fede 
        
        case OFPXMT13_OFB_STATE:
            oxm_vector[j] = MINIFLOW_GET_U32(flow, state);
            break;
        
        case OFPXMT13_OFB_FLAGS:
            oxm_vector[j] = (uint32_t) MINIFLOW_GET_TYPE(flow, uint16_t, 
                offsetof(struct flow, tunnel) + offsetof(struct flow_tnl, flags));
            break;    
        
        case OFPXMT14_OFB_PBB_UCA:
            //TODO_fede  
        
        case OFPXMT15_OFB_TCP_FLAGS:
            oxm_vector[j] = (uint32_t) miniflow_get_tcp_flags(flow);
            break;
            
        default:
            fprintf(stderr, "Warning: bad key extractor.\n");
            oxm_vector[j] = 0;
        }
    }
    *key = oxm_vector;
    *size = --j;
}

/* Having the read_key, look for the state value inside the state table. */
struct state_entry *state_table_lookup(struct state_table *table, 
                                       struct miniflow *flow)
{
    struct state_entry * e = NULL;  
    uint32_t *key;
    uint32_t key_size;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    extract_key__(&key, &key_size, &table->read_key, flow);

    HMAP_FOR_EACH_WITH_HASH(e, hmap_node, jhash_words(key, key_size, 0), 
                            &table->state_entries) {
            if (key_size == e->key_size && !memcmp(key, e->key, key_size)) {
                VLOG_WARN_RL(&rl, "Found corresponding state %u", e->state);
                return e;
            }
    }

    if (e == NULL) {
        VLOG_WARN_RL(&rl, "Not found the corresponding state value\n");
        return &table->default_state_entry;
    }
    else
        return e; //TODO: Che significa? 
}

void state_table_write_state(struct state_entry *entry, struct miniflow *flow)
{
    *(miniflow_get_u32_values_writable(flow) +
            count_1bits(flow->map & ((UINT64_C(1) << 
                offsetof(struct flow, state)) - 1))) = entry->state;
}

void state_table_set_state(struct state_table *table, struct miniflow *flow, 
                           uint32_t state, uint32_t *k, uint32_t k_size) 
{
    uint32_t *key;
    uint32_t key_size, hash_key;    
    struct state_entry *e;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    if (flow != NULL) {
        extract_key__(&key, &key_size, &table->write_key, flow);
        //                                int h;
        //                                printf("ethernet address for write key is:");
        //                                for (h=0;h<6;h++){
        //                                printf("%02X", key[h]);}
        //                                printf("\n");
    } else {
        key = k;
        key_size = k_size;
        printf("state table no pkt exist \n");
    }

    hash_key = jhash_words(key, key_size, 0);

    HMAP_FOR_EACH_WITH_HASH(e, hmap_node, hash_key, &table->state_entries) {
        if (key_size == e->key_size && !memcmp(key, e->key, key_size)) {
            VLOG_WARN_RL(&rl, "state value is %u updated to hash map", state);
            e->state = state;
            return;
        }
    }

    e = xmalloc(sizeof(struct state_entry));
    e->key = key;
    e->key_size = key_size;
    e->state = state;
    hmap_insert(&table->state_entries, &e->hmap_node, hash_key);
    VLOG_WARN_RL(&rl, "state value is %u inserted to hash map", e->state);
}

void state_table_set_extractor(struct state_table *table, 
                               struct key_extractor *ke, bool update) 
{
    struct key_extractor *dest;
    if (update) {
        dest = &table->write_key;
                printf("writing key\n");
    } else {
        dest = &table->read_key;
                printf("reading key\n");
    }
    dest->field_count = ke->field_count;

    memcpy(dest->fields, ke->fields, 4 * ke->field_count);
}

void state_table_del_state(struct state_table *table, uint32_t *key, 
                           uint32_t key_size) 
{
    struct state_entry *e;
    bool found = 0;
    HMAP_FOR_EACH_WITH_HASH(e, hmap_node, jhash_words(key, key_size, 0), 
                            &table->state_entries) {
        if (key_size == e->key_size && !memcmp(key, e->key, key_size)) {
            found = 1;
            break;
        }
    }
    if (found) {
        hmap_remove(&table->state_entries, &e->hmap_node);
        hmap_shrink(&table->state_entries);
    }
}

static inline uint32_t *miniflow_get_values_writable(struct miniflow *mf)
{
    return OVS_LIKELY(mf->values_inline)
        ? mf->inline_values : mf->offline_values;
}

static inline uint32_t *miniflow_get_u32_values_writable(struct miniflow *mf)
{
    return miniflow_get_values_writable(mf);
}