#ifndef STATE_TABLE_H
#define STATE_TABLE_H 1

#include "hmap.h"
#include "packets.h"

#include <linux/slab.h>
#include <linux/kernel.h>

#define MAX_EXTRACTION_FIELD_COUNT 8
#define MAX_STATE_KEY_LEN 48

#define STATE_DEFAULT 0

const uint8_t dscp_mask = 0x3;
const uint8_t ecn_mask =  !0x3;
//TODO: sostituisci packet con ofpbuf!
/** 
 * oxm_vector length is greater than extractor->field_count; that is because
 * fields like ethernet addresses are greater than 32 bits, and so they are
 * coded in more than one integer.
 * Match fields assigned to more than one 32 bit integer are (currently
 * ETH_ALEN is 6):
 *   - OFPXMT12_OFB_ETH_DST:        ETH_ALEN B
 *   - OFPXMT12_OFB_ETH_SRC:        ETH_ALEN B
 *   - OFPXMT12_OFB_ARP_SHA:        ETH_ALEN B
 *   - OFPXMT12_OFB_ARP_THA:        ETH_ALEN B
 *   - OFPXMT12_OFB_IPV6_SRC        16       B
 *   - OFPXMT12_OFB_IPV6_DST        16       B
 *   - OFPXMT12_OFB_IPV6_ND_TARGET: 16       B
 *   - OFPXMT12_OFB_IPV6_ND_SLL:    ETH_ALEN B
 *   - OFPXMT12_OFB_IPV6_ND_TLL:    ETH_ALEN B
 * In the worst case we'll need 6*ETH_ALEN + 16*3 - 4*9 = 48 additional bytes.
 * oxm_vector[] is composed by u32, so additional size is 48/4 = 12.
 */
 /*
#define OXM_VECTOR_ADDITIONAL_SIZE 12
*/
struct key_extractor {
    uint32_t    field_count;
    uint32_t    fields[MAX_EXTRACTION_FIELD_COUNT]; /*  from enum 
                                                    oxm12_ofb_match_fields */
};

struct state_entry {
    struct hmap_node    hmap_node;
    u32                 key;
    uint32_t            key_size;
    uint32_t            state;
};

struct state_table {
    struct key_extractor    read_key;
    struct key_extractor    write_key;
    struct hmap             state_entries; 
    struct state_entry      default_state_entry;
};


struct state_table *state_table_create(void);
void state_table_destroy(struct state_table *);
struct state_entry *state_table_lookup(struct state_table *, struct ofpbuf *);
void state_table_write_state(struct state_entry *, struct ofpbuf *);
void state_table_set_state(struct state_table *, struct ofpbuf *, uint32_t, 
    uint8_t *, uint32_t);
void state_table_set_extractor(struct state_table *, struct key_extractor *, 
    int);
void state_table_del_state(struct state_table *, uint8_t *, uint32_t);

#endif /* state_table.h */