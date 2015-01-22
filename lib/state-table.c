#include "state-table.h"

u32 __extract_hash(struct key_extractor *, struct sw_flow_key *, 
	struct sk_buff *);

void miniflow_set_state(struct miniflow *flow, uint32_t state)
{
	*(miniflow_get_u32_values(flow) +
            count_1bits(flow->map & ((UINT64_C(1) << 
            	offsetof(struct flow, state)) - 1))) = state;
}

struct state_table *state_table_create(void) 
{
    struct state_table *table = xmalloc(sizeof(struct state_table));

	memset(table, 0, sizeof(*table));
	 
    table->state_entries = (struct hmap) 
    	HMAP_INITIALIZER(&table->state_entries);

	/* default state entry */
	table->default_state_entry.state = STATE_DEFAULT;
	
    return table;
}

void state_table_destroy(struct state_table *table) 
{
	hmap_destroy(&table->state_entries);
    free(table);
}

u32 __extract_hash(struct key_extractor *extractor, struct miniflow *flow)
{
	/** 
	 * TODO: Inserire controlli sul protocollo effettivo del pacchetto.  Alcuni
	 * campi sono in comune tra più protocolli, se viene settato il key
	 * extractor in modo errato si potrebbero avere problemi.
	 */
	const int OXM_VECTOR_SIZE = extractor->field_count + 
		OXM_VECTOR_ADDITIONAL_SIZE;
    u32 oxm_vector[OXM_VECTOR_SIZE];
    int i, j, k;

    for (i = 0; i < extractor->field_count && j < OXM_VECTOR_SIZE; i++, j++) {
    	switch (extractor->fields[i]) {
    	case OFPXMT12_OFB_IN_PORT:
    		oxm_vector[j] = MINIFLOW_GET_U32(flow, in_port);
    		break;

	    case OFPXMT12_OFB_IN_PHY_PORT:
	    	//TODO_fede

	    case OFPXMT12_OFB_METADATA:
	    	memcpy(oxm_vector + j, miniflow_get_metadata(flow),
	    		sizeof(ovs_be64));
	    	j++;
	    	break;

	    case OFPXMT12_OFB_ETH_DST:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, dl_dst));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, dl_dst) + 4);
	    	// memcpy(oxm_vector + j, key->eth.dst, ETH_ALEN);
	    	// j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1;
	    	break;

	    case OFPXMT12_OFB_ETH_SRC:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, dl_src));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, dl_src) + 4);
	    	//memcpy(oxm_vector + j, key->eth.src, ETH_ALEN);
	    	//j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1;
	    	break;   
	    
	    case OFPXMT12_OFB_ETH_TYPE:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, dl_type));
    		break;      
	    
	    case OFPXMT12_OFB_VLAN_VID:
	    	oxm_vector[j] = (u32) miniflow_get_vid(flow);
	    	break;

	    case OFPXMT12_OFB_VLAN_PCP:
	    	oxm_vector[j] = (u32) vlan_tci_to_pcp(MINIFLOW_GET_BE16(flow, 
	    		vlan_tci));
	    	break;
	    
	    case OFPXMT12_OFB_IP_DSCP:
	    	oxm_vector[j] = (u32) (MINIFLOW_GET_U8(flow, nw_tos) & dscp_mask);
	    	break;
	    
	    case OFPXMT12_OFB_IP_ECN:
		    oxm_vector[j] = (u32) (MINIFLOW_GET_U8(flow, nw_tos) & ecn_mask);
	    	break;     
	    
	    case OFPXMT12_OFB_IP_PROTO:
	    case OFPXMT12_OFB_ARP_OP:
	    	oxm_vector[j] = (u32) MINIFLOW_GET_U8(flow, nw_proto);
    		break;    
	    
	    case OFPXMT12_OFB_IPV4_SRC:
	    	oxm_vector[j] = (u32) ntohl(MINIFLOW_GET_BE32(flow, nw_src));
    		break; 
	    
	    case OFPXMT12_OFB_IPV4_DST:
	    	oxm_vector[j] = (u32) ntohl(MINIFLOW_GET_BE32(flow, nw_dst));
    		break;  
	    
	    case OFPXMT12_OFB_TCP_SRC:
	    case OFPXMT12_OFB_UDP_SRC:
	    case OFPXMT12_OFB_SCTP_SRC:  
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
    		break;     
	    
	    case OFPXMT12_OFB_TCP_DST:
	    case OFPXMT12_OFB_UDP_DST:
	    case OFPXMT12_OFB_SCTP_DST:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
    		break;         
	    
	    case OFPXMT12_OFB_ICMPV4_TYPE:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
    		break; 
	    
	    case OFPXMT12_OFB_ICMPV4_CODE:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
    		break; 
	    
	    case OFPXMT12_OFB_ARP_SPA:
	    	oxm_vector[j] = (u32) ntohl(MINIFLOW_GET_BE32(flow, nw_src));
	    	break;
	    
	    case OFPXMT12_OFB_ARP_TPA:
	    	oxm_vector[j] = (u32) ntohl(MINIFLOW_GET_BE32(flow, nw_dst));
	    	break;  
	    
	    case OFPXMT12_OFB_ARP_SHA:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, arp_sha));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, arp_sha) + 4);
	    	//memcpy(oxm_vector + j, key->ipv4.arp.sha, ETH_ALEN);
	    	//j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1;
	    	break; 
	    
	    case OFPXMT12_OFB_ARP_THA:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, arp_tha));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, arp_tha) + 4);
	    	//memcpy(oxm_vector + j, key->ipv4.arp.tha, ETH_ALEN);
	    	//j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1;
	    	break;  
	    
	    case OFPXMT12_OFB_IPV6_SRC:
	  		for (k = 0; k < 4; k++) {
	    		oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, ipv6_src) + k * 4);
	    		if (k != 3) {
	    			j++;
	    		}
	    	}
	    	//memcpy(oxm_vector + j, key->ipv6.addr.src.s6addr, 16);
	    	//j += 3;
	    	break;
	    
	    case OFPXMT12_OFB_IPV6_DST:
	    	for (k = 0; k < 4; k++) {
	    		oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, ipv6_dst) + k * 4);
	    		if (k != 3) {
	    			j++;
	    		}
	    	}
	    	//memcpy(oxm_vector + j, key->ipv6.addr.dst.s6addr, 16);
	    	//j += 3;
	    	break;  
	    
	    case OFPXMT12_OFB_IPV6_FLABEL:
	    	oxm_vector[j] = (u32) ntohl(MINIFLOW_GET_BE32(flow, ipv6_label));
    		break;
	    
	    case OFPXMT12_OFB_ICMPV6_TYPE:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_src));
    		break; 
	    
	    case OFPXMT12_OFB_ICMPV6_CODE:
	    	oxm_vector[j] = (u32) ntohs(MINIFLOW_GET_BE16(flow, tp_dst));
    		break; 
	    
	    case OFPXMT12_OFB_IPV6_ND_TARGET://TODO
		    for (k = 0; k < 4; k++) {
	    		oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, nd_target) + k * 4);
	    		if (k != 3) {
	    			j++;
	    		}
	    	}
	    	//memcpy(oxm_vector + j, key->ipv6.nd.target.s6addr, 16);
	    	//j += 3;
	    	break;    	    	
	    
	    case OFPXMT12_OFB_IPV6_ND_SLL:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, arp_sha));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, arp_sha) + 4);
			//memcpy(oxm_vector + j, key->ipv6.nd.sll, ETH_ALEN);
	    	//j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1; 
	    	break;
	    
	    case OFPXMT12_OFB_IPV6_ND_TLL:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, arp_tha));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, arp_tha) + 4);
	    	//memcpy(oxm_vector + j, key->ipv6.nd.tll, ETH_ALEN);
	    	//j += ETH_ALEN / 4 + ((ETH_ALEN % 4) != 0) - 1;
	    	break;   
	    
	    case OFPXMT12_OFB_MPLS_LABEL:
	    	oxm_vector[j] = mpls_lse_to_label(MINIFLOW_GET_BE32(flow, mpls_lse));
	    	break;
	    
	    case OFPXMT12_OFB_MPLS_TC:
	    	oxm_vector[j] = (u32) mpls_lse_to_tc(MINIFLOW_GET_BE32(flow, mpls_lse));
	    	break;
	    
	    case OFPXMT13_OFB_MPLS_BOS:
	    	oxm_vector[j] = (u32) mpls_lse_to_bos(MINIFLOW_GET_BE32(flow, mpls_lse));
	    	break;   
	    
	    case OFPXMT13_OFB_PBB_ISID:
	    	//TODO_fede   
	    
	    case OFPXMT13_OFB_TUNNEL_ID:
	    	oxm_vector[j] = MINIFLOW_GET_TYPE(flow, uint32_t, 
	    		offsetof(struct flow, tunnel));
	    	oxm_vector[++j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, tunnel) + 4);
	    	break;  
	    
	    case OFPXMT13_OFB_IPV6_EXTHDR:
	    	//TODO_fede 
	    
	    case OFPXMT13_OFB_STATE:
	        oxm_vector[j] = MINIFLOW_GET_U32(flow, state);
    		break;
	    
	    case OFPXMT13_OFB_FLAGS:
	    	oxm_vector[j] = (u32) MINIFLOW_GET_TYPE(flow, uint16_t, 
	    		offsetof(struct flow, tunnel) + offsetof(struct flow_tnl, flags));
	    	break;    
	    
	    case OFPXMT14_OFB_PBB_UCA:
	    	//TODO_fede  
	    
	    case OFPXMT15_OFB_TCP_FLAGS:
	    	oxm_vector[j] = (u32) miniflow_get_tcp_flags(flow);
    		break;
    		
    	default:
    		fprintf(stderr, "Warning: bad key extractor.\n");
    		oxm_vector[j] = 0;
    	}
    }

    return arch_fast_hash2(oxm_vector, --j, 0);
}

/* Having the read_key, look for the state value inside the state table. */
struct state_entry *state_table_lookup(struct state_table *table, 
	struct miniflow *flow)
{
	struct state_entry * e = NULL;	
	uint32_t key;

    key = __extract_hash(&table->read_key, flow);

	HMAP_FOR_EACH_WITH_HASH(e, hmap_node, key, &table->state_entries) {
			if (key == e->key) {
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

//TODO
/* having the state value  */
void state_table_write_state(struct state_entry *entry, struct packet *pkt) {
	struct  ofl_match_tlv *f;
    
	HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, 
		hmap_node, hash_int(OXM_OF_STATE,0), &pkt->handle_std->match.match_fields) {
                uint32_t *state = (uint32_t*) f->value;
                *state = (*state & 0x0) | (entry->state);
    }
}

void state_table_del_state(struct state_table *table, uint32_t key) {
	struct state_entry *e;
	int found = 0;
	HMAP_FOR_EACH_WITH_HASH(e, hmap_node, key, &table->state_entries) {
		if (key == e->key) {
			found = 1;
			break;
		}
	}
	if (found) {
		hmap_remove(&table->state_entries, &e->hmap_node);
		hmap_shrink(&table->state_entries);
	}
}

void state_table_set_extractor(struct state_table *table, 
	struct key_extractor *ke, int update) {
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

//TODO
void state_table_set_state(struct state_table *table, struct packet *pkt, 
	uint32_t state, uint8_t *k, uint32_t len) {
	uint8_t key[MAX_STATE_KEY_LEN] = {0};	
	struct state_entry *e;

	if (pkt) {
		__extract_hash(key, &table->write_key, pkt);
                                        int h;
                                        printf("ethernet address for write key is:");
                                        for (h=0;h<6;h++){
                                        printf("%02X", key[h]);}
                                        printf("\n");
	} else {
		memcpy(key, k, MAX_STATE_KEY_LEN);
	        printf("state table no pkt exist \n");
	}
	
	HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
		hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
			if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
				VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u updated to hash map", state);
				e->state = state;
				return;
			}
	}

	e = xmalloc(sizeof(struct state_entry));
	memcpy(e->key, key, MAX_STATE_KEY_LEN);
	e->state = state;
	VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u inserted to hash map", e->state);
        hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
}