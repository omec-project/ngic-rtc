#ifndef __LI_CONFIG_H_
#define __LI_CONFIG_H_

#include "pfcp_enum.h"
#include "gw_adapter.h"
#include "pfcp_util.h"

#define ADD_LI_ENTRY			1
#define UPDATE_LI_ENTRY			2
#define DELETE_LI_ENTRY			3

extern struct rte_hash *li_info_by_imsi_hash;
extern struct rte_hash *li_id_by_imsi_hash;

/**
 * @brief  : Delete LI entry using id
 * @param  : uiId[], array contains li entries to delete from hash and stop li
 * @param  : uiCntr, number of entries in array
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
del_li_entry(uint64_t *uiId, uint16_t uiCntr);

/**
 * @brief  : Fill LI config values
 * @param  : li_config_t, array of structure from which li_config is to be filled
 * @param  : uiCntr, number of entries in array
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
fillup_li_df_hash(struct li_df_config_t *li_df_config, uint16_t uiCntr);

/**
 * @brief  : Retrive LI UE Database As Per IMSI
 * @param  : uiImsi, key for search
 * @param  : li_config_t, structure to store retrived li_config
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
get_li_config(uint64_t uiImsi, struct li_df_config_t **li_config);

/**
 * @brief  : add id in imsi hash
 * @param  : uiId, key for search
 * @param  : uiImsi, IMSI
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
add_id_in_imsi_hash(uint64_t uiId, uint64_t uiImsi);

/**
 * @brief  : get id from imsi hash
 * @param  : uiImsi, key for search imsi
 * @param  : imsi_id_hash, structure for imsi id
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
get_id_using_imsi(uint64_t uiImsi, imsi_id_hash_t **imsi_id_hash);

/**
 * @brief  : fill li configuration in context
 * @param  : ue_context, context of ue
 * @param  : imsi_id_config, imsi to li id mapping
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_li_config_in_context(ue_context *context, imsi_id_hash_t *imsi_id_config);

#endif // __LI_CONFIG_H_
