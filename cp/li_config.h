#ifndef __LI_CONFIG_H_
#define __LI_CONFIG_H_

#include "pfcp_enum.h"
#include "gw_adapter.h"

extern struct rte_hash *li_df_by_imsi_hash;

/**
 * @brief  : Delete LI entry using imsi
 * @param  : uiImsi
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
del_li_imsi_entry(uint64_t uiImsi);

/**
 * @brief  : Fill LI config values
 * @param  : li_config_t, structure from which li_config is to be filled
 * @param  : uiCntr
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

#endif // __LI_CONFIG_H_
