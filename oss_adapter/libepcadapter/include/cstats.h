/*
 * Copyright (c) 2019 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __CSTATS_H
#define __CSTATS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "gw_structs.h"

/* Function */
/**
 * @brief: intializing statstics timer
 * @param: void
 * @return: nothing
 */
void statTimerInit(void);
/* Function */
/**
 * @brief: get interval
 * @param: response
 * @return: sucess code
 */
int csGetInterval(char **response);
/* Function */
/**
 * @brief: get stats logging
 * @param: response
 * @return: sucess code
 */
int csGetStatLogging(char **response);
/* Function */
/**
 * @brief: update stats logging
 * @param: json value
 * @param: response
 * @return: on sucess return sucess code and on fail return error code
 */
int csUpdateStatLogging(const char *json, char **response);
/* Function */
/**
 * @brief: update interval frequency
 * @param: json value
 * @param: response
 * @return: on sucess return sucess code and on fail return error code
 */
int csUpdateInterval(const char *json, char **response);
/* Function */
/**
 * @brief: get stats live
 * @param: response
 * @return: sucess code
 */
int csGetLive(char **response);
/* Function */
/**
 * @brief: all gateway supported stats
 * @param: response
 * @return: sucess code
 */
int csGetLiveAll(char **response);
/* Function */
/**
 * @brief: reset the stats
 * @param: json value
 * @param: response
 * @return: on sucess return sucess code and on fail return error code
 */
int csResetStats(const char *json, char **response);
/* Function */
/**
 * @brief: cli intialization
 * @param: command line interface node
 * @param: peer count
 * @return: nothing
 */
void cli_init(cli_node_t *cli_node, int *cnt_peer);
/* Function */
/**
 * @brief: get number of request tries
 * @param: response
 * @param: request tries
 * @return: sucess code
 */
int get_number_of_request_tries(char **response, int request_tries);
/* Function */
/**
 * @brief: get transmit count value
 * @param: response
 * @param: transmit count value
 * @return: sucess code
 */
int get_number_of_transmit_count(char **response, int transmit_count);
/* Function */
/**
 * @brief: get transmit timer value
 * @param: response
 * @param: transmit timer value
 * @return: sucess code
 */
int get_transmit_timer_value(char **response, int transmit_timer_value);
/* Function */
/**
 * @brief: get periodic value
 * @param: response
 * @param: periodic  value
 * @return: sucess code
 */
int get_periodic_timer_value(char **response, int periodic_timer_value);
/* Function */
/**
 * @brief: get request timeout value
 * @param: response
 * @param: request timeout value
 * @return: sucess code
 */
int get_request_timeout_value(char **response, int request_timeout);
/* Function */
/**
 * @brief: get perf flag json resp
 * @param: response
 * @param: perf flag value
 * @return: sucess code
 */
int get_perf_flag_json_resp(char **response, int perf_flag);
/* Function */
/**
 * @brief: get request tries value
 * @param: json value
 * @param: response
 * @return: request tries value
 */
int get_request_tries_value(const char *json, char **response);
/* Function */
/**
 * @brief: get transmit count value
 * @param: json value
 * @param: response
 * @return: transmit count
 */
int get_transmit_count_value(const char *json, char **response);
/* Function */
/**
 * @brief: get request timeout value
 * @param: json value
 * @param: response
 * @return: request timeout value
 */
int get_request_timeout_value_in_milliseconds(const char *json, char **response);
/* Function */
/**
 * @brief: get transmit value
 * @param: json value
 * @param: response
 * @return: transmit timer value in sec
 */
int get_transmit_timer_value_in_seconds(const char *json, char **response);
/* Function */
/**
 * @brief: get  perf flag value
 * @param: json value
 * @param: response
 * @return: perf flag value in 0 or 1
 */
int get_perf_flag_value_in_int(const char *json, char **response);
/* Function */
/**
 * @brief: get  periodic value
 * @param: json value
 * @param: response
 * @return: periodic timer value in sec
 */
int get_periodic_timer_value_in_seconds(const char *json, char **response);
/* Function */
/**
 * @brief: to construct json
 * @param: parameter name
 * @param: parameter set value
 * @return: nothing
 */
void construct_json(const char *param,const char *value, char *buf);
/* Function */
/**
 * @brief: return error response if cmd not supported
 * @param: gateway type
 * @param: response
 * @return: return error code
 */
int resp_cmd_not_supported(uint8_t gw_type, char **response);
/* Function */
/**
 * @brief: return error response if post invalid value
 * @param: json
 * @param: response
 * @return: return error code
 */
int invalid_value_error_response(const char *json, char **response);
/* Function */
/**
 * @brief: return error response if post invalid json string
 * @param: json
 * @param: response
 * @return: return rest code
 */
int check_valid_json(const char *json, char **response);
/* Function */
/**
 * @brief: get pcap generation status.
 * @param: response
 * @param: pcap_gen_status, status of pcap generation.
 * @return: return error code
 */
int get_pcap_generation_status(char **response, uint8_t pcap_gen_status);
/* Function */
/**
 * @brief: get pcap generation command value.
 * @param: json, json data.
 * @param: response, response vlue.
 * @return: return error code
 */
int get_pcap_generation_cmd_value(const char *json, char **response);
/* Function */
/**
 * @brief: get cp configuration
 * @param: response
 * @param: cp config structure pointer
 * @return: return rest status
 */
int get_cp_configuration(char **response, cp_configuration_t *cp_config_ptr);
/* Function */
/**
 * @brief: get dp configuration
 * @param: response
 * @param: dp config structure pointer
 * @return: return rest status
 */
int get_dp_configuration(char **response, dp_configuration_t *dp_config_ptr);

#ifdef __cplusplus
}
#endif

#endif /* __CSTATS_H */
