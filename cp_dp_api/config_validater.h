/*
 * Copyright (c) 2020 Sprint
 * Copyright (c) 2020 T-Mobile
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

#define KEY_LEN 32
#define CFG_VALUE_LENGTH 64
#define KEY_NOT_FOUND 1
#define VALUE_FORMAT_NOT_CORRECT 2
#define BUFFER_SIZE 256
#define STARTING_INDEX 0
#define IPV4_LEN 16
#define IPV6_LEN 24
#define MAC_ADDRESS_LEN 12
#define MAC_ADDRESS_SEPARTER 5

#define CP_CFG_PATH "../config/cp.cfg"
#define DP_CFG_PATH "../config/dp.cfg"

typedef struct {
	const char *key;
	const char *value;
	int (*fun_ptr)(char *, char *);
} cfg_data;

typedef struct {
	const char *section_name;
} section;

/**
 * @brief  : validate the integer
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_integer(char *key, char *value);

/**
 * @brief  : validate the ipv4 pattern
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_ipv4(char *key, char *value);

/**
 * @brief  : validate the ipv4/ipv6 pattern
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_ipv4v6(char *key, char *value);

/**
 * @brief  : validate the ipv6 pattern
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_ipv6(char *key, char *value);

/**
 * @brief  : validate the ipv4/ipv6 pattern
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_ipv4_ipv6(char *key, char *value);

/**
 * @brief  : validate the mac address
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_mac(char *key, char *value);

/**
 * @brief  : validate the string patterns
 * @param  : key, value
 * @return : Returns 0 successfull else error code
 */
int is_valid_string(char *key, char *value);

/**
 * @brief  : validate the integer
 * @param  : value
 * @return : Returns 0 successfull else error code
 */
int is_valid_apn(char *value);

/**
 * @brief  : validate the alphanumeric value
 * @param  : value
 * @return : Returns 0 successfull else error code
 */
int is_valid_alphanumeric_value(char *value);

/**
 * @brief  : validate the alpha value
 * @param  : value
 * @return : Returns 0 successfull else error code
 */
int is_valid_alpha_value(char *value);

/**
 * @brief  : validate the interface value
 * @param  : value
 * @return : Returns 0 successfull else error code
 */
int is_valid_interface(char *value);

/**
 * @brief  : read cfg file and perform validation
 * @param  : path
 * @return : Returns nothing
 */
void read_cfg_file(const char *path);
