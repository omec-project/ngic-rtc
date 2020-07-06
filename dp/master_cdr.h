/*
 * Copyright (c) 2017 Intel Corporation
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

#ifndef _MASTER_CDR_H
#define _MASTER_CDR_H
/**
 * @file
 * This file contains function prototypes for the CDR master record
 */

#include "cdr.h"


/**
 * @brief  : sets the master cdr file
 * @param  : master_cdr_file, master cdr filepath
 * @return : Returns nothing
 */
void
set_master_cdr_file(const char *master_cdr_file);

/**
 * @brief  : finalizes *.cur cdr files into *.csv and records into the master cdr file
 * @param  : cdr_path
 * @return : Returns nothing
 */
void
finalize_cur_cdrs(const char *cdr_path);

/**
 * @brief  : frees all memory allocated by master_cdr.c
 * @param  : No param
 * @return : Returns nothing
 */
void
free_master_cdr(void);

#endif /* _MASTER_H */
