/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _MASTER_CDR_H
#define _MASTER_CDR_H
/**
 * @file
 * This file contains function prototypes for the CDR master record
 */

#include "cdr.h"

/**
 * sets the master cdr file
 * @param master_cdr_file
 */
void
set_master_cdr_file(const char *master_cdr_file);

/**
 * finalizes *.cur cdr files into *.csv and records into the master cdr file
 * @param cdr_path
 */
void
finalize_cur_cdrs(const char *cdr_path);

/**
 * @brief frees all memory allocated by master_cdr.c
 */
void
free_master_cdr(void);

#endif /* _MASTER_H */
