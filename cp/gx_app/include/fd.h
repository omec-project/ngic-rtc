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

#ifndef __FD_H__
#define __FD_H__

#include <freeDiameter/freeDiameter-host.h>
#include <freeDiameter/libfdcore.h>
#include <freeDiameter/libfdproto.h>

/* TBD - create proper definition */
#define TRC2

#define FD_REASON_OK                     0
#define FD_REASON_CORE_INIT_FAIL         1
#define FD_REASON_PARSECONF_FAIL         2
#define FD_REASON_CORESTART_FAIL         3
#define FD_REASON_NOT_APPL               4
#define FD_REASON_DICT_GETVAL            5
#define FD_REASON_DICT_SEARCH            6
#define FD_REASON_REGISTER_CALLBACK      7
#define FD_REASON_REGISTER_APPLICATION   8
#define FD_REASON_MSG_SEND_FAIL          9
#define FD_REASON_MSG_ADD_ORIGIN_FAIL   10
#define FD_REASON_MSG_NEW_FAIL          11
#define FD_REASON_MSG_NEW_FAIL_APPL     12
#define FD_REASON_AVP_NEW_FAIL          13
#define FD_REASON_AVP_ADD_FAIL          14
#define FD_REASON_AVP_SETVALUE_FAIL     15
#define FD_REASON_BROWSE_FIRST_FAIL     16
#define FD_REASON_BROWSE_NEXT_FAIL      17

typedef struct fdAddress {
   uint16_t type;
   uint8_t address[16];
} FdAddress;

typedef time_t FdTime;

#define FDCHECK_FCT(a, b) \
   CHECK_FCT_DO(a, return b)

#define FDCHECK_FCT_2(a) \
{ \
   S16 __ret__ = a; \
   if (__ret__ != FD_REASON_NOT_APPL) \
      return __ret__; \
}

/*
 * FDCHECK_FCT_DICT_GETVAL(a, b, c, d)
 *    a - the dictionary entry object pointer
 *    b - pointer to structure to hold dictionary object
 *    c - the return value variable
 *    d - error code if failure detected
 */
#define FDCHECK_FCT_DICT_GETVAL(a, b, c, d) \
   CHECK_FCT_DO(fd_dict_getval(a,b), c = FD_REASON_DICT_GETVAL; d)

/*
 * FDCHECK_FCT_DICT(a, b, c, d, e, f)
 *    a - type of object that is being searched
 *    b - how the object must be searched
 *    c - name of the dictionary item
 *    d - the dictionary entry object pointer
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_FCT_DICT(a, b, c, d, e, f) \
   CHECK_FCT_DO(fd_dict_search(fd_g_config->cnf_dict, a, b, (void*)c, &d, ENOENT), e = FD_REASON_DICT_SEARCH; f)

/*
 * FDCHECK_FCT_REGISTER_CALLBACK(a, b, c, d)
 *    a - the callback function pointer to register
 *    b - the dictionary entry pointer to the command
 *    c - the return value variable
 *    d - error code if failure detected
 */
#define FDCHECK_FCT_REGISTER_CALLBACK(a, b, c, d) \
   data.command = b; \
   CHECK_FCT_DO(fd_disp_register(a, DISP_HOW_CC, &data, NULL, NULL), c = FD_REASON_REGISTER_CALLBACK; d)

/*
 * FDCHECK_FCT_REGISTER_APPLICATION(a, b, c, d)
 *    a - the dictionary entry pointer to the application
 *    b - the dictionary entry pointer to the vendor
 *    c - the return value variable
 *    d - error code if failure detected
 */
#define FDCHECK_FCT_REGISTER_APPLICATION(a, b, c, d) \
   CHECK_FCT_DO(fd_disp_app_support(a, b, 1, 0), c = FD_REASON_REGISTER_APPLICATION; d)

/*
 * FDCHECK_MSG_SEND(a, b, c, d, e)
 *    a - pointer to message to send
 *    b - answer callback function pointer
 *    c - answer callback data
 *    d - the return value variable
 *    e - error code if failure detected
 */
#define FDCHECK_MSG_SEND(a, b, c, d, e) \
   CHECK_FCT_DO(fd_msg_send(&a,b,c), d = FD_REASON_MSG_SEND_FAIL; e)

/*
 * FDCHECK_MSG_ADD_ORIGIN(a, b, c, d, e)
 *    a - message pointer
 *    b - the return value variable
 *    c - error code if failure detected
 */
#define FDCHECK_MSG_ADD_ORIGIN(a, b, c) \
   CHECK_FCT_DO(fd_msg_add_origin(a, 0), b = FD_REASON_MSG_ADD_ORIGIN_FAIL; c)

/*
 * FDCHECK_MSG_NEW(a, b, c, d)
 *    a - the dictionary entry pointer to the command to create
 *    b - message pointer variable
 *    c - the return value variable
 *    d - error code if failure detected
 */
#define FDCHECK_MSG_NEW(a, b, c, d) \
   CHECK_FCT_DO(fd_msg_new(a, MSGFL_ALLOC_ETEID, &b), c = FD_REASON_MSG_NEW_FAIL; d)

/*
 * FDCHECK_MSG_NEW_APPL(a, b, c, d, e)
 *    a - the dictionary entry pointer to the command to create
 *    b - the dictionary entry pointer to the application the command is associated with
 *    c - message pointer variable
 *    d - the return value variable
 *    e - error code if failure detected
 */
#define FDCHECK_MSG_NEW_APPL(a, b, c, d, e) \
   CHECK_FCT_DO(fd_msg_new_appl(a, b, MSGFL_ALLOC_ETEID, &c), d = FD_REASON_MSG_NEW_FAIL_APPL; e)

/*
 * FDCHECK_MSG_FREE(a)
 *    a - message pointer to free
 */
#define FDCHECK_MSG_FREE(a) \
{ \
   int __rval__ = fd_msg_free(a); \
   if (__rval__ != 0) \
      LOG_E("fd_msg_free(): unable to free the msg pointer (%d)", __rval__); \
}

/*
 * FDCHECK_MSG_NEW_ANSWER_FROM_REQ(a, b, c, d)
 *    a - dictionary pointer that contains the definition for the request
 *    b - request message pointer
 *    c - the return value variable
 *    d - error code if failure detected
 */
#define FDCHECK_MSG_NEW_ANSWER_FROM_REQ(a, b, c, d) \
   CHECK_FCT_DO(fd_msg_new_answer_from_req(a, &b, 0), c = FD_REASON_MSG_NEW_FAIL; d)

/*
 * FDCHECK_MSG_ADD_AVP_GROUPED_2(a, b, c, d, e, f)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - avp pointer to hold the created avp object
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_GROUPED_2(a, b, c, d, e, f) \
{ \
   struct avp * ___avp___; \
   CHECK_FCT_DO(fd_msg_avp_new(a, 0, &___avp___), e = FD_REASON_AVP_NEW_FAIL; f); \
   CHECK_FCT_DO(fd_msg_avp_add(b, c, ___avp___), e = FD_REASON_AVP_ADD_FAIL; f); \
   d = ___avp___; \
}

/*
 * FDCHECK_MSG_ADD_AVP_GROUPED(a, b, c, d, e)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the return value variable
 *    e - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_GROUPED(a, b, c, d, e) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_GROUPED_2(a, b, c, __avp__, d, e); \
   (void)__avp__; \
}

/*
 * FDCHECK_MSG_ADD_AVP(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the avp_value pointer
 *    e - avp pointer to hold the created avp object
 *    f - the return value variable
 *    g - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP(a, b, c, d, e, f, g) \
{ \
   struct avp * ___avp___; \
   CHECK_FCT_DO(fd_msg_avp_new(a, 0, &___avp___), f = FD_REASON_AVP_NEW_FAIL; g); \
   CHECK_FCT_DO(fd_msg_avp_setvalue(___avp___, d), f = FD_REASON_AVP_SETVALUE_FAIL; g); \
   CHECK_FCT_DO(fd_msg_avp_add(b, c, ___avp___), f = FD_REASON_AVP_ADD_FAIL; g); \
   e = ___avp___; \
}

/*
 * FDCHECK_MSG_ADD_AVP_OSTR_2(a, b, c, d, e, f, g, h)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - pointer to octet string value
 *    e - length of the octet string value
 *    f - avp pointer to hold the created avp object
 *    g - the return value variable
 *    h - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_OSTR_2(a, b, c, d, e, f, g, h) \
{ \
   union avp_value __val__; \
   __val__.os.data = (unsigned char *)d; \
   __val__.os.len = e; \
   FDCHECK_MSG_ADD_AVP(a, b, c, &__val__, f, g, h); \
}

/*
 * FDCHECK_MSG_ADD_AVP_OSTR(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - pointer to octet string value
 *    e - length of the octet string value
 *    f - the return value variable
 *    g - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_OSTR(a, b, c, d, e, f, g) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_OSTR_2(a, b, c, d, e, __avp__, f, g); \
   (void)__avp__;\
}

/*
 * FDCHECK_MSG_ADD_AVP_STR_2(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - pointer to the null terminated string value
 *    e - avp pointer to hold the created avp object
 *    f - the return value variable
 *    g - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_STR_2(a, b, c, d, e, f, g) \
{ \
   union avp_value val; \
   val.os.data = (unsigned char *)d; \
   val.os.len = strlen((const S8 *)d); \
   FDCHECK_MSG_ADD_AVP(a, b, c, &val, e, f, g); \
}

/*
 * FDCHECK_MSG_ADD_AVP_STR(a, b, c, d, e, f)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - pointer to the null terminated string value
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_STR(a, b, c, d, e, f) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_STR_2(a, b, c, d, __avp__, e, f); \
   (void)__avp__;\
}

/*
 * FDCHECK_MSG_ADD_AVP_S32_2(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the int32_t value
 *    e - avp pointer to hold the created avp object
 *    f - the return value variable
 *    g - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_S32_2(a, b, c, d, e, f, g) \
{ \
   union avp_value val; \
   val.i32 = d; \
   FDCHECK_MSG_ADD_AVP(a, b, c, &val, e, f, g); \
}

/*
 * FDCHECK_MSG_ADD_AVP_S32(a, b, c, d, e, f)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the int32_t value
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_S32(a, b, c, d, e, f) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_S32_2(a, b, c, d, __avp__, e, f); \
   (void)__avp__; \
}

/*
 * FDCHECK_MSG_ADD_AVP_U32_2(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the uint32_t value
 *    e - avp pointer to hold the created avp object
 *    f - the return value variable
 *    g - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_U32_2(a, b, c, d, e, f, g) \
{ \
   union avp_value val; \
   val.u32 = d; \
   FDCHECK_MSG_ADD_AVP(a, b, c, &val, e, f, g); \
}

/*
 * FDCHECK_MSG_ADD_AVP_U32(a, b, c, d, e, f)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the uint32_t value
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_U32(a, b, c, d, e, f) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_U32_2(a, b, c, d, __avp__, e, f); \
   (void)__avp__; \
}

/*
 * FDCHECK_MSG_ADD_AVP_TIME_2(a, b, c, d, e, f, g)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the time_t value
 *    e - avp pointer to hold the created avp object
 *    f - the return value variable
 *    g - error code if failure detected
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define FDCHECK_MSG_ADD_AVP_TIME_2(a, b, c, d, e, f, g) \
{ \
   union avp_value val; \
   union { \
       uint32_t u32; \
       uint8_t u8[sizeof(uint32_t)]; \
   } t; \
   t.u32 = (uint32_t)(d + 220898800UL); \
   uint8_t u8; \
   u8 = t.u8[0]; t.u8[0] = t.u8[3]; t.u8[3] = u8; \
   u8 = t.u8[1]; t.u8[1] = t.u8[2]; t.u8[2] = u8; \
   val.os.data = t.u8; \
   val.os.len = sizeof(uint32_t); \
   FDCHECK_MSG_ADD_AVP(a, b, c, &val, e, f, g); \
}
#else
#define FDCHECK_MSG_ADD_AVP_TIME_2(a, b, c, d, e, f, g) \
{ \
   union avp_value val; \
   union { \
       uint32_t u32; \
       uint8_t u8[sizeof(uint32_t)]; \
   } t; \
   t.u32 = (uint32_t)(d + 220898800UL); \
   val.os.data = t.u8; \
   val.os.len = sizeof(uint32_t); \
   FDCHECK_MSG_ADD_AVP(a, b, c, &val, e, f, g); \
}
#endif

/*
 * FDCHECK_MSG_ADD_AVP_TIME(a, b, c, d, e, f)
 *    a - the avp dictionary entry pointer
 *    b - avp or msg pointer to add the avp to
 *    c - location where the avp should be inserted (usually MSG_BRW_LAST_CHILD)
 *    d - the time_t value
 *    e - the return value variable
 *    f - error code if failure detected
 */
#define FDCHECK_MSG_ADD_AVP_TIME(a, b, c, d, e, f) \
{ \
   struct avp * __avp__; \
   FDCHECK_MSG_ADD_AVP_TIME_2(a, b, c, d, __avp__, e, f); \
   (void)__avp__; \
}

/*
 * FDCHECK_MSG_FIND_AVP(a, b, c, d)
 *    a - the msg pointer to search
 *    b - the dictionary entry pointer for the avp to search
 *    c - location where the AVP reference will be stored
 *    d - fallback (what to do if there is an error)
 */
#define FDCHECK_MSG_FIND_AVP(a, b, c, d) \
{ \
   if (fd_msg_search_avp(a, b, &c) != 0) \
   { \
      d; \
   } \
}

/*
 * FDCHECK_AVP_GET_HDR(a, b, c, d)
 *    a - the dictionary entry pointer for the avp
 *    b - the avp pointer
 *    c - the avp header pointer to populate
 *    d - fallback (what to do if there is an error)
 */
#define FDCHECK_AVP_GET_HDR(a, b, c, d) \
{ \
   if (fd_msg_avp_hdr(b,&c) != 0) { \
      struct dict_avp_data * __deval__ = NULL; \
      fd_dict_getval(a, &__deval__); \
      LOG_E("fd_msg_avp_hdr(): unable to retrieve avp header for [%s]", __deval__ ? __deval__->avp_name : ""); \
      d; \
   } \
}

/*
 * FDCHECK_AVP_GET_S32(a, b, c, d)
 *    a - the dictionary entry pointer for the avp
 *    b - the avp pointer
 *    c - the int32_t variable to populate
 *    d - fallback (what to do if there is an error)
 */
#define FDCHECK_AVP_GET_S32(a, b, c, d) \
{ \
   struct avp_hdr *__hdr__= NULL; \
   FDCHECK_AVP_GET_HDR(a, b, __hdr__, d); \
   c = __hdr__->avp_value->i32; \
}

/*
 * FDCHECK_AVP_GET_U32(a, b, c, d)
 *    a - the dictionary entry pointer for the avp
 *    b - the avp pointer
 *    c - the uint32_t variable to populate
 *    d - fallback (what to do if there is an error)
 */
#define FDCHECK_AVP_GET_U32(a, b, c, d) \
{ \
   struct avp_hdr *__hdr__= NULL; \
   FDCHECK_AVP_GET_HDR(a, b, __hdr__, d); \
   c = __hdr__->avp_value->u32; \
}

/*
 * FD_ALLOC_LIST(a, b)
 *    a - pointer to the list structure
 *    b - type of the list structure
 */
#define FD_ALLOC_LIST(a, b) \
{ \
   if (a.count > 0) { \
      a.list = (b*)malloc( sizeof(*a.list) * a.count ); \
      memset( a.list, 0, sizeof(*a.list) * a.count ); \
      a.count = 0; \
   } \
}

/*
 * FD_CALLFREE_STRUCT(a, b)
 *    a - pointer to the structure to free
 *    b - free structure function pointer
 */
#define FD_CALLFREE_STRUCT(a, b) \
   b( &a );

/*
 * FD_CALLFREE_LIST(a, b)
 *    a - pointer to the list structure that each list element will have the free structure function called
 *    b - free structure function pointer
 */
#define FD_CALLFREE_LIST(a, b) \
{ \
   int __idx__; \
   if (a.list) { \
      for (__idx__ = 0; __idx__ < a.count; __idx__++) \
         FD_CALLFREE_STRUCT( a.list[__idx__], b ); \
   } \
}

/*
 * FD_FREE_LIST(a)
 *    a - pointer to the list structure to free
 */
#define FD_FREE_LIST(a) \
{ \
   if (a.list) { \
      free(a.list); \
      a.list = NULL; \
   } \
   a.count = 0; \
}

/*
 * FD_DUMP_MESSAGE(a)
 *    a - msg or avp pointer that will be printed
 */
#define FD_DUMP_MESSAGE(a) \
{ \
   char * buf = NULL; \
   size_t len = 0; \
   printf("%s\n", fd_msg_dump_treeview(&buf, &len, NULL, a, fd_g_config->cnf_dict, 0, 1)); \
   free(buf); \
}

static inline int fdmin(int lval, int rval) { return lval < rval ? lval : rval; }

/*
 * FD_PARSE_OCTETSTRING(a, b, c)
 *    a - pointer to the avp_value
 *    b - pointer to the destination list structure
 *    c - max length of the destinaltion buffer
 */
#define FD_PARSE_OCTETSTRING(a, b, c) \
{ \
   b.len = fdmin(a->os.len, c); \
   memcpy(b.val, a->os.data, b.len); \
}

/*
 * FD_PARSE_TIME(a, b)
 *    a - pointer to the avp_value
 *    b - variable where the resulting time_t value will be stored
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define FD_PARSE_TIME(a, b) \
{ \
   union { \
      uint32_t u32; \
      uint8_t u8[sizeof(uint32_t)]; \
   } _val; \
   _val.u32 = *(uint32_t*)a->os.data; \
   uint8_t u8; \
   u8 = _val.u8[0]; _val.u8[0] = _val.u8[3]; _val.u8[3] = u8; \
   u8 = _val.u8[1]; _val.u8[1] = _val.u8[2]; _val.u8[2] = u8; \
   b = ((FdTime)_val.u32) - (FdTime)2208988800; \
}
#else
#define FD_PARSE_TiME(a, b) \
{ \
   union { \
      uint32_t u32; \
      uint8_t u8[sizeof(uint32_t)]; \
   } _val; \
   _val.u32 = *(uint32_t*)a->os.data; \
   b = ((FdTime)_val.u32) - (FdTime)2208988800; \
}
#endif

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define FD_NETWORK_TO16(a) ((a[0] << 8) | a[1])
#else
#define FD_NETWORK_TO16(a) ((a[1] << 8) | a[0])
#endif

/*
 * FD_PARSE_ADDRESS(a, b)
 *    a - pointer to the avp_value
 *    b - FdAddress variable where the resulting address value will be stored
 */
#define FD_PARSE_ADDRESS(a, b) \
{ \
   memset(&b, 0, sizeof(b)); \
   b.type = FD_NETWORK_TO16( a->os.data ); \
   memcpy( b.address, &a->os.data[2], a->os.len - 2 ); \
}

/* FDCHECK_PARSE_DIRECT( function_name, struct avp *, pointer to structure to populate ) */
/*
 * FDCHECK_PARSE_DIRECT(a, b)
 *    a - parsing function pointer that will be called
 *    b - avp pointer to the grouped avp that will be parsed
 *    c - pointer to the destination structure that will be populated
 */
#define FDCHECK_PARSE_DIRECT(a,b,c) \
{ \
   int __ret__ = a(b,c); \
   if (__ret__ != FD_REASON_OK) \
      return __ret__; \
}

#define FD_LOW_NIBBLE(b) (b & 0x0f)
#define FD_HIGH_NIBBLE(b) (AQFD_LOW_NIBBLE(b >> 4))

#define FD_CHAR2TBCD(c) \
( \
   c >= '0' && c <= '9' ? c - '0' : \
   c == '*' ? 10 : \
   c == '#' ? 11 : \
   c == 'a' ? 12 : \
   c == 'b' ? 13 : \
   c == 'c' ? 14 : 15 \
)

#endif /* __FD_H__ */
