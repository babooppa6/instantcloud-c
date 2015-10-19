#include "cloud.h"
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <curl/curl.h>

#define DEFAULT_PORT   80
#define MAX_STRLEN 5000

char baseurl[] = "https://cloud.gurobi.com/api";
char accessid[ACCESS_ID_LEN+1];
char secretkey[SECRET_KEY_LEN+1];

#define SIG_LEN 28

static const char region_data[NUM_REGIONS][MAX_REGION_LEN+1] = \
  { REGION_US_EAST_1,
    REGION_US_WEST_1,
    REGION_US_WEST_2,
    REGION_EU_CENTRAL_1,
    REGION_EU_WEST_1,
    REGION_AP_NORTHEAST_1,
    REGION_AP_SOUTHEAST_1,
    REGION_AP_SOUTHEAST_2};
static const char machine_data[NUM_MACHINE_TYPE][MAX_MACHINE_LEN+1] = \
  { MACHINE_C4_LARGE,
    MACHINE_C4_2XLARGE,
    MACHINE_C4_4XLARGE,
    MACHINE_C4_8XLARGE,
    MACHINE_R3_8XLARGE };
static const char \
machine_state_data[NUM_MACHINE_STATE][MAX_STATE_LEN+1] = \
    { STATE_LAUNCHING,
      STATE_PENDING,
      STATE_OBTAINING_LICENSE,
      STATE_IDLE,
      STATE_RUNNING,
      STATE_KILLING,
      STATE_SHUTTING_DOWN,
      STATE_LAUNCH_ERROR };

static const char \
license_type_data[NUM_CLOUD_LICENSE_TYPE][MAX_LICENSE_TYPE_LEN+1] = \
  { LICENSE_FULL_COMPUTE_SERVER,
    LICENSE_LIGHT_COMPUTE_SERVER,
    LICENSE_DISTRIBUTED_WORKER };

static const char \
license_type_encode[NUM_CLOUD_LICENSE_TYPE][24+1] = \
  { "full%20compute%20server",
    "light%20compute%20server",
    "distributed%20worker" };


static int sendcommand(const char *command, char *postfields, char *timestr,
                       char *signature, char *response);

/* JSMN JSON parser from http://zserge.bitbucket.org/jsmn.html */

/**
 * JSON type identifier. Basic types are:
 * o Object
 * o Array
 * o String
 * o Other primitive: number, boolean (true/false) or null
 */
typedef enum {
  JSMN_PRIMITIVE = 0,
  JSMN_OBJECT = 1,
  JSMN_ARRAY = 2,
  JSMN_STRING = 3
} jsmntype_t;

typedef enum {
  /* Not enough tokens were provided */
  JSMN_ERROR_NOMEM = -1,
  /* Invalid character inside JSON string */
  JSMN_ERROR_INVAL = -2,
  /* The string is not a full JSON packet, more bytes expected */
  JSMN_ERROR_PART = -3
} jsmnerr_t;

/**
 * JSON token description.
 * @paramtypetype (object, array, string etc.)
 * @paramstartstart position in JSON data string
 * @paramendend position in JSON data string
 */
typedef struct {
  jsmntype_t type;
  int start;
  int end;
  int size;
#ifdef JSMN_PARENT_LINKS
  int parent;
#endif
} jsmntok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string
 */
typedef struct {
  unsigned int pos; /* offset in the JSON string */
  unsigned int toknext; /* next token to allocate */
  int toksuper; /* superior token node, e.g parent object or array */
} jsmn_parser;

/**
 * Create JSON parser over an array of tokens
 */
static void jsmn_init(jsmn_parser *parser);

/**
 * Run JSON parser. It parses a JSON data string into and array of tokens, each describing
 * a single JSON object.
 */
static jsmnerr_t jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
                     jsmntok_t *tokens, unsigned int num_tokens);


/* hmac sha1 from http://oauth.googlecode.com/svn/code/c/liboauth/src/sha1.c */

#define MAX_MESSAGE_LENGTH 4096


#ifdef WIN32
#define __LITTLE_ENDIAN__
#endif

#ifdef __BIG_ENDIAN__
# define SHA_BIG_ENDIAN
#elif defined __LITTLE_ENDIAN__
/* override */
#elif defined __BYTE_ORDER
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define SHA_BIG_ENDIAN
# endif
#else /* ! defined __LITTLE_ENDIAN__ */
# include <endian.h> /* machine/endian.h */
# if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
#  define SHA_BIG_ENDIAN
# endif
#endif


/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

typedef struct sha1nfo {
  uint32_t buffer[BLOCK_LENGTH/4];
  uint32_t state[HASH_LENGTH/4];
  uint32_t byteCount;
  uint8_t bufferOffset;
  uint8_t keyBuffer[BLOCK_LENGTH];
  uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

static void sha1_init(sha1nfo *s);
static void sha1_writebyte(sha1nfo *s, uint8_t data);
static void sha1_write(sha1nfo *s, const char *data, size_t len);
static uint8_t* sha1_result(sha1nfo *s);
static void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);
static uint8_t* sha1_resultHmac(sha1nfo *s);

#define SHA1_K0  0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

static void
sha1_init(sha1nfo *s)
{
  s->state[0] = 0x67452301;
  s->state[1] = 0xefcdab89;
  s->state[2] = 0x98badcfe;
  s->state[3] = 0x10325476;
  s->state[4] = 0xc3d2e1f0;
  s->byteCount = 0;
  s->bufferOffset = 0;
}

static uint32_t
sha1_rol32(uint32_t number,
           uint8_t  bits)
{
  return ((number << bits) | (number >> (32-bits)));
}

static void
sha1_hashBlock(sha1nfo *s)
{
  uint8_t i;
  uint32_t a,b,c,d,e,t;

  a=s->state[0];
  b=s->state[1];
  c=s->state[2];
  d=s->state[3];
  e=s->state[4];
  for (i=0; i<80; i++) {
    if (i>=16) {
      t = s->buffer[(i+13)&15] ^ s->buffer[(i+8)&15] ^ s->buffer[(i+2)&15] ^ s->buffer[i&15];
      s->buffer[i&15] = sha1_rol32(t,1);
    }
    if (i<20) {
      t = (d ^ (b & (c ^ d))) + SHA1_K0;
    } else if (i<40) {
      t = (b ^ c ^ d) + SHA1_K20;
    } else if (i<60) {
      t = ((b & c) | (d & (b | c))) + SHA1_K40;
    } else {
      t = (b ^ c ^ d) + SHA1_K60;
    }
    t+=sha1_rol32(a,5) + e + s->buffer[i&15];
    e=d;
    d=c;
    c=sha1_rol32(b,30);
    b=a;
    a=t;
  }
  s->state[0] += a;
  s->state[1] += b;
  s->state[2] += c;
  s->state[3] += d;
  s->state[4] += e;
}

static void
sha1_addUncounted(sha1nfo *s,
                  uint8_t data)
{
  uint8_t * const b = (uint8_t*) s->buffer;
#ifdef SHA_BIG_ENDIAN
  b[s->bufferOffset] = data;
#else
  b[s->bufferOffset ^ 3] = data;
#endif
  s->bufferOffset++;
  if (s->bufferOffset == BLOCK_LENGTH) {
    sha1_hashBlock(s);
    s->bufferOffset = 0;
  }
}

static void
sha1_writebyte(sha1nfo *s,
               uint8_t  data) {
  ++s->byteCount;
  sha1_addUncounted(s, data);
}

static void
sha1_write(sha1nfo    *s,
           const char *data,
           size_t      len)
{
  for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

static void
sha1_pad(sha1nfo *s)
{
  /* Implement SHA-1 padding */

  /* Pad with 0x80 followed by 0x00 until the end of the block */
  sha1_addUncounted(s, 0x80);
  while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

  /* Append length in the last 8 bytes */
  sha1_addUncounted(s, 0); /* We're only using 32 bit lengths */
  sha1_addUncounted(s, 0); /* But SHA-1 supports 64 bit lengths */
  sha1_addUncounted(s, 0); /* So zero pad the top bits */
  sha1_addUncounted(s, s->byteCount >> 29); /* Shifting to multiply by 8 */
  sha1_addUncounted(s, s->byteCount >> 21); /* as SHA-1 supports bitstreams as well as */
  sha1_addUncounted(s, s->byteCount >> 13); /* byte. */
  sha1_addUncounted(s, s->byteCount >> 5);
  sha1_addUncounted(s, s->byteCount << 3);
}

static uint8_t*
sha1_result(sha1nfo *s)
{
  int i;
  /* Pad to complete the last block */
  sha1_pad(s);

#ifndef SHA_BIG_ENDIAN
  /* Swap byte order back */

  for (i=0; i<5; i++) {
    s->state[i]=
      (((s->state[i])<<24)& 0xff000000)
      | (((s->state[i])<<8) & 0x00ff0000)
      | (((s->state[i])>>8) & 0x0000ff00)
      | (((s->state[i])>>24)& 0x000000ff);
  }
#endif

  /* Return pointer to hash (20 characters) */
  return (uint8_t*) s->state;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

static void
sha1_initHmac(sha1nfo       *s,
              const uint8_t* key,
              int            keyLength)
{
  uint8_t i;
  memset(s->keyBuffer, 0, BLOCK_LENGTH);
  if (keyLength > BLOCK_LENGTH) {
    /* Hash long keys */
    sha1_init(s);
    for (;keyLength--;) sha1_writebyte(s, *key++);
    memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
  } else {
    /* Block length keys are used as is */
    memcpy(s->keyBuffer, key, keyLength);
  }
  /* Start inner hash */
  sha1_init(s);
  for (i=0; i<BLOCK_LENGTH; i++) {
    sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
  }
}

static uint8_t*
sha1_resultHmac(sha1nfo *s) {
  uint8_t i;
  /* Complete inner hash */
  memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
  /* Calculate outer hash */
  sha1_init(s);
  for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
  for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
  return sha1_result(s);
}

/* self-test */
#ifdef VERBOSE
static void
printHash(uint8_t* hash) {
  int i;
  for (i=0; i<20; i++) {
    if (i > 0) printf(":");
    printf("%02x", hash[i]);
  }
  printf("\n");
}
#endif


static void
getISO8601(char *time_str)
{
  time_t now;
  time(&now);

  /* 2011-10-08T07:07:09Z
     01234567890123456789 */
  strftime(time_str, 21, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

}

static const char b64_table[] = \
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static int
b64_encode(const char *input,
           int         len,
           char       *output,
           int         buf_len)
{
  int i, j, b, out_len;

  out_len = (len / 3) * 4;
  if (out_len >= buf_len) {
    return -1;
  }
  j = 0;
  for (i = 0; i < len; i += 3) {
    b = (input[i] & 0xFC) >> 2;
    output[j++] = b64_table[b];
    b = (input[i] & 0x03) << 4;
    if (i + 1 < len) {
      b |= (input[i+1] & 0xF0) >> 4;
      output[j++] = b64_table[b];
      b = (input[i+1] & 0x0F) << 2;
      if (i + 2 < len) {
        b |= (input[i+2] & 0xC0) >> 6;
        output[j++] = b64_table[b];
        b =  input[i+2] & 0x3F;
        output[j++] = b64_table[b];
      } else {
        output[j++] = b64_table[b];
        output[j++] = '=';
      }
    } else {
      output[j++] = b64_table[b];
      output[j++] = '=';
      output[j++] = '=';
    }
  }
  return 0;
}


int
ICgetlicenses(int              *num_licenseP,
              ICcloudlicense   *licenses)
{
  char request[MAX_STRLEN+1];
  char response[MAX_STRLEN+1];
  char timestr[MAX_STRLEN+1];
  char digest[MAX_STRLEN+1];
  char signature[SIG_LEN+1];
  char *endpoint = "licenses";
  char command[MAX_STRLEN+1];
  sha1nfo s;
  jsmn_parser parser;
  jsmntok_t tokens[256];
  int         jsmn_ret;
  jsmntok_t *t;
  int  num_license  = -1;
  int  found_credit = 0;
  int  found_lic_id = 0;
  int  found_exp    = 0;
  int  found_rate   = 0;
  int  i;
  int error = 0;


  if (!(strlen(accessid) == ACCESS_ID_LEN   &&
        strlen(secretkey) == SECRET_KEY_LEN   )) {
    error = ERROR_INVALID_ARGUMENT;
    goto QUIT;
  }

  sprintf(command, "%s/%s?id=%s", baseurl, endpoint, accessid);
#ifdef VERBOSE
  printf("command %s\n", command);
#endif

  getISO8601(timestr);
  sprintf(request, "GET&id=%s&%s", accessid, timestr);

  sha1_init(&s);
  sha1_initHmac(&s, (unsigned char *) secretkey, 43);
  sha1_write(&s, request, strlen(request));
  memcpy(digest, sha1_resultHmac(&s), 20);
  digest[20] = 0;
#ifdef VERBOSE
  printf("digest ");
  printHash((uint8_t *)digest);
#endif

  b64_encode(digest, 20, signature, SIG_LEN);
  signature[SIG_LEN] = '\0';

#ifdef VERBOSE
  printf("request %s\n", request);
  printf("timestr %s\n", timestr);
  printf("signature %s\n", signature);
#endif

  error = sendcommand(command, NULL, timestr, signature, response);
  if (error) goto QUIT;

#ifdef VERBOSE
  printf("response %s\n", response);
#endif

  jsmn_init(&parser);

  jsmn_ret = jsmn_parse(&parser, response, strlen(response), tokens, 256);
  if (jsmn_ret < 0) {
    printf("jsmn_error %d\n", jsmn_ret);
    error = ERROR_NETWORK;
    goto QUIT;
  }

  for (i = 0; i < jsmn_ret; i++) {
    char buff[128];
    int  size;
    t = &tokens[i];
    if (t->type == JSMN_ARRAY) /* Ignore enclosing array */
      continue;
    if (t->type == JSMN_OBJECT) {
      num_license++;
      continue;
    }
    if (t->type == JSMN_STRING && licenses) {
      size = (t->end - t->start);
      memcpy(buff, &response[t->start], sizeof(char)*size);
      buff[size] = 0;
#ifdef VERBOSE
      printf("str: %s\n", buff);
#endif
      if (found_credit) {
        licenses[num_license].credit = strtod(buff, NULL);
        found_credit = 0;
      } else if (found_lic_id) {
        sscanf(buff, "%d", &(licenses[num_license].license_id));
        found_lic_id = 0;
      } else if (found_exp) {
        memcpy(licenses[num_license].expiration, buff, sizeof(char)*(size+1));
        found_exp = 0;
      } else if (found_rate) {
        memcpy(licenses[num_license].rate_plan, buff, sizeof(char)*(size+1));
        found_rate = 0;
      } else if (strcmp(buff, "credit") == 0) {
        found_credit = 1;
      } else if (strcmp(buff, "licenseId") == 0) {
        found_lic_id = 1;
      } else if (strcmp(buff, "expiration") == 0) {
        found_exp = 1;
      } else if (strcmp(buff, "ratePlan") == 0) {
        found_rate = 1;
      }
    }
  }

  if (num_licenseP) {
    *num_licenseP = num_license + 1;
  }


QUIT:

  return error;
}

static int
getmachineinfo(char           *response,
               ICmachineinfo **machine_infoP)
{
  jsmn_parser parser;
  jsmntok_t tokens[256];
  int         jsmn_ret;
  jsmntok_t *t;
  ICmachineinfo *machine_info = NULL;
  ICmachine     *machines     = NULL;
  int  num_machines = 0;
  int  id_found = 0;
  int  state_found = 0;
  int  dns_name_found = 0;
  int  machine_found = 0;
  int  time_found = 0;
  int  region_found = 0;
  int  lic_type_found = 0;
  int  idle_found = 0;
  int  lic_found = 0;
  int  password_found = 0;
  char buff[128];
  int  size;
  int  flag;
  int  i;
  int  j;
  int  error = 0;

  jsmn_init(&parser);

  jsmn_ret = jsmn_parse(&parser, response, strlen(response), tokens, 256);
  if (jsmn_ret < 0) {
    error = ERROR_NETWORK;
    printf("getmachine info error in jsmn_parse\n");
    goto QUIT;
  }


  /* Count the number of machines we have */

  for (i = 0; i < jsmn_ret; i++) {
    t = &tokens[i];
    if (t->type == JSMN_OBJECT) {
      num_machines++;
    }
  }

  /* Alloc machine info */
  MALLOC(machine_info, 1);
  MALLOC(machine_info->machines, num_machines);
  MALLOC(machine_info->machine_ids, num_machines);
  for (i = 0; i < num_machines; i++) {
    MALLOC(machine_info->machine_ids[i], sizeof(char)*(MAX_ID_LEN+1));
  }

  machines = machine_info->machines;
  *machine_infoP = machine_info;

  num_machines = -1;
  for (i = 0; i < jsmn_ret; i++) {
    t = &tokens[i];
    if (t->type == JSMN_ARRAY) /* Ignore enclosing array */
      continue;
    if (t->type == JSMN_OBJECT) {
      num_machines++;
      continue;
    }
    if (t->type == JSMN_STRING) {
      size = (t->end - t->start);
      memcpy(buff, &response[t->start], sizeof(char)*size);
      buff[size] = 0;
#ifdef VERBOSE
      printf("str: %s %d %d %d\n", buff, lic_found, id_found, idle_found);
#endif
      if (id_found) {
        memcpy(machines[num_machines].machine_id, buff, sizeof(char)*(size+1));
        id_found = 0;
      } else if (state_found) {
        flag = 0;
        for (j = 0; j < NUM_MACHINE_STATE; j++) {
          if (strcmp(machine_state_data[j], buff) == 0) {
            memcpy(machines[num_machines].state, buff, sizeof(char)*(size+1));
            flag = 1;
            break;
          }
        }
        if (!flag) {
          error = ERROR_NETWORK;
          goto QUIT;
        }
        state_found = 0;
      } else if (dns_name_found) {
        memcpy(machines[num_machines].dns_name, buff, sizeof(char)*(size+1));
        dns_name_found = 0;
      } else if (machine_found) {
        flag = 0;
        for (j = 0; j < NUM_MACHINE_TYPE; j++) {
          if (strcmp(machine_data[j], buff) == 0) {
            memcpy(machines[num_machines].machine_type, buff,
                   sizeof(char)*(size+1));
            flag = 1;
            break;
          }
        }
        if (!flag) {
          error = ERROR_NETWORK;
          goto QUIT;
        }
        machine_found = 0;
      } else if (time_found) {
        memcpy(machines[num_machines].create_time, buff, sizeof(char)*(size+1));
        time_found = 0;
      } else if (region_found) {
        flag = 0;
        for (j = 0; j < NUM_REGIONS; j++) {
          if (strcmp(region_data[j], buff) == 0) {
            memcpy(machines[num_machines].region, buff, sizeof(char)*(size+1));
            flag = 1;
            break;
          }
        }
        if (!flag) {
          error = ERROR_NETWORK;
          goto QUIT;
        }
        region_found = 0;
      } else if (lic_type_found) {
        flag = 0;
        for (j = 0; j < NUM_CLOUD_LICENSE_TYPE; j++) {
          if (strcmp(license_type_data[j], buff) == 0) {
            memcpy(machines[num_machines].license_type, buff,
                   sizeof(char)*(size+1));
            flag = 1;
            break;
          }
        }
        if (!flag) {
          error = ERROR_NETWORK;
          goto QUIT;
        }
        lic_type_found = 0;
      } else if (lic_found) {
        machines[num_machines].license_id = atoi(buff);
        lic_found = 0;
      } else if (idle_found) {
        size = (t->end - t->start);
        memcpy(buff, &response[t->start], sizeof(char)*size);
        machines[num_machines].idle_shutdown = atoi(buff);
        idle_found = 0;
      } else if (password_found) {
        memcpy(machines[num_machines].user_password, buff,
               sizeof(char)*(size+1));
        password_found = 0;
      } else if (strcmp(buff, "_id") == 0) {
        id_found = 1;
      } else if (strcmp(buff, "state") == 0) {
        state_found = 1;
      } else if (strcmp(buff, "DNSName") == 0) {
        dns_name_found = 1;
      } else if (strcmp(buff, "machineType") == 0) {
        machine_found = 1;
      } else if (strcmp(buff, "createTime") == 0) {
        time_found = 1;
      } else if (strcmp(buff, "region") == 0) {
        region_found = 1;
      } else if (strcmp(buff, "licenseType") == 0) {
        lic_type_found = 1;
      } else if (strcmp(buff, "idleShutdown") == 0) {
        idle_found = 1;
      } else if (strcmp(buff, "licenseId") == 0) {
        lic_found = 1;
      } else if (strcmp(buff, "userPassword") == 0) {
        password_found = 1;
      }
    }

    if (t->type == JSMN_PRIMITIVE && idle_found) {
      size = (t->end - t->start);
      memcpy(buff, &response[t->start], sizeof(char)*size);
      machines[num_machines].idle_shutdown = atoi(buff);
      idle_found = 0;
    }
  }

  machine_info->num_machines = num_machines + 1;
  for (i = 0; i < machine_info->num_machines; i++) {
    memcpy(machine_info->machine_ids[i],
           machine_info->machines[i].machine_id,
           sizeof(MAX_ID_LEN+1));
  }

QUIT:

  return error;
}


int
ICgetmachines(ICmachineinfo **machine_infoP)
{
  char request[MAX_STRLEN+1];
  char response[MAX_STRLEN+1];
  char timestr[MAX_STRLEN+1];
  char digest[MAX_STRLEN+1];
  char signature[SIG_LEN+1];
  char *endpoint = "machines";
  char command[MAX_STRLEN+1];
  sha1nfo s;
  int  error = 0;

  if (!(strlen(accessid) == ACCESS_ID_LEN   &&
        strlen(secretkey) == SECRET_KEY_LEN   )) {
    error = ERROR_INVALID_ARGUMENT;
    goto QUIT;
  }

  /* free old machine info */
  error = ICfreemachineinfo(machine_infoP);
  if (error) goto QUIT;

  sprintf(command, "%s/%s?id=%s", baseurl, endpoint, accessid);
#ifdef VERBOSE
  printf("command %s\n", command);
#endif

  getISO8601(timestr);
  sprintf(request, "GET&id=%s&%s", accessid, timestr);

  sha1_init(&s);
  sha1_initHmac(&s, (unsigned char *) secretkey, 43);
  sha1_write(&s, request, strlen(request));
  memcpy(digest, sha1_resultHmac(&s), 20);
  digest[20] = 0;

#ifdef VERBOSE
  printf("digest ");
  printHash((uint8_t *)digest);
#endif


  b64_encode(digest, 20, signature, SIG_LEN);
  signature[SIG_LEN] = '\0';

#ifdef VERBOSE
  printf("request %s\n", request);
  printf("timestr %s\n", timestr);
  printf("signature %s\n", signature);
#endif

  error = sendcommand(command, NULL, timestr, signature, response);
  if (error) goto QUIT;

#ifdef VERBOSE
  printf("response %s\n", response);
#endif

  error = getmachineinfo(response, machine_infoP);
  if (error) goto QUIT;

QUIT:

  return error;
}

int
IClaunchmachines(int              n,
                 char            *license_type,
                 int             *license_idP,
                 char            *user_password,
                 char            *region,
                 char            *machine_type,
                 int             *idleshutdownP,
                 ICmachineinfo  **machine_infoP)
{
  char request[MAX_STRLEN+1];
  char response[MAX_STRLEN+1];
  char timestr[MAX_STRLEN+1];
  char digest[MAX_STRLEN+1];
  char signature[SIG_LEN+1];
  char *endpoint = "launch";
  char command[MAX_STRLEN+1];
  char *post_end;
  sha1nfo  s;
  int  i;
  int  flag = 0;
  ICmachineinfo *machine_info = NULL;
  int  error = 0;


  if (!(strlen(accessid) == 17 && strlen(secretkey) == 43)) {
    error = ERROR_INVALID_ARGUMENT;
    goto QUIT;
  }

  if (n <= 0) goto QUIT;

  /* free old machine info */
  error = ICfreemachineinfo(machine_infoP);
  if (error) goto QUIT;

  /* alloc info for new machines */
  MALLOC(machine_info, n);
  MALLOC(machine_info->machine_ids, n);
  for (i = 0; i < n; i++) {
    MALLOC(machine_info->machine_ids[i], sizeof(char)*(MAX_ID_LEN+1));
  }
  machine_info->machines = NULL;
  machine_info->num_machines = n;

  *machine_infoP = machine_info;

  sprintf(command, "%s/%s", baseurl, endpoint);

#ifdef VERBOSE
  printf("command %s\n", command);
#endif

  getISO8601(timestr);
  sprintf(request, "POST&id=%s&numMachines=%d", accessid, n);

  if (license_type) {
    flag = 0;
    for (i = 0; i < NUM_CLOUD_LICENSE_TYPE; i++) {
      if (strcmp(license_type_data[i], license_type) == 0) {
        flag = 1;
        break;
      }
    }

    if (!flag) {
      error = ERROR_INVALID_ARGUMENT;
      goto QUIT;
    }
    sprintf(&request[strlen(request)],
            "&licenseType=%s", license_type_encode[i]);
  }

  if (user_password) {
    sprintf(&request[strlen(request)],
            "&userPassword=%s", user_password);
  }

  if (machine_type) {
    flag = 0;
    for (i = 0; i < NUM_MACHINE_TYPE; i++) {
      if (strcmp(machine_data[i], machine_type) == 0) {
        flag = 1;
        break;
      }
    }

    if (!flag) {
      error = ERROR_INVALID_ARGUMENT;
      goto QUIT;
    }
    sprintf(&request[strlen(request)], "&machineType=%s",
            machine_type);
  }

  if (license_idP) {
    sprintf(&request[strlen(request)], "&licenseId=%d", *license_idP);
  }

  if (region) {
    flag = 0;
    for (i = 0; i < NUM_REGIONS; i++) {
      if (strcmp(region_data[i], region) == 0) {
        flag = 1;
        break;
      }
    }

    if (!flag) {
      error = ERROR_INVALID_ARGUMENT;
      goto QUIT;
    }
    sprintf(&request[strlen(request)], "&region=%s", region);
  }

  if (idleshutdownP) {
     sprintf(&request[strlen(request)], "&idleShutdown=%d", *idleshutdownP);
  }

  post_end = &request[strlen(request)];

  sprintf(&request[strlen(request)], "&%s", timestr);

  sha1_init(&s);
  sha1_initHmac(&s, (unsigned char *) secretkey, 43);
  sha1_write(&s, request, strlen(request));
  memcpy(digest, sha1_resultHmac(&s), 20);
  digest[20] = 0;
#ifdef VERBOSE
  printf("digest ");
  printHash((uint8_t *)digest);
#endif


  b64_encode(digest, 20, signature, SIG_LEN);
  signature[SIG_LEN] = '\0';

#ifdef VERBOSE
  printf("request %s\n", request);
  printf("timestr %s\n", timestr);
  printf("signature %s\n", signature);
#endif

  *post_end = '\0';

  error = sendcommand(command, &request[5], timestr, signature, response);
  if (error) goto QUIT;

#ifdef VERBOSE
  printf("response %s\n", response);
#endif

  error = getmachineinfo(response, machine_infoP);
  if (error) goto QUIT;


QUIT:

  return error;
}

int
ICkillmachines(int             n,
               char          **machine_ids,
               ICmachineinfo **machine_infoP)
{
  char    request[MAX_STRLEN+1];
  char    response[MAX_STRLEN+1];
  char    timestr[MAX_STRLEN+1];
  char    digest[MAX_STRLEN+1];
  char    signature[SIG_LEN+1];
  char   *endpoint = "kill";
  char    command[MAX_STRLEN+1];
  char    machineIdJSON[MAX_STRLEN+1];
  char   *post_end;
  sha1nfo s;
  int     i;
  int     error = 0;


  if (!(strlen(accessid) == 17 && strlen(secretkey) == 43)) {
    error = ERROR_INVALID_ARGUMENT;
    goto QUIT;
  }


  if (n <= 0) goto QUIT;

  sprintf(command, "%s/%s", baseurl, endpoint);
#ifdef VERBOSE
  printf("command %s\n", command);
#endif

  sprintf(request, "POST&id=%s", accessid);

  sprintf(machineIdJSON, "%%5B"); /* [ -> %5B */
  for (i = 0; i < n; i++) {
    if (i > 0) {
      sprintf(&machineIdJSON[strlen(machineIdJSON)], "%%2C"); /* , -> %2C */
    }
    /* " -> %22 */
    sprintf(&machineIdJSON[strlen(machineIdJSON)], "%%22%s%%22",machine_ids[i]);
  }
  /* [ -> %5D */
  sprintf(&machineIdJSON[strlen(machineIdJSON)], "%%5D");
#ifdef VERBOSE
  printf("machineJSON %s\n", machineIdJSON);
#endif

  sprintf(&request[strlen(request)], "&machineIds=%s", machineIdJSON);

  post_end = &request[strlen(request)];


  getISO8601(timestr);
  sprintf(&request[strlen(request)], "&%s", timestr);

  sha1_init(&s);
  sha1_initHmac(&s, (unsigned char *) secretkey, 43);
  sha1_write(&s, request, strlen(request));
  memcpy(digest, sha1_resultHmac(&s), 20);
  digest[20] = 0;
#ifdef VERBOSE
  printf("digest ");
  printHash((uint8_t *)digest);
#endif

  b64_encode(digest, 20, signature, SIG_LEN);
  signature[SIG_LEN] = '\0';

#ifdef VERBOSE
  printf("request %s\n", request);
  printf("timestr %s\n", timestr);
  printf("signature %s\n", signature);
#endif

  *post_end = '\0';

  error = sendcommand(command, &request[5], timestr, signature, response);
  if (error) goto QUIT;

#ifdef VERBOSE
  printf("response %s\n", response);
#endif

  error = getmachineinfo(response, machine_infoP);
  if (error) goto QUIT;

QUIT:

  return error;
}

int
ICcloudcreds(char *id,
             char *key)
{
  if (!id || !key)
    return ERROR_NULL_ARGUMENT;

  if (strlen(id)  != ACCESS_ID_LEN ||
      strlen(key) != SECRET_KEY_LEN  )
    return ERROR_INVALID_ARGUMENT;

  memcpy(accessid, id, sizeof(char)*(ACCESS_ID_LEN+1));
  accessid[ACCESS_ID_LEN] = 0;

  memcpy(secretkey, key, sizeof(char)*(SECRET_KEY_LEN+1));
  secretkey[SECRET_KEY_LEN] = 0;

  return 0;
}

int
ICfreemachineinfo(ICmachineinfo **machine_infoP)
{
  int i;
  ICmachineinfo *info;
  int num_machines;
  int error = 0;

  if (*machine_infoP) {
    info = *machine_infoP;
    num_machines = info->num_machines;

    if (info->machine_ids) {
      for (i = 0; i < num_machines; i++) {
        FREE(info->machine_ids[i]);
      }
      FREE(info->machine_ids);
    }

    if (info->machines) {
      FREE(info->machines);
    }
    info->num_machines = 0;

    FREE(info);
  }

  return error;
}

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void   *contents,
                    size_t  size,
                    size_t  nmemb,
                    void   *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  if (mem->size + realsize > MAX_STRLEN)
    return 0;

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}


static int
sendcommand(const char *command,
            char       *postfields,
            char       *timestr,
            char       *signature,
            char       *response)
{
  int  error;
  CURL *curl_handle;
  CURLcode res;
  struct MemoryStruct chunk;
  struct curl_slist *list = NULL;
  char dateheader[MAX_STRLEN+1];
  char signheader[MAX_STRLEN+1];
  long response_code;

  chunk.memory = response;
  chunk.size = 0;

  curl_global_init(CURL_GLOBAL_ALL);

  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_URL, command);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &chunk);

#if 0
  if (strlen(signature) != 28) {
    printf("Bad signature %s\n", signature);
  }
  assert(strlen(signature) == 28);
#endif

  sprintf(dateheader, "X-Gurobi-Date: %s", timestr);
  sprintf(signheader, "X-Gurobi-Signature: %s", signature);

  list = curl_slist_append(list, signheader);
  list = curl_slist_append(list, dateheader);

  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, list);

  if (postfields) {
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, postfields);
  }

  res = curl_easy_perform(curl_handle);

  curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);

  curl_slist_free_all(list);

  curl_easy_cleanup(curl_handle);

  curl_global_cleanup();

#ifdef VERBOSE
  printf("response_code %ld\n", response_code);
#endif

  if (res == CURLE_OK && response_code == 200) {
    error = 0;
  } else {
    printf("Server Error: %ld\n%s\n", response_code, response);
    error = ERROR_NETWORK;
  }

  return error;
}


/**
 * Allocates a fresh unused token from the token pull.
 */
static jsmntok_t*
jsmn_alloc_token(jsmn_parser *parser,
                 jsmntok_t *tokens,
                 size_t num_tokens)
{
  jsmntok_t *tok;
  if (parser->toknext >= num_tokens) {
    return NULL;
  }
  tok = &tokens[parser->toknext++];
  tok->start = tok->end = -1;
  tok->size = 0;
#ifdef JSMN_PARENT_LINKS
  tok->parent = -1;
#endif
  return tok;
}

/**
 * Fills token type and boundaries.
 */
static void
jsmn_fill_token(jsmntok_t *token,
                jsmntype_t type,
                int        start,
                int        end)
{
  token->type = type;
  token->start = start;
  token->end = end;
  token->size = 0;
}

/**
 * Fills next available token with JSON primitive.
 */
static jsmnerr_t
jsmn_parse_primitive(jsmn_parser *parser,
                     const char *js,
                     size_t len,
                     jsmntok_t *tokens,
                     size_t num_tokens)
{
  jsmntok_t *token;
  int start;

  start = parser->pos;

  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    switch (js[parser->pos]) {
#ifndef JSMN_STRICT
      /* In strict mode primitive must be followed by "," or "}" or "]" */
    case ':':
#endif
    case '\t' : case '\r' : case '\n' : case ' ' :
    case ','  : case ']'  : case '}' :
      goto found;
    }
    if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
      parser->pos = start;
      return JSMN_ERROR_INVAL;
    }
  }
#ifdef JSMN_STRICT
  /* In strict mode primitive must be followed by a comma/object/array */
  parser->pos = start;
  return JSMN_ERROR_PART;
#endif

 found:
  if (tokens == NULL) {
    parser->pos--;
    return 0;
  }
  token = jsmn_alloc_token(parser, tokens, num_tokens);
  if (token == NULL) {
    parser->pos = start;
    return JSMN_ERROR_NOMEM;
  }
  jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
#ifdef JSMN_PARENT_LINKS
  token->parent = parser->toksuper;
#endif
  parser->pos--;
  return 0;
}

/**
 * Fills next token with JSON string.
 */
static jsmnerr_t
jsmn_parse_string(jsmn_parser *parser,
                  const char  *js,
                  size_t      len,
                  jsmntok_t  *tokens,
                  size_t      num_tokens)
{
  jsmntok_t *token;

  int start = parser->pos;

  parser->pos++;

  /* Skip starting quote */
  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    char c = js[parser->pos];

    /* Quote: end of string */
    if (c == '\"') {
      if (tokens == NULL) {
        return 0;
      }
      token = jsmn_alloc_token(parser, tokens, num_tokens);
      if (token == NULL) {
        parser->pos = start;
        return JSMN_ERROR_NOMEM;
      }
      jsmn_fill_token(token, JSMN_STRING, start+1, parser->pos);
#ifdef JSMN_PARENT_LINKS
      token->parent = parser->toksuper;
#endif
      return 0;
    }

    /* Backslash: Quoted symbol expected */
    if (c == '\\' && parser->pos + 1 < len) {
      int i;
      parser->pos++;
      switch (js[parser->pos]) {
        /* Allowed escaped symbols */
      case '\"': case '/' : case '\\' : case 'b' :
      case 'f' : case 'r' : case 'n'  : case 't' :
        break;
        /* Allows escaped symbol \uXXXX */
      case 'u':
        parser->pos++;
        for(i = 0; i < 4 && parser->pos < len && js[parser->pos] != '\0'; i++) {
          /* If it isn't a hex character we have an error */
          if(!((js[parser->pos] >= 48 && js[parser->pos] <= 57) || /* 0-9 */
               (js[parser->pos] >= 65 && js[parser->pos] <= 70) || /* A-F */
               (js[parser->pos] >= 97 && js[parser->pos] <= 102))) { /* a-f */
            parser->pos = start;
            return JSMN_ERROR_INVAL;
          }
          parser->pos++;
        }
        parser->pos--;
        break;
        /* Unexpected symbol */
      default:
        parser->pos = start;
        return JSMN_ERROR_INVAL;
      }
    }
  }
  parser->pos = start;
  return JSMN_ERROR_PART;
}

/**
 * Parse JSON string and fill tokens.
 */
static jsmnerr_t
jsmn_parse(jsmn_parser *parser,
           const char  *js,
           size_t       len,
           jsmntok_t   *tokens,
           unsigned int num_tokens)
{
  jsmnerr_t r;
  int i;
  jsmntok_t *token;
  int count = 0;

  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    char c;
    jsmntype_t type;

    c = js[parser->pos];
    switch (c) {
    case '{': case '[':
      count++;
      if (tokens == NULL) {
        break;
      }
      token = jsmn_alloc_token(parser, tokens, num_tokens);
      if (token == NULL)
        return JSMN_ERROR_NOMEM;
      if (parser->toksuper != -1) {
        tokens[parser->toksuper].size++;
#ifdef JSMN_PARENT_LINKS
        token->parent = parser->toksuper;
#endif
      }
      token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
      token->start = parser->pos;
      parser->toksuper = parser->toknext - 1;
      break;
    case '}': case ']':
      if (tokens == NULL)
        break;
      type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
#ifdef JSMN_PARENT_LINKS
      if (parser->toknext < 1) {
        return JSMN_ERROR_INVAL;
      }
      token = &tokens[parser->toknext - 1];
      for (;;) {
        if (token->start != -1 && token->end == -1) {
          if (token->type != type) {
            return JSMN_ERROR_INVAL;
          }
          token->end = parser->pos + 1;
          parser->toksuper = token->parent;
          break;
        }
        if (token->parent == -1) {
          break;
        }
        token = &tokens[token->parent];
      }
#else
      for (i = parser->toknext - 1; i >= 0; i--) {
        token = &tokens[i];
        if (token->start != -1 && token->end == -1) {
          if (token->type != type) {
            return JSMN_ERROR_INVAL;
          }
          parser->toksuper = -1;
          token->end = parser->pos + 1;
          break;
        }
      }
      /* Error if unmatched closing bracket */
      if (i == -1) return JSMN_ERROR_INVAL;
      for (; i >= 0; i--) {
        token = &tokens[i];
        if (token->start != -1 && token->end == -1) {
          parser->toksuper = i;
          break;
        }
      }
#endif
      break;
    case '\"':
      r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
      if (r < 0) return r;
      count++;
      if (parser->toksuper != -1 && tokens != NULL)
        tokens[parser->toksuper].size++;
      break;
    case '\t' : case '\r' : case '\n' : case ' ':
      break;
    case ':':
      parser->toksuper = parser->toknext - 1;
      break;
    case ',':
      if (tokens != NULL &&
          tokens[parser->toksuper].type != JSMN_ARRAY &&
          tokens[parser->toksuper].type != JSMN_OBJECT) {
#ifdef JSMN_PARENT_LINKS
        parser->toksuper = tokens[parser->toksuper].parent;
#else
        for (i = parser->toknext - 1; i >= 0; i--) {
          if (tokens[i].type == JSMN_ARRAY || tokens[i].type == JSMN_OBJECT) {
            if (tokens[i].start != -1 && tokens[i].end == -1) {
              parser->toksuper = i;
              break;
            }
          }
        }
#endif
      }
      break;
#ifdef JSMN_STRICT
      /* In strict mode primitives are: numbers and booleans */
    case '-': case '0': case '1' : case '2': case '3' : case '4':
    case '5': case '6': case '7' : case '8': case '9':
    case 't': case 'f': case 'n' :
      /* And they must not be keys of the object */
      if (tokens != NULL) {
        jsmntok_t *t = &tokens[parser->toksuper];
        if (t->type == JSMN_OBJECT ||
            (t->type == JSMN_STRING && t->size != 0)) {
          return JSMN_ERROR_INVAL;
        }
      }
#else
      /* In non-strict mode every unquoted value is a primitive */
    default:
#endif
      r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
      if (r < 0) return r;
      count++;
      if (parser->toksuper != -1 && tokens != NULL)
        tokens[parser->toksuper].size++;
      break;

#ifdef JSMN_STRICT
      /* Unexpected char in strict mode */
    default:
      return JSMN_ERROR_INVAL;
#endif
    }
  }

  for (i = parser->toknext - 1; i >= 0; i--) {
    /* Unmatched opened object or array */
    if (tokens[i].start != -1 && tokens[i].end == -1) {
      return JSMN_ERROR_PART;
    }
  }

  return count;
}

/**
 * Creates a new parser based over a given  buffer with an array of tokens
 * available.
 */
static void
jsmn_init(jsmn_parser *parser) {
  parser->pos = 0;
  parser->toknext = 0;
  parser->toksuper = -1;
}
