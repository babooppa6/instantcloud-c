/* Instant Cloud Client */
#include <stdlib.h>

#define NUM_CLOUD_LICENSE_TYPE 3
#define LICENSE_FULL_COMPUTE_SERVER  "full compute server"
#define LICENSE_LIGHT_COMPUTE_SERVER "light compute server"
#define LICENSE_DISTRIBUTED_WORKER   "distributed worker"

#define NUM_MACHINE_STATE 8
#define STATE_LAUNCHING          "launching"
#define STATE_PENDING            "pending"
#define STATE_OBTAINING_LICENSE  "obtaining license"
#define STATE_IDLE               "idle"
#define STATE_RUNNING            "running"
#define STATE_KILLING            "killing"
#define STATE_SHUTTING_DOWN      "shutting down"
#define STATE_LAUNCH_ERROR       "launch error"

#define NUM_MACHINE_TYPE 5
#define MACHINE_C4_LARGE   "c4.large"
#define MACHINE_C4_2XLARGE "c4.2xlarge"
#define MACHINE_C4_4XLARGE "c4.4xlarge"
#define MACHINE_C4_8XLARGE "c4.8xlarge"
#define MACHINE_R3_8XLARGE "r3.8xlarge"

#define NUM_REGIONS 8
#define REGION_US_EAST_1       "us-east-1"
#define REGION_US_WEST_1       "us-west-1"
#define REGION_US_WEST_2       "eu-west-2"
#define REGION_EU_CENTRAL_1    "eu-central-1"
#define REGION_EU_WEST_1       "eu-west-1"
#define REGION_AP_NORTHEAST_1  "ap-northeast-1"
#define REGION_AP_SOUTHEAST_1  "ap-southeast-1"
#define REGION_AP_SOUTHEAST_2  "ap-southeast-2"


#define MAX_ID_LEN           32
#define MAX_STATE_LEN        32
#define MAX_DNS_LEN          128
#define MAX_TIME_LEN         64
#define MAX_MACHINE_LEN      32
#define MAX_REGION_LEN       16
#define MAX_ISO8601_LEN      24
#define MAX_LICENSE_TYPE_LEN 32
#define MAX_RATE_LEN         32

#define ACCESS_ID_LEN        17
#define SECRET_KEY_LEN       43


typedef struct _machine
{
  char machine_id[MAX_ID_LEN+1];
  char state[MAX_STATE_LEN+1];
  char dns_name[MAX_DNS_LEN+1];
  char create_time[MAX_TIME_LEN+1];
  char machine_type[MAX_MACHINE_LEN+1];
  char region[MAX_REGION_LEN+1];
  char license_type[MAX_LICENSE_TYPE_LEN+1];
  int  idle_shutdown;
  int  license_id;
  char user_password[MAX_ID_LEN+1];
} ICmachine;

typedef struct _machineinfo {
  ICmachine   *machines;
  char       **machine_ids;
  int          num_machines;
} ICmachineinfo;

typedef struct _ICcloudlicense
{
  int    license_id;
  double credit;
  char   expiration[MAX_ISO8601_LEN+1];
  char   rate_plan[MAX_RATE_LEN+1];
} ICcloudlicense;

int ICcloudcreds(char *accessid, char *secretkey);
int IClaunchmachines(int n, char *license_type, int *license_idP,
                     char *machine_password, char *region,
                     char *machine_typeP, int *idleshutdownP,
                     char *gurobi_version,
                     ICmachineinfo **machine_infoP);
int ICkillmachines(int n, char **machine_ids, ICmachineinfo **machine_infoP);
int ICgetmachines(ICmachineinfo **machine_infoP);
int ICgetlicenses(int *num_licensesP, ICcloudlicense *licenses);
int ICfreemachineinfo(ICmachineinfo **machine_infoP);



#define ERROR_NULL_ARGUMENT    1000
#define ERROR_INVALID_ARGUMENT 2000
#define ERROR_NETWORK          3000
#define ERROR_OUT_OF_MEMORY    4000


#define MALLOC(ptr, count) do {                        \
    if (count > 0) {                                   \
      ptr = malloc((count)*sizeof(*(ptr)));            \
      if (ptr == NULL) {                               \
        error = ERROR_OUT_OF_MEMORY;                   \
        goto QUIT;                                     \
      }                                                \
    } else {                                           \
      ptr = NULL;                                      \
    }                                                  \
  } while(0)

#define CALLOC(ptr, count) do {                       \
    if (count > 0) {                                  \
      ptr = calloc(count, sizeof(*(ptr)));            \
      if (ptr == NULL && (count) > 0) {               \
        error = ERROR_OUT_OF_MEMORY;                  \
        goto QUIT;                                    \
      }                                               \
    } else {                                          \
      ptr = NULL;                                     \
    }                                                 \
  } while(0)


#define FREE(ptr) do {                                  \
    if (ptr) {                                          \
      free((void *) ptr);                               \
      ptr = NULL;                                       \
    }                                                   \
  } while(0)
