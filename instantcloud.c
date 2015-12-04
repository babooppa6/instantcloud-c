#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "cloud.h"

#define LAUNCH   "launch"
#define KILL     "kill"
#define MACHINE  "machine"
#define MACHINES "machines"
#define LICENSE  "license"
#define LICENSES "licenses"

#define HELP         "--help"
#define ID           "--id"
#define KEY          "--key"

#define SERVER       "--server"
#define SERVERS      "--servers"
#define WORKER       "--worker"
#define WORKERS      "--workers"
#define READY        "--ready"

#define NUM_MACHINES   "--nummachines"
#define LICENSE_TYPE   "--licensetype"
#define PASSWORD       "--password"
#define LICENSE_ID     "--licenseid"
#define INSTANCE       "--instance"
#define REGION         "--region"
#define IDLE_SHUTDOWN  "--idleshutdown"
#define MACHINE_TYPE   "--machinetype"
#define GUROBI_VERSION "--gurobiversion"

#define HELP_COMMAND     0
#define LAUNCH_COMMAND   1
#define KILL_COMMAND     2
#define MACHINES_COMMAND 3
#define LICENSES_COMMAND 4

#define SERVERS_FLAG 1
#define WORKERS_FLAG 2
#define READY_FLAG   3

char region_data[NUM_REGIONS][MAX_REGION_LEN+1] = \
  { REGION_US_EAST_1,
    REGION_US_WEST_1,
    REGION_US_WEST_2,
    REGION_EU_CENTRAL_1,
    REGION_EU_WEST_1,
    REGION_AP_NORTHEAST_1,
    REGION_AP_SOUTHEAST_1,
    REGION_AP_SOUTHEAST_2 };
char machine_data[NUM_MACHINE_TYPE][MAX_MACHINE_LEN+1] = \
  { MACHINE_C4_LARGE,
    MACHINE_C4_2XLARGE,
    MACHINE_C4_4XLARGE,
    MACHINE_C4_8XLARGE,
    MACHINE_R3_8XLARGE };
char machine_state_data[NUM_MACHINE_STATE][MAX_STATE_LEN+1] = \
  { STATE_LAUNCHING,
    STATE_PENDING,
    STATE_OBTAINING_LICENSE,
    STATE_IDLE,
    STATE_RUNNING,
    STATE_SHUTTING_DOWN,
    STATE_LAUNCH_ERROR };
const char license_type_data[NUM_CLOUD_LICENSE_TYPE][MAX_LICENSE_TYPE_LEN+1] = \
  { LICENSE_FULL_COMPUTE_SERVER,
    LICENSE_LIGHT_COMPUTE_SERVER,
    LICENSE_DISTRIBUTED_WORKER };

void
usage() {
  printf("instantcloud command [<options>]\n");
  printf("\n");
  printf("Here command is one of the following:\n");
  printf("\tlaunch\tLaunch a set of Gurobi machines\n");
  printf("\tkill\tKill a set of Gurobi machines\n");
  printf("\tlicenses\tShow the licenses associated with your account\n");
  printf("\tmachines\tShow currently running machines\n");
  printf("\n");
  printf("General options:\n");
  printf("  --help (-h):  this message\n");
  printf("  --id (-I): access id\n");
  printf("  --key (-K): secret key\n");
}

int
get_id(char **idP)
{
  char *id = NULL;

  if (*idP != NULL) {
    return 0;
  } else if ((id = getenv("IC_ACCESS_ID")) != NULL) {
    *idP = id;
    return 0;
  } else {
    return 1;
  }
}

int
get_secretkey(char **keyP)
{
  char *key = NULL;
  if (*keyP != NULL) {
    return 0;
  } else if ((key = getenv("IC_SECRET_KEY")) != NULL) {
    *keyP = key;
    return 0;
  } else {
    return 1;
  }
}

void
print_machines(int        num_machines,
               ICmachine *machines)
{
  int i;
  for (i = 0; i < num_machines; i++) {
    printf("Machine name: %s\n", machines[i].dns_name);
    printf("\tlicense type: %s\n", machines[i].license_type);
    printf("\tstate: %s\n", machines[i].state);
    printf("\tmachine type: %s\n", machines[i].machine_type);
    printf("\tregion: %s\n", machines[i].region);
    printf("\tidle shutdown: %d\n", machines[i].idle_shutdown);
    printf("\tuser password: %s\n", machines[i].user_password);
    printf("\tcreate time: %s\n", machines[i].create_time);
    printf("\tlicense id: %d\n", machines[i].license_id);
    printf("\tmachine id: %s\n", machines[i].machine_id);
  }
}

int
main(int   argc,
     char *argv[])
{

  int    cursor;
  int    idleshutdown         = 60;
  char  *license_type         = NULL;
  int    licenseid            = -1;
  int   *licenseidP           = NULL;
  char  *password             = NULL;
  char  *region               = NULL;
  char  *machine_type         = NULL;
  char  *gurobi_version       = NULL;
  char  *id                   = NULL;
  char  *key                  = NULL;
  int    num_machines         = -1;
  char **machine_ids          = NULL;
  int    num_licenses         = -1;
  ICcloudlicense *licenses    = NULL;
  int    command              = -1;
  int    flag                 = 0;
  ICmachine *machines         = NULL;
  ICmachineinfo *machine_info = NULL;
  int    i;
  int    error              = 0;


  for (cursor = 1; cursor < argc; cursor++) {
    if (strlen(argv[cursor]) > 1 &&
        argv[cursor][0] == '-'     ) {
      if (strcmp(argv[cursor], HELP) == 0 ||
          strcmp(argv[cursor], "-h") == 0   ) {
        command = HELP_COMMAND;
      } else if (strcmp(argv[cursor], ID) == 0   ||
                 strcmp(argv[cursor], "-I") == 0   ) {
        id = argv[cursor + 1];
        cursor++;
      } else if (strcmp(argv[cursor], KEY) == 0  ||
                 strcmp(argv[cursor], "-K") == 0   ) {
        key = argv[cursor + 1];
        cursor++;
      }
    } else if (strlen(argv[cursor]) > 1          &&
               strcmp(argv[cursor], LAUNCH) == 0   ) {
      command = LAUNCH_COMMAND;
    } else if (strlen(argv[cursor]) > 1        &&
               strcmp(argv[cursor], KILL) == 0   ) {
      command = KILL_COMMAND;
    } else if (strlen(argv[cursor]) > 1               &&
               (strcmp(argv[cursor], MACHINE) == 0 ||
                strcmp(argv[cursor], MACHINES) == 0  )   ) {
      command = MACHINES_COMMAND;
    } else if (strlen(argv[cursor]) > 1                &&
               (strcmp(argv[cursor], LICENSE) == 0 ||
                strcmp(argv[cursor], LICENSES) == 0  )    ) {
      command = LICENSES_COMMAND;
    } else {
      break;
    }
  }

  if (command == -1) {
    printf("Unrecognized command\n");
    usage();
    exit(1);
  }

  error = get_id(&id);
  if (error) {
    printf("Could not find access id. Set the access id with --id\n");
    printf("Or by setting the environmental variable IC_ACCESS_ID\n");
    exit(1);
  }

  error = get_secretkey(&key);
  if (error) {
    printf("Could not find secret key. Set the secret key with --key\n");
    printf("Or by setting the environmental variable IC_SECRET_KEY\n");
    exit(1);
  }

  error = ICcloudcreds(id, key);
  if (error) {
    printf("Bad cloud credentials\n");
    goto QUIT;
  }


  if (command == HELP_COMMAND) {
    usage();
    exit(0);
  } else if (command == LAUNCH_COMMAND) {
    for (cursor = cursor - 1; cursor < argc; cursor++) {
      if (strlen(argv[cursor]) > 1 &&
          argv[cursor][0] == '-'     ) {
        if (strcmp(argv[cursor], "-n") == 0        ||
            strcmp(argv[cursor], NUM_MACHINES) == 0   ) {
          num_machines = strtol(argv[++cursor], (char **) NULL, 10);
          if (errno == ERANGE || num_machines == 0) {
            printf("Bad option %s for number of machines\n", argv[cursor]);
            goto QUIT;
          }
        } else if (strcmp(argv[cursor], "-l") == 0         ||
                   strcmp(argv[cursor], LICENSE_TYPE) == 0   ) {
          license_type = argv[++cursor];
          flag = 0;
          for (i = 0; i < NUM_CLOUD_LICENSE_TYPE; i++) {
            if (strcmp(license_type_data[i], license_type) == 0) {
              flag = 1;
              break;
            }
          }
          if (!flag) {
            printf("Bad option %s for license type\n", license_type);
            goto QUIT;
          }
        } else if (strcmp(argv[cursor], "-p") == 0    ||
                   strcmp(argv[cursor], PASSWORD) == 0  ) {
          password = argv[++cursor];
        } else if (strcmp(argv[cursor], "-s") == 0         ||
                   strcmp(argv[cursor], IDLE_SHUTDOWN) == 0   ) {
          idleshutdown = atoi(argv[++cursor]);
        } else if (strcmp(argv[cursor], "-i") == 0     ||
                   strcmp(argv[cursor], LICENSE_ID) == 0  ) {
          licenseid = atoi(argv[++cursor]);
          licenseidP = &licenseid;
        } else if (strcmp(argv[cursor], "-r") == 0  ||
                   strcmp(argv[cursor], REGION) == 0  ) {
          region = argv[++cursor];
          flag = 0;
          for (i = 0; i < NUM_REGIONS; i++) {
            if (strcmp(region_data[i], region) == 0) {
              flag = 1;
              break;
            }
          }
          if (!flag) {
            printf("Bad option %s for region\n", region);
            goto QUIT;
          }
        } else if (strcmp(argv[cursor], "-m") == 0        ||
                   strcmp(argv[cursor], MACHINE_TYPE) == 0  ) {
          machine_type = argv[++cursor];
          flag = 0;
          for (i = 0; i < NUM_MACHINE_TYPE; i++) {
            if (strcmp(machine_data[i], machine_type) == 0) {
              flag = 1;
              break;
            }
          }
          if (!flag) {
            printf("Bad options %s for machine type\n", machine_type);
            goto QUIT;
          }
        } else if (strcmp(argv[cursor], "-g") == 0          ||
                   strcmp(argv[cursor], GUROBI_VERSION) == 0  ) {
          gurobi_version = argv[++cursor];
        }
      }
    }

    error = IClaunchmachines(num_machines, license_type,
                             licenseidP, password, region,
                             machine_type, &idleshutdown,
                             gurobi_version, &machine_info);
    if (error) goto QUIT;

    num_machines = machine_info->num_machines;
    machines     = machine_info->machines;

    print_machines(num_machines, machines);

  } else if (command == KILL_COMMAND) {
    num_machines = 0;
    i = cursor;
    for (; cursor < argc; cursor++) {
      if (strlen(argv[cursor]) != 17) {
        printf("Invalid machine id: %s\n", argv[cursor]);
        exit(1);
      } else {
        num_machines++;
      }
    }

    machine_ids = malloc(sizeof(char *)*num_machines);
    if (machine_ids == NULL) {
      error = ERROR_OUT_OF_MEMORY;
      goto QUIT;
    }

    cursor = i;
    i = 0;
    for (; cursor < argc; cursor++) {
      machine_ids[i] = argv[cursor];
      i++;
    }

    error = ICkillmachines(num_machines, machine_ids, &machine_info);
    if (error) goto QUIT;

    num_machines = machine_info->num_machines;
    machines     = machine_info->machines;

    print_machines(num_machines, machines);

    free(machine_ids);
  } else if (command == MACHINES_COMMAND) {
    for (cursor = cursor - 1; cursor < argc; cursor++) {
      if (strlen(argv[cursor]) > 1 &&
          argv[cursor][0] == '-'     ) {
        if (strcmp(argv[cursor], "-s") == 0   ||
            strcmp(argv[cursor], SERVER) == 0 ||
            strcmp(argv[cursor], SERVERS) == 0  ) {
          flag = SERVERS_FLAG;
        } else if (strcmp(argv[cursor], "-w") == 0   ||
                   strcmp(argv[cursor], WORKER) == 0 ||
                   strcmp(argv[cursor], WORKERS) == 0  ) {
          flag = WORKERS_FLAG;
        } else if (strcmp(argv[cursor], "-r") == 0 ||
                   strcmp(argv[cursor], READY) == 0  ) {
          flag = READY_FLAG;
        }
      }
    }

#ifdef VERBOSE
    printf("machines flag %d\n", flag);
#endif

    error = ICgetmachines(&machine_info);
    if (error) goto QUIT;

    num_machines = machine_info->num_machines;
    machines     = machine_info->machines;

    if (flag == SERVERS_FLAG) {
      int server_count = 0;

      for (i = 0; i < num_machines; i++) {
        if ((strcmp(machines[i].state, STATE_IDLE) == 0   ||
             strcmp(machines[i].state, STATE_RUNNING) == 0  ) &&
            strcmp(machines[i].license_type,
                   LICENSE_FULL_COMPUTE_SERVER) == 0             ) {
          if (server_count > 0)
            printf(",");
          printf("%s", machines[i].dns_name);
          server_count++;
        }
      }
      printf("\n");
    } else if (flag == WORKERS_FLAG) {
      int has_server = 0;
      int worker_count = 0;

      for (i = 0; i < num_machines; i++) {
        if ((strcmp(machines[i].state, STATE_IDLE) == 0   ||
             strcmp(machines[i].state, STATE_RUNNING) == 0  )  &&
            strcmp(machines[i].license_type,
                   LICENSE_FULL_COMPUTE_SERVER) == 0             ) {
           has_server = 1;
           break;
         }
      }

      if (has_server) {
        for (i = 0; i < num_machines; i++) {
          if (strcmp(machines[i].state, STATE_IDLE) == 0   ||
              strcmp(machines[i].state, STATE_RUNNING) == 0  ) {
            if (worker_count > 0)
              printf(",");
            printf("%s", machines[i].dns_name);
            worker_count++;
          }
        }
      }
    } else {
      print_machines(num_machines, machines);
    }
  } else if (command == LICENSES_COMMAND) {
    error = ICgetlicenses(&num_licenses, NULL);
    if (error) goto QUIT;

    licenses = malloc(sizeof(ICcloudlicense)*num_licenses);
    if (licenses == NULL) {
      error = ERROR_OUT_OF_MEMORY;
      goto QUIT;
    }

    error = ICgetlicenses(&num_licenses, licenses);
    if (error) goto QUIT;

    printf("License Id   Credit  Rate      Expiration\n");
    for (i = 0; i < num_licenses; i++) {
      printf("%d     ", licenses[i].license_id);
      printf(" %8.2f ", licenses[i].credit);
      printf(" %s ",    licenses[i].rate_plan);
      printf(" %s\n",   licenses[i].expiration);
    }
  }

QUIT:
  if (licenses) {
    free(licenses);
    licenses = NULL;
  }

  error = ICfreemachineinfo(&machine_info);
  if (error)
    printf("error %d\n", error);

  return error;
}
