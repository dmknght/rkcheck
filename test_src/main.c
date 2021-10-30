#include "clamav.h"
#include "yara.h"
#include <stdio.h>


YR_RULES* rules = NULL;
char *yr_db_path = "/home/dmknght/ParrotProjects/rkcheck/database/signatures.ydb";

typedef struct UserData {
  int scan_message;
  const char* matched_rule;
} UserData;


int yr_callback_func(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  /*
    Cast user_data (*((UserData*) (user_data))).scan_message
  */

  struct UserData data = (*((UserData*) (user_data)));
  struct YR_RULE* scan_data = ((YR_RULE*) (message_data));
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    (*((UserData*) (user_data))).scan_message = CL_VIRUS;
    (*((UserData*) (user_data))).matched_rule = scan_data->identifier;
    /* Abort Yara engine if the rules matched one*/
    return CALLBACK_ABORT;
  }
  return ERROR_SUCCESS;
}


static cl_error_t scan_callback(int fd, const char *type, void *context) {
  int flags = SCAN_FLAGS_FAST_MODE;
  int timeout = 1000000;
  UserData user_data;

  user_data.scan_message = CL_CLEAN;

  yr_rules_scan_fd(rules, fd, flags, yr_callback_func, &user_data, timeout);
  if (user_data.scan_message == CL_VIRUS)
  {
    // TODO print file path
    printf("Detected %s\n", user_data.matched_rule);
    /* Return CL_CLEAN so engine does not skip all other files in compressed file*/
    return CL_CLEAN;
  }
  else if (user_data.scan_message == CL_CLEAN)
  {
    return CL_CLEAN;
  }
}


int main() {
  static struct cl_engine *engine;
  const char *virname = NULL;
  char file[256];
  unsigned long size;
  unsigned long int scanned = 0;
  struct cl_scan_options options;
  int stack_size = DEFAULT_STACK_SIZE;
  int max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;

  /* Init ClamAV Engine */
  cl_init(CL_INIT_DEFAULT);
  engine = cl_engine_new();
  cl_engine_compile(engine);
  cl_engine_set_clcb_pre_scan(engine, scan_callback);
  options.parse |= ~0; /* enable all parsers */

  /* Init yara engine */
  yr_initialize();
  if (yr_rules_load(yr_db_path, &rules) != ERROR_SUCCESS)
    printf("Failed to load yara rules\n");
  printf("Loaded %d rules\n", rules->num_rules);
  yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
  yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);

  /* DO SCAN */
  cl_scanfile("/tmp/hello1.zip", &virname, &scanned, engine, &options);
  // cl_scanfile("/tmp/hello", &virname, &scanned, engine, &options);
  // cl_scanfile("/tmp/04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2_detected", &virname, &scanned, engine, &options);

  /* Finit All */
  cl_engine_free(engine);
  if (rules != NULL)
    yr_rules_destroy(rules);
  yr_finalize();
}
