#include <yara.h>


int yr_rule_count_strings(YR_RULE* rule) {
    int i = 0;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string) {
        i++;
    }
    return i;
}


int yr_scan_count_strings_m(YR_SCAN_CONTEXT* context, YR_RULE* rule) {
    int i = 0;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string) // copied from int handle_message, yara.c, Show matched strings.
    {
        YR_MATCH* match;
        yr_string_matches_foreach(context, string, match) {
            // printf("base: %d off: %d d_len: %d %s\n", match->base, match->offset, match->data_length, match->data); // Show matched strings
            i++;
        }
    }
    return i;
}
