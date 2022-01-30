#include <yara.h>


int yr_rule_count_strings(YR_RULE* rule) {
    int i = 0;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string) {
        i++;
    }
    return i;
}


int yr_scan_count_strings_m(YR_SCAN_CONTEXT* context, YR_STRING* string) {
    int i = 0;
    YR_MATCH* match;
    
    yr_string_matches_foreach(context, string, match) {
        i++;
    }

    return i;
}
