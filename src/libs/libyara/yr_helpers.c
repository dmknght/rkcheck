#include <yara.h>


int yr_rule_count_strings(YR_RULE* rule) {
    int i = 0;
    YR_STRING* string;

    yr_rule_strings_foreach(rule, string) {
        i++;
    }
    return i;
}


int yr_string_count_string_match(YR_SCAN_CONTEXT* context) {
    int i = 0;
    // YR_MATCH* match;
    // YR_STRING* string;
    
    // yr_string_matches_foreach(context, string, match) {
    //     i++;
    // }

    return i;
}
