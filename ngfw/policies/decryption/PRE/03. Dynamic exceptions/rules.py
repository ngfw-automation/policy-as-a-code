# This section is for decryption exceptions

import  settings
from    ngfw.objects.tags.tags       import tags
from    ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                             "MUST-BE-UNIQUE-FOR-EACH-RULE",                     
        "description":                      "MUST-BE-POPULATED-FOR-EACH-RULE",                  
        "tags":                             [group_tags["tls-d-exceptions-dynamic"]["name"]],  
        "group_tag":                        group_tags["tls-d-exceptions-dynamic"]["name"],  

        "source_zones":                     settings.ZONE_INSIDE,
        "source_addresses":                 settings.DEFAULT_INSIDE_ADDRESS,
        "negate_source":                    False,                             
        "source_users":                     "any",                              
        "source_hip":                       None,

        "destination_zones":                settings.ZONE_OUTSIDE,
        "destination_addresses":            "any",                              
        "negate_destination":               False,                             
        "destination_hip":                  None,

        "services":                         "service-https",                    
        "url_categories":                   "any",                              

        "action":                           "no-decrypt",                      
        "decryption_type":                  "ssl-forward-proxy",                
        "decryption_profile":               settings.DP_NO_DECRYPTION,

        "log_setting":                      settings.LFP_DEFAULT,
        "log_successful_tls_handshakes":    True,
        "log_failed_tls_handshakes":        True,

        "target":                           None,
        "negate_target":                    False,
        "disabled":                         False
    }
)

# ==============================================================================================
#
#   Create security rules below this comment section.
#   Define only attributes that differ from the section defaults specified above this comment
#
# ==============================================================================================
section_rules = (
    # ==================================================================================================
    # Rules for static exceptions (hard-coded in the config or based on EDLs which are updated manually)
    # ==================================================================================================
   {
        "name":                             "do-not-decrypt-dynamic-dst-ip",
        "destination_addresses":            "DAG-tls_d_auto_exceptions",
        "description":                      "IP-based dynamic exceptions based on tagged addresses that failed to be decrypted"
    },
)