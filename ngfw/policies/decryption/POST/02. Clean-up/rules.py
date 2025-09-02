# This section is for regular decryption

import  settings
from    ngfw.objects.tags.tags       import tags
from    ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                             "MUST-BE-UNIQUE-FOR-EACH-RULE",                    
        "description":                      "MUST-BE-POPULATED-FOR-EACH-RULE",                 
        "tags":                             [group_tags["tls-d-clean-up"]["name"]],  
        "group_tag":                        group_tags["tls-d-clean-up"]["name"],  

        "source_zones":                     settings.ZONE_INSIDE,
        "source_addresses":                 settings.DEFAULT_INSIDE_ADDRESS,
        "negate_source":                    False,                              
        "source_users":                     "any",                              
        "source_hip":                       None,

        "destination_zones":                settings.ZONE_OUTSIDE,
        "destination_addresses":            "any",                              
        "negate_destination":               False,                              
        "destination_hip":                  None,

        "services":                         "any",                              
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
    # ============================================================================
    # Rules for regular decryption
    # ============================================================================
    {
        "name":           "clean-up-rule-explicit-no-decryption",
        "description":    "Clean up rule - do not decrypt anything else"
    }, # This comma is important!
)