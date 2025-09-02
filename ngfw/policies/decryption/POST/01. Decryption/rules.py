# This section is for regular decryption

import  settings
from    ngfw.objects.tags.tags       import tags
from    ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                             "MUST-BE-UNIQUE-FOR-EACH-RULE",                     
        "description":                      "MUST-BE-POPULATED-FOR-EACH-RULE",                 
        "tags":                             [group_tags["tls-d-decryption"]["name"]],  
        "group_tag":                        group_tags["tls-d-decryption"]["name"],  

        "source_zones":                     settings.ZONE_INSIDE,
        "source_addresses":                 settings.DEFAULT_INSIDE_ADDRESS,
        "negate_source":                    False,                             
        "source_users":                     settings.GRP_PREDEFINED["grp_tls_d_decrypt"].lower(),
        "source_hip":                       None,

        "destination_zones":                settings.ZONE_OUTSIDE,
        "destination_addresses":            settings.DEFAULT_INSIDE_ADDRESS,
        "negate_destination":               True,                              
        "destination_hip":                  None,

        "services":                         "service-https",                  
        "url_categories":                   "any",                              

        "action":                           "decrypt",                        
        "decryption_type":                  "ssl-forward-proxy",               
        "decryption_profile":               None,                               

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
        "name":                             "compatible-decryption-tcp-443",
        "url_categories":                   "EDL-URL-ssl_and_http2_compatibility",
        "decryption_profile":               settings.DP_COMPATIBLE,
        "description":                      "Decryption for legacy protocols and HTTP/2 to HTTP1.1 downgrade"
    },
    {
        "name":                             "default-decryption-tcp-443",
        "decryption_profile":               settings.DP_DEFAULT,
        "description":                      "Default decryption"
    }
)