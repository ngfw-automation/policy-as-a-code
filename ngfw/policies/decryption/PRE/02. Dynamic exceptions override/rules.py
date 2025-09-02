# This section is to override dynamic exceptions (temporary approach
# to partially mitigate the indiscriminate nature of the exceptions based on IP auto-tagging)

import  settings
from    ngfw.objects.tags.tags       import tags
from    ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                             "MUST-BE-UNIQUE-FOR-EACH-RULE",                     # ++ Default rule name
        "description":                      "MUST-BE-POPULATED-FOR-EACH-RULE",                  # ++ Default description
        "tags":                             [group_tags['tls-d-enforced-decryption']['name']],  # ++ Default tag(s)
        "group_tag":                        group_tags['tls-d-enforced-decryption']['name'],  # ++ Default group tag

        "source_zones":                     settings.ZONE_INSIDE,               # ++ Default source zone(s)
        "source_addresses":                 settings.DEFAULT_INSIDE_ADDRESS,            # ++ Default source address(es)
        "negate_source":                    False,                              # ++ Default source negation
        "source_users":                     "any",                              # ++ Default source user(s)
        "source_hip":                       None,

        "destination_zones":                settings.ZONE_OUTSIDE,              # ++ Default destination zone(s)
        "destination_addresses":            "any",                              # ++ Default destination address(es)
        "negate_destination":               False,                              # ++ Default destination negation
        "destination_hip":                  None,

        "services":                         "service-https",                    # ++ Default service(s)
        "url_categories":                   "any",                              # ++ URL categories

        "action":                           "decrypt",                          # ++ Default action
        "decryption_type":                  "ssl-forward-proxy",                # ++
        "decryption_profile":               settings.DP_STRICT,                 # ++

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
    # Rules for capturing the traffic sinkholed by Palo Alto Networks DNS Security
    # ============================================================================
    {
        "name":                             'enforced-decryption-dst-url',
        "source_users":                     settings.GRP_PREDEFINED['grp_tls_d_decrypt'].lower(),
        "destination_addresses":            settings.DEFAULT_INSIDE_ADDRESS,
        "negate_destination":               True,
        "url_categories":                   ['unknown', 'newly-registered-domain', 'high-risk'],
        "description":                      'These URLs are always decrypted regardless of all exceptions'
    },
)