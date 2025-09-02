# This section is for static decryption exceptions

import  settings
from    ngfw.objects.tags.tags       import tags
from    ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                             "MUST-BE-UNIQUE-FOR-EACH-RULE",                     # ++ Default rule name
        "description":                      "MUST-BE-POPULATED-FOR-EACH-RULE",                  # ++ Default description
        "tags":                             [group_tags["tls-d-exceptions-static"]["name"]],  # ++ Default tag(s)
        "group_tag":                        group_tags["tls-d-exceptions-static"]["name"],  # ++ Default group tag

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

        "action":                           "no-decrypt",                       # Default action (decrypt|no-decrypt|decrypt-and-forward)
        "decryption_type":                  "ssl-forward-proxy",                # ++
        "decryption_profile":               settings.DP_NO_DECRYPTION,          # ++

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
        "name":                             "do-not-decrypt-dst-url",
        "url_categories":                   ["EDL-URL-no_decryption_dst", "UCL-m365-worldwide-any-optimize", "EDL-URL-m365_worldwide_any_allow", "UCL-acme-generic-app"],
        "description":                      "URL-based exceptions for destinations that we do not want to decrypt"
    },
    {
        "name":                             "do-not-decrypt-dst-ip",
        "destination_addresses":            "EDL-IP-no_decryption_dst",
        "description":                      "IP-based exceptions for destinations that we do not want to decrypt"
    },
    {
        "name":                             "do-not-decrypt-src-ip",
        "source_addresses":                 "EDL-IP-no_decryption_src",
        "description":                      "IP-based exceptions for sources that we do not want to decrypt"
    },
    {
        "name":                             "do-not-decrypt-src-usr",
        "source_users":                     settings.GRP_PREDEFINED["grp_tls_d_exception"].lower(),
        "description":                      "User-based exceptions for sources that we do not want to decrypt"
    }
)