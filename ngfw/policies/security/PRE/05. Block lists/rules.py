import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",     # Default rule name
        "type":                 "universal",                        # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",  # Default description
        "tag":                  group_tags["block-lists"]["name"],          # Default tag(s)                             +++
        "group_tag":            group_tags["block-lists"]["name"],          # Default group tag                          +++

        "fromzone":             settings.ZONE_INSIDE,      # Default source zone(s)                     +++
        "source":               settings.DEFAULT_INSIDE_ADDRESS,            # Default source address(es)
        "negate_source":        False,                              # Default source negation
        "source_user":          "any",                              # Default source user(s)

        "tozone":               settings.ZONE_OUTSIDE,              # Default destination zone(s)                +++
        "destination":          "any",                              # Default destination address(es)
        "negate_destination":   False,                              # Default destination negation

        "application":          "any",                              # Application(s)                             +++
        "service":              "any",                              # Default service(s)                         +++
        "category":             "any",                              # URL categories

        "action":               "deny",                             # Default action                             +++

        "group":                None,                               # Default profile group
        "virus":                None,                               # Antivirus Security Profile
        "spyware":              None,                               # Anti-Spyware Security Profile
        "vulnerability":        None,                               # Vulnerability Protection Security Profile
        "url_filtering":        None,                               # URL Filtering Security Profile
        "file_blocking":        None,                               # File Blocking Security Profile
        "wildfire_analysis":    None,                               # Wildfire Analysis Security Profile
        "data_filtering":       None,                               # Data Filtering Security Profile

        "log_setting":          settings.LFP_DEFAULT,               # Default Log Forwarding Profile             +++
        "log_start":            False,                              # Do not log at session start by default     +++
        "log_end":              True,                               # Log at session end by default              +++

        "target":               None,                               # "None" is equivalent to "all firewalls"
        "negate_target":        False,
        "disabled":             False
    }
)
# ==============================================================================================
#
#   Create security rules below this comment section.
#   Define only attributes that differ from the section defaults specified above this comment
#
# ==============================================================================================
section_rules = (
    # =====================================================================================
    # Section for a global block of known bad IPs (feeds from Palo Alto Networks).
    # False positives may be temporarily overridden via the break-glass rules
    # =========================================================================================
    {
        "name":         "block-known-bad-ip-destinations",
        "source":       settings.DEFAULT_INSIDE_ADDRESS,
        "destination":  ["panw-bulletproof-ip-list", 
                         "panw-highrisk-ip-list", 
                         "panw-known-ip-list", 
                         "panw-torexit-ip-list"], 
        "description":  "Blocks all connections to known 'bad' IP addresses according to Palo Alto Networks"
    },
    {
        "name":         "block-known-bad-ip-sources",
        "fromzone":     settings.ZONE_OUTSIDE,
        "tozone":       "any",
        "source":       ["panw-bulletproof-ip-list",
                         "panw-highrisk-ip-list",
                         "panw-known-ip-list",
                         "panw-torexit-ip-list"],
        "destination":  "any", 
        "description":  "Blocks all connections from known 'bad' IP addresses according to Palo Alto Networks"
    },
    # Geo-location-based blocking
    {  
        "name":         "block-sanctioned-countries-inbound",
        "fromzone":     settings.ZONE_OUTSIDE,
        "tozone":       "any",
        "source":       ["AF"],
        "destination":  "any",
        "description":  "Blocks all inbound connections from sanctioned countries and geographical regions"
    },
    {
        "name":         "block-sanctioned-countries-outbound",
        "destination":  ["AF"],
        "description":  "Blocks all outbound connections to sanctioned countries and geographical regions"
    }
)
