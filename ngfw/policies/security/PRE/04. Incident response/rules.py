import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",     # Default rule name
        "type":                 "universal",                        # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",  # Default description
        "tag":                  group_tags["incident-response"]["name"],  # Default tag(s)
        "group_tag":            group_tags["incident-response"]["name"],  # Default group tag

        "fromzone":             "any",                              # Default source zone(s)      
        "source":               settings.DEFAULT_INSIDE_ADDRESS,            # Default source address(es)
        "negate_source":        False,                              # Default source negation
        "source_user":          "any",                              # Default source user(s)

        "tozone":               "any",                              # Default destination zone(s)
        "destination":          "any",                              # Default destination address(es)
        "negate_destination":   False,                              # Default destination negation

        "application":          "any",                              # Application(s)                            
        "service":              "any",                              # Default service(s)                        
        "category":             "any",                              # URL categories

        "action":               "deny",                             # Default action                            

        "group":                None,                               # Default profile group                     
        "virus":                None,                               # Antivirus Security Profile
        "spyware":              None,                               # Anti-Spyware Security Profile
        "vulnerability":        None,                               # Vulnerability Protection Security Profile
        "url_filtering":        None,                               # URL Filtering Security Profile
        "file_blocking":        None,                               # File Blocking Security Profile
        "wildfire_analysis":    None,                               # Wildfire Analysis Security Profile
        "data_filtering":       None,                               # Data Filtering Security Profile

        "log_setting":          settings.LFP_DEFAULT,               # Default Log Forwarding Profile
        "log_start":            False,                              # Do not log at session start by default   
        "log_end":              True,                               # Log at session end by default             

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
    # Section for Incident response rules - block known bad IPs or URLs (internal EDLs)
    # =====================================================================================
    {   
        "name":         "incident-response-block-ip-source",
        "source":       "EDL-IP-full_block_src",
        "description":  "Source IP-based full block. Intended to be used by Security Operations as part of "
                        "incident response only"
    },
    {   
        "name":         "incident-response-block-ip-destination",
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "destination":  "EDL-IP-full_block_dst",
        "description":  "Destination IP-based full block. Intended to be used by Security Operations "
                        "as part of incident response only"
    },
    {   
        "name":         "incident-response-block-url",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "tozone":       settings.ZONE_OUTSIDE,
        "category":     "EDL-URL-full_block_dst",
        "description":  "URL-based full block. Intended to be used by Security Operations as part of incident response only. "
                        "Destination IP-based rule above is more preferable than this one when the destination "
                        "has a fixed IP-address (as it will block the connection at an earlier stage of the session)"
    },
    # ==================================================================================================================
    # Isolation of hosts which were tagged as compromised based on C&C traffic they produced
    # ==================================================================================================================
    {   
        "name":         "incident-response-compromised-host-isolation", 
        "source":       "DAG-compromised_hosts",
        "description":  "Provides host isolation. C&C traffic causes the source IP to be tagged and consequently be "
                        "blocked by this rule"
    }
)
