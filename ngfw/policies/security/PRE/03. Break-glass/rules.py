import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",     # Default rule name
        "type":                 "universal",                        # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",  # Default description
        "tag":                  group_tags["break-glass"]["name"],        # Default tag(s)
        "group_tag":            group_tags["break-glass"]["name"],        # Default group tag

        "fromzone":             [settings.ZONE_INSIDE],             # Default source zone(s)
        "source":               [settings.DEFAULT_INSIDE_ADDRESS],          # Default source address(es)
        "negate_source":        False,                              # Default source negation
        "source_user":          "any",                              # Default source user(s)

        "tozone":               settings.ZONE_OUTSIDE,              # Default destination zone(s)
        "destination":          "any",                              # Default destination address(es)
        "negate_destination":   False,                              # Default destination negation

        "application":          "any",                              # Application(s)            
        "service":              "any",                              # Default service(s)        
        "category":             "any",                              # URL categories

        "action":               "allow",                            # Default action        

        "group":                "PG-break-glass",                   # Default profile group 
        
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
    # =================================================================================================================
    # Section for "break-glass" rules: ip source-based, ip destination-based, url-based, user-based
    # =================================================================================================================
    {
        "name":         "break-glass-ip-source",
        "source":       "EDL-IP-break_glass_src",
        "description":  "Source IP-based rule intended to be a temporary bypass of security controls imposed by "
                        "the part of the policy below the 'break-glass' section. This rule can be engaged only "
                        "in emergency. Ensure you have a clear understanding of the implications of using this rule. "
    },
    {
        "name":         "break-glass-ip-destination",
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "destination":  "EDL-IP-break_glass_dst",
        "description":  "Destination IP-based rule intended to be a temporary bypass of security controls imposed by "
                        "the part of the policy below the 'break-glass' section. This rule can be engaged only "
                        "in exceptional circumstances."
    },
    {
        "name":         "break-glass-url",
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "category":     "EDL-URL-break_glass_dst",
        "description":  "URL-based rule intended to be a temporary bypass of security controls imposed by the part "
                        "of the policy below the 'break-glass' section. This rule can be engaged only "
                        "in exceptional circumstances."
    }
)
