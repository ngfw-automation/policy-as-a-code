import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",     # Default rule name
        "type":                 "universal",                        # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",  # Default description
        "tag":                  group_tags['dns-sec']['name'],      # Default tag(s)
        "group_tag":            group_tags['dns-sec']['name'],      # Default group tag

        "fromzone":             settings.ZONE_INSIDE,               # Default source zone(s)
        "source":               settings.DEFAULT_INSIDE_ADDRESS,            # Default source address(es)
        "negate_source":        False,                              # Default source negation
        "source_user":          "any",                              # Default source user(s)

        "tozone":               settings.ZONE_OUTSIDE,              # Default destination zone(s)
        "destination":          "AG-rfc_1918",                      # Default destination address(es)
        "negate_destination":   False,                              # Default destination negation

        "application":          "any",                              # Application(s)
        "service":              "application-default",              # Default service(s)
        "category":             "any",                              # URL categories

        "action":               "allow",                            # Default action

        "group":                "PG-apps-regular",                  # Default profile group
        
        "virus":                None,                               # Antivirus Security Profile
        "spyware":              None,                               # Anti-Spyware Security Profile
        "vulnerability":        None,                               # Vulnerability Protection Security Profile
        "url_filtering":        None,                               # URL Filtering Security Profile
        "file_blocking":        None,                               # File Blocking Security Profile
        "wildfire_analysis":    None,                               # Wildfire Analysis Security Profile
        "data_filtering":       None,                               # Data Filtering Security Profile

        "log_setting":          settings.LFP_DEFAULT,
        "log_start":            False,
        "log_end":              True,

        "target":               None,
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
    # ============================================================================
    # Rule for capturing the traffic sinkholed by Palo Alto Networks DNS Security
    # ============================================================================
    {
        "name":         "incident-response-palo-dns-sinkhole",
        "destination":  f"H-dns-sinkhole-{settings.DNS_SINKHOLE_RESOLVED_ADDRESS}_32",
        "application":  "any",
        "service":      "any",
        "action":       "drop",
        "description":  "Intercepts all connections to the `sinkhole` "
                        "destination which indicates that respective host triggered a DNS-based security control "
                        "(DNS-security via the anti-spyware profile on the name resolution rules)"
    },
    # =====================================================================
    #           Rules for DNS Name Resolution on domain controllers
    # =====================================================================
    {
        "name":         "name-resolution-domain-controllers",
        "group":        "PG-apps-risky",
        "fromzone":     settings.ZONE_INSIDE,
        "source":       "DAG-domain-controllers",
        "destination":  "any",
        "application":  "dns-base",
        "service":      ["SVC-udp-53", "SVC-tcp-53"],
        "description":  "Name resolution via any public servers, including Root Hints. Update the destination if your "
                        "DCs have hardcoded forwarders (ensure they have at least 3 forwarders configured unless you're "
                        "happy for them to fail back to root hints)"
    },
    # =====================================================================
    #       Rules for DNS Name Resolution on regular network endpoints
    # =====================================================================
    {
        "name":         "name-resolution-all-clients",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "destination":  ["H-open_dns-208.67.222.222_32", "H-open_dns-208.67.220.220_32"],
        "application":  "dns-base",
        "service":      ["SVC-udp-53", "SVC-tcp-53"],
        "description":  "Name resolution for clients that are not configured to use the DCs for name resolution."
                        "Disable this rule if you do not have such clients."
    },
    {
        "name":         "name-resolution-encrypted-dns-block",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "destination":  "any",
        "application":  ["dns-over-https", "dns-over-tls"],
        "action":       "deny",
        "description":  "We explicitly block all encrypted DNS traffic that firewalls are unable to inspect "
                        "because we do not decrypt this traffic. You may want to decrypt TCP/853 to identify DoT "
                        "more reliably."
    }
)
