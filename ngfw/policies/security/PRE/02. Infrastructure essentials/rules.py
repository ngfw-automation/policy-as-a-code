# Section for core infrastructure - Time sync, Certificate revocation checks, OS connectivity checks,
# End-point AV/EDR, general network troubleshooting, fw "helper" apps, etc.

import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":             "MUST-BE-UNIQUE-FOR-EACH-RULE",     # Default rule name
        "type":             "universal",                        # Default rule type (universal|interzone|intrazone)
        "description":      "MUST-BE-POPULATED-FOR-EACH-RULE",  # Default description
        "tag":              group_tags["infra-essentials"]["name"],   # Default tag(s)
        "group_tag":        group_tags["infra-essentials"]["name"],   # Default group tag

        "fromzone":         settings.ZONE_INSIDE,      # Default source zone(s)
        "source":           settings.DEFAULT_INSIDE_ADDRESS,            # Default source address(es)
        "negate_source":    False,                              # Default source negation
        "source_user":      "any",                              # Default source user(s)

        "tozone":               settings.ZONE_OUTSIDE,          # Default destination zone(s)
        "destination":          "any",                          # Default destination address(es)
        "negate_destination":   False,                          # Default destination negation

        "application":          "any",                          # Application(s)
        "service":              "application-default",          # Default service(s)
        "category":             "any",                          # URL categories

        "action":               "allow",                        # Default action

        "group":                "PG-apps-regular",              # Default profile group
        
        "virus":                None,                           # Antivirus Security Profile
        "spyware":              None,                           # Anti-Spyware Security Profile
        "vulnerability":        None,                           # Vulnerability Protection Security Profile
        "url_filtering":        None,                           # URL Filtering Security Profile
        "file_blocking":        None,                           # File Blocking Security Profile
        "wildfire_analysis":    None,                           # Wildfire Analysis Security Profile
        "data_filtering":       None,                           # Data Filtering Security Profile

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
    # Section for core infrastructure - Time sync, Certificate revocation checks, OS connectivity checks,
    # End-point AV/EDR, general network troubleshooting, fw "helper" apps, etc.
    # ============================================================================
    {
        "name":         "time-sync-os-default",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "destination":  ["FQDN-time.apple.com", "FQDN-time.windows.com"],
        "application":  ['ntp-base'],
        "service":      ['SVC-tcp-123', 'SVC-udp-123'],
        "description":  "Time synchronization for Windows and MacOS via their default time sources"
    },
    {
        "name":         "certificate-revocation-checks",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "application":  "ocsp",
        "service":      "SVC-tcp-80",
        "category":     ['low-risk'],
        "description":  "TLS/SSL certificate revocation checks"
    },
    {
        "name":         "endpoint-edr-antivirus",
        "fromzone":     [settings.ZONE_INSIDE],
        "application":  ['paloalto-traps'],
        "group":        "PG-apps-trusted",
        "description":  "Updates and other traffic related to Endpoint Detection and Response, and Antivirus software. [Update the rule to allow the EDR used in your organization]"
    },
    {
        "name":         "os-connectivity-checks",
        "fromzone":     [settings.ZONE_INSIDE],
        "source":       [settings.DEFAULT_INSIDE_ADDRESS],
        "application":  ['APP-windows-conn-check'],
        "description":  'Checks allowing endpoint operating systems to detect Internet connection'
    },
    {
        "name":         "fw-helper-apps",
        "fromzone":     [settings.ZONE_INSIDE],
        "application":  ["skype-probe"],
        "description":  '"Helper" apps intended to allow correct identification of associated apps (for example, '
                        '"skype-probe" is necessary to prevent "skype" from evasive behaviour and thus to be correctly'
                        ' identified)'
    },
    {
        "name":         "general-network-troubleshooting-internet",
        "fromzone":     [settings.ZONE_INSIDE],
        "source_user":  "known-user",
        "application":  ["ping", "traceroute"],
        "description":  "Common network troubleshooting tools used for basic connectivity checks. This rule covers Internet-bound troubleshooting."
    },
    {
        "name":         "enforce-tls-for-chrome-app",
        "fromzone":     [settings.ZONE_INSIDE],
        "application":  "quic",
        "action":       "deny",
        "description":  "Block for UDP-based encrypted QUIC protocol (primarily used by Google services and Chrome "
                        "browser) to be able to inspect regular TLS connections that QUIC-clients fail back to when "
                        "they are unable to communicate over UDP. This rule is based on App-ID"
    },
    {
        "name":         "enforce-tls-for-chrome-svc",
        "fromzone":     [settings.ZONE_INSIDE],
        "application":  "any",
        "service":      ["SVC-udp-80", "SVC-udp-443"],
        "action":       "deny",
        "description":  'Block for UDP-based encrypted QUIC protocol (primarily used by Google services and Chrome '
                                'browser) to be able to inspect regular TLS connections that QUIC-clients fail back to when '
                                'they are unable to communicate over UDP. This rule is based on L3/L4 only in order to catch '
                                'recent changes made by Google resulting in some of QUIC connections identified '
                                'as "unknown-udp"'
    },
    {
        "name":         "palo-alto-firewalls-to-cloud-services",
        "source":       "AG-all-palo-alto-devices",
        "application":  "APG-palo-alto-services",
        "description":  "Allows traffic from firewalls to Palo Alto Networks services"
    },
    {
        "name":         "palo-alto-firewalls-to-cloud-services-dependencies",
        "source":       "AG-all-palo-alto-devices",
        "application":  "ssl",
        "destination":  "any",
        "category":     "UCL-palo-alto-dependencies",
        "description":  "Allows all firewalls, including Prisma Access gateways, to access externally hosted EDLs and "
                        "various Palo services that do not have a purpose-built app signature"
    },
    {
        "name":         "palo-alto-firewalls-to-tac",
        "source":       "AG-all-palo-alto-devices",
        "application":  "ssh",
        "destination":  "FQDN-tacupload.paloaltonetworks.com",
        "description":  "Allows direct uploads (core files etc.) from firewalls to Palo Alto Networks TAC"
    }
)
