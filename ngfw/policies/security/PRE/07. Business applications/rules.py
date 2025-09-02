import settings
from   ngfw.objects.tags.group_tags   import group_tags
from   lib.auxiliary_functions         import get_source_user_for_category

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",      # Default rule name
        "type":                 "universal",                         # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",   # Default description
        "tag":                  group_tags["business-apps"]["name"], # Default tag(s)
        "group_tag":            group_tags["business-apps"]["name"], # Default group tag

        "fromzone":             settings.ZONE_INSIDE,                # Default source zone(s)
        "source":               settings.DEFAULT_INSIDE_ADDRESS,             # Default source address(es)
        "negate_source":        False,                               # Default source negation
        "source_user":          "known-user",                        # Default source user(s)

        "tozone":               settings.ZONE_OUTSIDE,               # Default destination zone(s)
        "destination":          "any",                               # Default destination address(es)
        "negate_destination":   False,                               # Default destination negation

        "application":          "any",                               # Application(s)
        "service":              "application-default",               # Default service(s)
        "category":             "any",                               # URL categories

        "action":               "allow",                             # Default action

        "group":                "PG-apps-regular",                   # Default profile group
        "virus":                None,                                # Antivirus Security Profile
        "spyware":              None,                                # Anti-Spyware Security Profile
        "vulnerability":        None,                                # Vulnerability Protection Security Profile
        "url_filtering":        None,                                # URL Filtering Security Profile
        "file_blocking":        None,                                # File Blocking Security Profile
        "wildfire_analysis":    None,                                # Wildfire Analysis Security Profile
        "data_filtering":       None,                                # Data Filtering Security Profile

        "log_setting":          settings.LFP_DEFAULT,                # Default Log Forwarding Profile
        "log_start":            False,                               # Do not log at session start by default
        "log_end":              True,                                # Log at session end by default

        "target":               None,                                # "None" is equivalent to "all firewalls"
        "negate_target":        False,                               # Do not negate the target
        "disabled":             False                                # Enable the rule
    }
)
# ==============================================================================================
#
#   Create security rules below this comment section.
#   Define only attributes that differ from the section defaults specified above this comment
#
# ==============================================================================================
section_rules = (
    # The ACME's in-house generic trusted web apps
    {
        "name":         'acme-generic-app',
        "group":        'PG-apps-trusted',
        "application":  'APG-web-browsing',
        "service":      ['service-https', 'service-http'],
        "category":     'UCL-acme-generic-app',
        "description":  "This rule provides access to everything in the ACME's EXAMPLE.COM and EXAMPLE.NET domains"
                        "provided this is regular TLS traffic over TCP/443 or HTTP over TCP/80"
    },
    # Legacy apps defined in higher level device groups and provisioned via tagging and an application filter
    {
        "name":         'acme-custom-apps-legacy',
        "group":        'PG-apps-trusted',
        "application":  f'{settings.PREFIX_FOR_APPLICATION_FILTERS}custom-apps-legacy',
        "description":  'This rule covers ACME custom application signatures that were deployed at a higher level '
                        'device group (for example, Shared) and thus propagate down to this policy DG and need to be allowed.'
    },
    # Business apps approved for use by all employees ACME-wide regardless of their category
    {
        "name":         'calendly-app',
        "application":  'calendly',

        "description":  'Provides access to Calendly - SaaS-based application that provides cross-business meeting '
                        'scheduling service'
    },
        # ==> Microsoft 365 (Office 365) for authenticated users <===
    {
        "name":         'm365-apps-optimize-and-allow-ip',
        "source_user":  'known-user',
        "group":        'PG-apps-trusted',
        "destination":  ['EDL-IP-m365_worldwide_any_allow', 'EDL-IP-m365_worldwide_any_optimize'],
        "application":  ['APG-office365-core-web', 'APG-office365-dep-http', 'APG-office365-dep-non-http'],
        "description":  'Access to M365 Optimize and Allow categories of IP addresses.'
    },
    {
        "name":         'm365-apps-allow-url',
        "source_user":  'known-user',
        "group":        'PG-apps-trusted',
        "application":  ['APG-office365-core-web', 'APG-office365-dep-http'],
        "category":     ['EDL-URL-m365_worldwide_any_allow', 'EDL-URL-m365_worldwide_any_optimize'],
        "description":  'M365'
    },
    {
        "name":         'm365-apps-all-url',
        "source_user":  'known-user',
        "group":        'PG-apps-allowed-exe',
        "application":  ['APG-office365-core-web', 'APG-office365-dep-http'],
        "category":     ['EDL-URL-m365_worldwide_any_all'],
        "description":  'M365'
    },
    {
        "name":         'm365-dependencies-all-ip',
        "source_user":  'known-user',
        "destination":  ['EDL-IP-m365_worldwide_any_all'],
        "application":  ['APG-office365-dep-non-http'],
        "description":  'M365'
    },
    {
        "name":         'm365-sfb-skype',
        "source_user":  'known-user',
        "destination":  ['EDL-IP-m365_worldwide_any_all'],
        "application":  ['skype', 'unknown-udp'],
        "service":      'SVC-udp-3478-3481',
        "description":  'M365'
    },
    {
        "name":         'm365-sfb-stun',
        "source_user":  'known-user',
        "destination":  ['EDL-IP-m365_worldwide_any_all'],
        "application":  ['stun'],
        "service":      'any',
        "description":  'M365'
    },
    {
        "name":         'm365-sfb',
        "source_user":  'known-user',
        "destination":  ['EDL-IP-m365_worldwide_any_all'],
        "application":  ['ms-lync-audio', 'ms-lync-base', 'ms-lync-video'],
        "description":  'M365'
    },
    {
        "name":         'm365-apps-non-edl',
        "source_user":  'known-user',
        "group":        'PG-apps-trusted',
        "destination":  'any',
        "application":  ['APG-office365-core-web'],
        "description":  'M365 applications provisioned based on AppID signatures only (this rule addresses the issue '
                        'of some apps such as PowerBI not being covered by M365 EDLs).'
    }
)
