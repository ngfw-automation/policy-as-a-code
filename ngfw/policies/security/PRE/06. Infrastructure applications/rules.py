# Section for core infrastructure apps - ServiceNow, SSO, File Sharing

import settings
from ngfw.objects.tags.group_tags import group_tags

section_defaults = (
    {
        "name":                 "MUST-BE-UNIQUE-FOR-EACH-RULE",      # Default rule name
        "type":                 "universal",                         # Default rule type (universal|interzone|intrazone)
        "description":          "MUST-BE-POPULATED-FOR-EACH-RULE",   # Default description
        "tag":                  group_tags["infra-apps"]["name"],    # Default tag(s)                           +
        "group_tag":            group_tags["infra-apps"]["name"],    # Default group tag                        +

        "fromzone":             settings.ZONE_INSIDE,           # Default source zone(s)                        +
        "source":               settings.DEFAULT_INSIDE_ADDRESS,        # Default source address(es)                    +
        "negate_source":        False,                          # Default source negation
        "source_user":          "any",                          # Default source user(s)                        +

        "tozone":               settings.ZONE_OUTSIDE,          # Default destination zone(s)
        "destination":          "any",                          # Default destination address(es)               +
        "negate_destination":   False,                          # Default destination negation

        "application":          "any",                          # Application(s)            
        "service":              "application-default",          # Default service(s)                            +        
        "category":             "any",                          # URL categories

        "action":               "allow",                        # Default action                                +

        "group":                "PG-apps-regular",              # Default profile group                         + 
        "virus":                None,                           # Antivirus Security Profile
        "spyware":              None,                           # Anti-Spyware Security Profile
        "vulnerability":        None,                           # Vulnerability Protection Security Profile
        "url_filtering":        None,                           # URL Filtering Security Profile
        "file_blocking":        None,                           # File Blocking Security Profile
        "wildfire_analysis":    None,                           # Wildfire Analysis Security Profile
        "data_filtering":       None,                           # Data Filtering Security Profile

        "log_setting":          settings.LFP_DEFAULT,           # Default Log Forwarding Profile                +
        "log_start":            False,                          # Do not log at session start by default        +    
        "log_end":              True,                           # Log at session end by default                 +

        "target":               None,                           # "None" is equivalent to "all firewalls"
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
    # Section for "Infrastructure" rules - everything related to base functionality of the network.
    # This includes SSO, internal file sharing, PC/thin client build, monitoring, software updates,
    # end-point management
    # =================================================================================================================

    # ==> Service Now
    { 
        "name":         'it-service-desk',
        "application":  'service-now',
        "description":  'This rule provides access to ServiceNow - a SaaS ticketing system used by ACME for all '
                        'its IT Support related workflows. All endpoints including anonymous ones are allowed to '
                        'access it, so that even users who experience UserID-related issues were able to raise a '
                        'support case in. Update this rule to permission the system your organization uses. If your '
                        'Service Desk system is internally hosted - delete this rule.'
    },
    # Download of restricted files (executables and various installation packages)
    {
        "name":         'download-of-restricted-file-types',
        "source_user":  'known-user',
        "group":        'PG-apps-trusted',  # this profile group includes a File Filtering profile that allows executable files
        "category":     'UCL-restricted_file_download',
        "application":  ['APG-web-browsing'],
        "description":  'This rule allows ALL authenticated internal users to download files of restricted types from '
                        'selected websites. You may want to include URLs specific for your organization (for example, '
                        'URLs used to download endpoint software updates specific to the your desktop PC brand(s))'
    },
    {
        "name":         'download-of-restricted-file-types-user-edl-based',
        "source_user":  settings.GRP_PREDEFINED['grp_exe_download'].lower(),
        "group":        'PG-apps-trusted',  # this profile group includes a File Filtering profile that allows executable files
        "category":     'EDL-URL-restricted_file_download',
        "application":  ['APG-web-browsing'],
        "description":  f'This rule allows the group {settings.GRP_PREDEFINED["grp_exe_download"]} to download '
                        f'files of restricted types from selected websites. It addresses on-demand scenarios '
                        f'for individual users or groups. Executable downloads may occur from websites not '
                        f'covered by the generic apps in the specified application group. For example, many '
                        f'Terraform providers are hosted on GitHub, so you must include github-base and '
                        f'github-downloading. Conversely, the access provisioning workflow should follow '
                        f'these steps: 1) identify the URL 2) add it to the EDL 3) ensure the relevant App-ID '
                        f'is part of the rule 4) add the user to the referenced AD group'

    },
    # ===> Endpoint software updates
    {  
        "name":         'endpoint-software-updates',
        "application":  'APG-endpoint-software-updates',
        "group":        'PG-apps-trusted',
        "description":  'Software updates for applications that are permitted from all endpoints, regardless '
                        'of the management posture of these applications. In other words, include only applications '
                        'whose updates endpoints are allowed to download directly from the Internet.'
    },
    # Endpoint management
    {  
        "name":         'endpoint-management-microsoft',
        "application":  'microsoft-intune',
        "group":        'PG-apps-trusted',
        "description":  'Endpoint management for Windows OS'
    },
    {
        "name":         'endpoint-management-apple',
        "application":  'jamf',
        "group":        'PG-apps-trusted',
        "description":  'Endpoint management for Apple Mac OS'
    }
)
