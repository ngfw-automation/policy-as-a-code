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
        "name":         'servicenow-app',
        "application":  'service-now',
        "description":  'This rule provides access to ServiceNow for all endpoints including anonymous ones so that '
                        'even users who experience UserID-related issues were able to raise a support case in '
                        'ServiceNow.'
    },
    # Download of restricted files (executables and various installation packages)
    {
        "name":         'download-of-restricted-file-types',
        "source_user":  'known-user',
        "group":        'PG-apps-trusted',
        "category":     'UCL-restricted_file_download',
        "application":  ['APG-web-browsing'],
        "description":  'This rule allows all users to download files of restricted types from selected websites'
    },
    {
        "name":         'download-of-restricted-file-types-user-edl-based',
        "source_user":  settings.GRP_PREDEFINED['grp_exe_download'].lower(),
        "group":        'PG-apps-trusted',
        "category":     'EDL-URL-restricted_file_download',
        "application":  ['APG-web-browsing'],
        "description":  f'This rule allows the group {settings.GRP_PREDEFINED["grp_exe_download"]} to download '
                        f'files of restricted types from selected websites'
    },
    # ===> Endpoint software updates
    {  
        "name":         'endpoint-software-updates',
        "application":  'APG-endpoint-software-updates',
        "group":        'PG-apps-trusted',
        "description":  'Software updates for applications that we are happy to allow from all endpoints regardless '
                        'the management posture of these applications'
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
    },
    {
        "name":         'google-storage-as-cdn',
        "application":  ['google-cloud-storage-base', 'google-cloud-storage-download'],
        "category":     'content-delivery-networks',
        "description":  'Google Cloud Storage (RESTful online file storage web service) used as CDN by some web-sites '
                        'to store their artifacts (pictures and other files)'
    }
)
