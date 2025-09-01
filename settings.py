"""
This file defines global variables/constants for the `main.py` and other modules in the /lib folder.
"""
POLICY_VERSION     = '1.0.10'
POLICY_DATE        = '17 August 2025'

# Minimum required versions for key modules
MIN_PAN_OS_PYTHON_VERSION = "1.12.1"
MIN_PAN_PYTHON_VERSION    = "0.25.0"

DEBUG_OUTPUT            = False # When enable outputs all XML API requests, including
                                 # API keys - use with caution.
VERBOSE_OUTPUT          = True   # defines verbosity of script output
SUPPRESS_WARNINGS       = False  # Defines whether to suppress warnings or not (i.e. a missing category in app/url requirements)
API_ERROR_LOG_FILENAME  = "logs/api_errors.log"
PRIVACY_MODE            = True
LOG_API_CALLS           = True
API_CALLS_LOG_FILENAME  = "logs/api_calls.log"

RICH_TRACEBACKS            = True   # Use Rich traceback
RICH_TRACEBACKS_SHOW_VARS  = False  # show the local variables in each frame
# (can expose sensitive info and produce very long output depending on the content of runtime variables - use with caution)

# Default for user input
DEFAULT_ADMIN_USERNAME  = "admin"

# Firewall address used to assess the policy, run tests and reports
DEFAULT_FIREWALL = "192.168.0.1"

# Default vsys name - referenced only in policy-test.py
DEFAULT_VSYS = "vsys1"

# The flag below means that when a commit operation is active or a commit is pending, the operation will fail.
# When there are uncommitted changes for the user performing the operation, they will be rolled back before performing
# the multiconfig operation.
MAKE_THE_FIRST_MULTI_CONFIG_TRANSACTIONAL = True

# If the blow flags set to TRUE, the script will delete the respective existing policy rules
# before, optionally, creating new ones from code
DELETE_CURRENT_SECURITY_POLICY          = True
DELETE_CURRENT_DECRYPTION_POLICY        = True
DELETE_CURRENT_NAT_POLICY               = False
DELETE_CURRENT_AUTHENTICATION_POLICY    = False
DELETE_CURRENT_OVERRIDE_POLICY          = False
DELETE_CURRENT_PBF_POLICY               = False

# If the below flags set to TRUE, the script will create the respective new policy rules
CREATE_SECURITY_POLICY       = True
CREATE_NAT_POLICY            = False
CREATE_AUTHENTICATION_POLICY = False
CREATE_OVERRIDE_POLICY       = False
CREATE_PBF_POLICY            = False

# When this flag is set to True the script will provision both Security and Decryption policy
# if the flag is set to False then only Security policy will be provisioned
CREATE_DECRYPTION_POLICY_FIREWALL = True
CREATE_DECRYPTION_POLICY_PANORAMA = True

# ====================================================================================
# Flags for bulk operations
# ====================================================================================

BULK_RULE_DELETION              = True
BULK_LFP_DELETION               = False
BULK_TAG_DELETION               = False

BULK_ADDRESS_CREATION           = True

# =================================================================================
#   Other flags
# =================================================================================

# These flags are used to add domain prefix to Source User identity specified for managed categories
# If your target is bound to an Active Directory domain you need to set

ADD_DOMAIN_PREFIX_FOR_LAB = True            # Set to TRUE if your lab environment
                                            # is connected to Active Directory

ADD_DOMAIN_PREFIX_FOR_PROD = True           # Set to TRUE if your production environment
                                            # is connected to Active Directory


ENABLE_SIR_GENERATION_FOR_HOST_ISOLATION  = False  # Set to True to make policy send HTTP API queries
                                                   # when a host is tagged for isolation because of C&C traffic detected

IMPORT_APP_VULN_SPYWARE_SIGNATURES = True   # Set to TRUE to import custom applications, vulnerability and spyware signatures

PERFORM_VALIDATION_CHECKS   = True
SOFT_VALIDATION_ONLY        = True # Do not interrupt the script if validation fails

VALIDATE_RULE_NAMES         = True # Perform validation for rule names
VALIDATE_RULE_DESCRIPTIONS  = True # Perform validation for rule descriptions

# This is a RegEx pattern for policy rule names.
# It is more restrictive than the default convention:
#   - we allow only lower case letters, numbers, dashes and underscores in the rule name
VALIDATION_PATTERN_FOR_RULE_NAMES        = r"^[a-z0-9][a-z0-9_-]{0,60}$"

# This is a RegEx pattern for policy rule descriptions.
# It is more restrictive than the default convention: set the minumum length to 12 characters and maximum to 1024 characters
VALIDATION_PATTERN_FOR_RULE_DESCRIPTIONS = r"^.{12,1024}$"


# Prefixes for automated naming

PREFIX_FOR_APPLICATION_GROUPS   = "APG-"
PREFIX_FOR_APPLICATION_FILTERS  = "APF-"
PREFIX_FOR_SERVICE_OBJECTS      = "SVC-"

# =================================================================================
# Zone names referenced in the policy rules
# =================================================================================

ZONE_INSIDE             = 'INSIDE'
ZONE_OUTSIDE            = 'OUTSIDE'


# Default generic source address for all rules in the policy
# in a Lab environment you may want to substitute the default "any" with a particular IP-address or Address
# Object/Group. If you go for an Address Object - make sure it gets defined.

DEFAULT_INSIDE_ADDRESS = 'AG-internal_network'

#

DNS_SINKHOLE_ADDRESS            = "sinkhole.paloaltonetworks.com"
DNS_SINKHOLE_RESOLVED_ADDRESS   = "198.135.184.22"
DEFAULT_DNS_SERVER              = "208.67.222.222"  # OpenDNS primary server
DNS_OVER_HTTPS_URL              = "https://doh.opendns.com/dns-query"  # OpenDNS DoH service
DOH_DOT_CERT_VERIFY             = True

# User groups for predefined rules with a specific purpose

GRP_PREDEFINED = {
    'grp_tls_d_exception':  'UG-decryption_break-glass',      # User group name for TLS-D break-glass rule
    'grp_tls_d_decrypt':    'UG-decryption',                  # User group name for TLS-D decryption rules
    'grp_exe_download':     'UG-restricted-file-download',    # User group name for those allowed to download files
                                                              # of restricted types from a pre-approved list of websites
}

# When this flag is set to True the script would attempt to create AD groups
# for all managed categories and all "pre-defined" groups from the list above
# If the groups already exist the script WILL NOT attempt to re-create them from scratch
# Thus it is safe to leave this flag On
CREATE_AD_GROUPS = False
# Path to the AD OU where the groups need to be created
# such as 'OU=Firewall Groups,OU=Groups,DC=example,DC=com' # Replace with your own CN
AD_OU_CANONICAL_NAME    = '' # Replace with your own CN
AD_DOMAIN_NAME          = 'example_domain'                                 # Replace with your own domain name
AD_DOMAIN_NAME_DNS      = 'example.com'                                    # Replace with your own DNS domain name

# When this flag is set the script would retrieve the current list of
# domain controllers and create relevant Address Objects
UPDATE_AD_DC_LIST       = False

# When this flag is set to True the script will create all local user groups
# that are mentioned in the policy rules
CREATE_GROUPS_USED_IN_POLICY_FIREWALL = False

# Creation of example security profiles (in order to be created they must be predefined in the CSV files
# and be named "Example Profile")
CREATE_EXAMPLE_SECURITY_PROFILES      = False

# Use a cookie file to store last used username
USE_COOKIE                            = True

# ======================================================================================
#                                   File names
# ======================================================================================

# Policy deployment targets (used to generate the interactive menu and unattended execution)
POLICY_TARGETS_FILENAME                    = "requirements/policy_targets.json"

# Business requirements for URL/App categories are defined in these two files
APP_CATEGORIES_REQUIREMENTS_FILENAME       = "requirements/categories_app.csv"
URL_CATEGORIES_REQUIREMENTS_FILENAME       = "requirements/categories_url.csv"

# This file contains runtime settings kept across script executions
# i.e. last admin user name or interactive menu choice
COOKIE_FILENAME                             = "misc/cookie.json"
CA_BUNDLE                                   = "misc/mozilla-and-internal-ca-bundle.pem"

# The script will generate the template files below if they are missing
APP_CATEGORIES_TEMPLATE_FILENAME            = "requirements/templates/template_categories_app.csv"
URL_CATEGORIES_TEMPLATE_FILENAME            = "requirements/templates/template_categories_url.csv"


APPLICATION_GROUPS_FILENAME                 = "ngfw/objects/application groups/app_groups.json"

# This file contains a file with all managed categories for ServiceNow
SERVICE_NOW_CATEGORIES_FILENAME             = "export/servicedesk/managed_categories.csv"

# These files contain definitions for EDLs
EDLS_FILENAME                               = "ngfw/objects/external dynamic lists/edls.csv"
CUSTOM_URL_CATEGORIES_FILENAME              = "ngfw/objects/custom objects/url category/custom-url-categories.csv"

# This file contains definitions of address objects
ADDRESS_OBJECTS_FILENAME                    = "ngfw/objects/addresses/address_objects.csv"

# This file contains definitions of service objects
SERVICE_OBJECTS_FILENAME                    = "ngfw/objects/services/service_objects.csv"

# These files contain test URLs for the test rig
TEST_URLS_FILENAME                          = "testing/panw-test-resources/urls.csv"
TEST_FQDNS_FILENAME                         = "testing/panw-test-resources/domains.csv"

# This file contains the list of applications that must be tagged
TAGGED_APPLICATIONS_FILENAME                = "ngfw/objects/applications/tagged_applications.json"


# ======================================================================================
#                                   Folder names
# ======================================================================================

DATA_PATTERNS_FOLDER                        = "ngfw/objects/custom objects/data patterns"
SECURITY_PROFILES_DATA_FILTERING_FOLDER     = "ngfw/objects/security profiles/data filtering"
SECURITY_PROFILES_VULNERABILITY_FOLDER      = "ngfw/objects/security profiles/vulnerability protection"
SECURITY_PROFILES_ANTISPYWARE_FOLDER        = "ngfw/objects/security profiles/anti-spyware"
SECURITY_PROFILES_ANTIVIRUS_FOLDER          = "ngfw/objects/security profiles/antivirus"
SECURITY_PROFILES_WILDFIRE_FOLDER           = "ngfw/objects/security profiles/wildfire"
SECURITY_PROFILES_FILE_BLOCKING_FOLDER      = "ngfw/objects/security profiles/file blocking"
SECURITY_PROFILES_URL_FILTERING_FOLDER      = "ngfw/objects/security profiles/url-filtering"
DECRYPTION_PROFILES_FOLDER                  = "ngfw/objects/decryption/decryption profile"

SECURITY_RULES_PRE_FOLDER                   = "ngfw/policies/security/PRE"
DECRYPTION_RULES_PRE_FOLDER                 = "ngfw/policies/decryption/PRE"
DECRYPTION_RULES_POST_FOLDER                = "ngfw/policies/decryption/POST"

# directories with custom signatures and response pages
CUSTOM_APPLICATION_SIGNATURES_FOLDER        = "ngfw/objects/applications"
CUSTOM_VULNERABILITY_SIGNATURES_FOLDER      = "ngfw/objects/custom objects/vulnerability"
CUSTOM_SPYWARE_SIGNATURES_FOLDER            = "ngfw/objects/custom objects/spyware"
CUSTOM_RESPONSE_PAGES_FOLDER                = "ngfw/device/response pages/<target_environment>"

CERTIFICATE_BUNDLE_FILENAME                 = "misc/mozilla-and-internal-ca-bundle.pem"

# ========================================================
# Dictionary mappings for files with business requirements
# ========================================================

# Possible values in the column "Action" of the App categories metadata
APP_ACTION_ALERT    = "do not manage"   # app category will be allowed via a common rule (several categories in one rule with Source User set to "known-user")
APP_ACTION_MANAGE   = "manage"          # app category will be managed via two dedicated rules - one would allow access for specified group, and another one would deny for 'known-user'
APP_ACTION_DENY     = "deny"            # category will be denied (no dedicated deny rules will be created - the connection will hit a risk-based deny rule)

# Possible values in the column "Action" of the URL categories metadata
url_action_alert    = "do not manage"   # A URL category with this action will be permitted (set to Alert in a common generic rule)
URL_ACTION_MANAGE   = "manage"          # A URL category with this action will be managed via a dedicated rule - it will also be blocked in the common generic rule
URL_ACTION_CONTINUE = "continue"        # A URL category with this action will be speed-bumped ('continue' action) in the common generic rule
URL_ACTION_OVERRIDE = "override"        # A URL category with this action will trigger the override action
URL_ACTION_DENY     = "deny"            # A URL category with this action will be denied in the common generic rule; there will be NO opportunity to enable a URL from this category other than allowing the URL via an Allow List (EDL).
URL_ACTION_ALLOW    = "allow"           # A URL with this action will have action set to Allow in the common generic rule (thus it will never be logged as a matching criterion);
# The latter action is recommended for "High Risk", "Medium Risk" and "Low Risk" categories specifically so that relevant
# URLs were logged based on their "functional/content" category rather than risk.
# the Risk classification will still be logged in the **list** of categories for each URL

# ========================================================
#          Profiles
# ========================================================


# Log forwarding profiles (the need to have two profiles comes from the fact standalone firewall
# deployments need to register Tagged addresses and users with the local User-ID subsystem
# rather than with the Panorama User-ID )

LFP_DEFAULT         = "LFP-default"         # Default Log Forwarding Profile Name for Panorama-based deployments

# Security and decryption profile names
SP_VULNR                    = "VPP-default"                     # Vulnerability profile applied to controlled URL categories with Low risk, and to controlled Apps
SP_VULNR_RISKY              = "VPP-strict"                      # Vulnerability profile applied to controlled URL categories with Medium and High risk
SP_VIRUS                    = "AVP-default"                     # Virus profile applied to controlled URL categories with Low risk, and to controlled Apps
SP_VIRUS_RISKY              = "AVP-strict"                      # Virus profile applied to controlled URL categories with Medium and High risk
SP_SPYWARE                  = "ASP-default"                     # Spyware profile applied to controlled URL categories with Low risk, and to controlled Apps
SP_SPYWARE_RISKY            = "ASP-strict"                      # Spyware profile applied to controlled URL categories with Medium and High risk
SP_FILE                     = "FBP-default"                     # File blocking profile applied to controlled URL categories with Low risk, and to controlled Apps
SP_FILE_RISKY               = "FBP-strict"                      # File blocking profile applied to controlled URL categories with Medium and High risk
SP_FILE_ALLOW_EXE           = "FBP-default-allow-exe"           # File blocking profile applied to controlled URL categories where executables can be tolerated (such as Internet Conferencing)
SP_FILE_LOG_ONLY            = "FBP-log-only"                    # File blocking profile applied to highly trusted traffic only - i.e. m365
SP_WILDFIRE                 = "WFP-default"                     # Wildfire profile applied to all policy rules
SP_DATA_FILTERING           = "DFP-default"                     # Data Filtering Profile applied to all rules
SP_URL_CTRLD                = "UFP-log-only"                    # URL filtering profile applied to rules with controlled categories (where categories specified as a matching criterion - hence the "log only" in the profile)
SP_URL_CTRLD_RISKY          = "UFP-log-only-detailed"           # URL filtering profile applied to rules with controlled categories with Medium and High risk (where categories specified as a matching criterion - hence the "log only" in the profile)
SP_URL_CTRLD_APPS           = "UFP-block-known-bad"             # Only known malicious URLs should be blocked by this profile (all others need to be set to Alert)
SP_URL_NON_CTRLD            = "UFP-block-known-bad-ctrl"        # URL filtering profile applied to rules with controlled categories (where categories are NOT specified as a matching criterion - hence the blocking actions in the profile)
SP_URL_NON_CTRLD_RISKY      = "UFP-block-known-bad-ctrl-risky"  # URL filtering profile applied to rules with controlled categories with Medium and High risk  (where categories are NOT specified as a matching criterion - hence the blocking actions in the profile)
# URL filtering profile applied to the rule managing traffic to the UNKNOWN category
SP_URL_NON_CTRLD_EXCEPTION  = "UFP-block-known-bad-ctrl-excpt"


# Server profiles (these profiles must be defined in a Template applied to the firewall)
SERVER_PROFILE_HTTP_SIR_IPS = "SRV-HTTP-sir-cmd-and-ctrl-ips"  # HTTP server profile that ServiceNow SIR creation upon C&C detection via IPS
SERVER_PROFILE_HTTP_SIR_URL = "SRV-HTTP-sir-cmd-and-ctrl-url"  # HTTP server profile that ServiceNow SIR creation upon C&C detection via URL

# Names of the decryption profiles used by the decryption policy
DP_DEFAULT          = "DP-default_decryption"
DP_STRICT           = "DP-strict_decryption"
DP_COMPATIBLE       = "DP-compatible_decryption"
DP_NO_DECRYPTION    = "DP-no_decryption"

# ==========================================================
#            Tags related settings
# ==========================================================


# Tag timeouts for dynamic tagging (minutes)
TAG_TIMEOUT_AUTO_TAGGING_TLS_D              = 720  # 12 hours
TAG_TIMEOUT_AUTO_TAGGING_COMPROMISED_HOST   = 0  #

# When the flag is set to True
# the script will
PREPEND_TAGS_WITH_NUMBER                        = True

# When this flag is set to True
# the script will ignore group tags
# specified in rules definitions and create tags
# identical to subfolder names
# found in the {security_rules_pre_folder}.
#
# Tag colors will be taken consequently from {color_names}
# This function is not currently implemented
USE_FOLDER_NAMES_AS_GROUP_TAGS                  = False
#
CREATE_CONSECUTIVE_TAG_FOR_SITE_SPECIFIC_RULES  = True
CREATE_CONSECUTIVE_TAGS_FOR_POST_RULES          = True

# ========================================================
#          Color-related settings
# ========================================================

# These standard color names can be converted to color codes by the color_code() method
# of the Tag class (for example panos.objects.Tag.color_code("red"))

color_names = [
    'red', 'green', 'blue', 'yellow', 'copper', 'orange', 'purple', 'gray',
    'light green', 'cyan', 'light gray', 'blue gray', 'lime', 'black', 'gold',
    'brown', 'olive', 'maroon', 'red-orange', 'yellow-orange', 'forest green',
    'turquoise blue', 'azure blue', 'cerulean blue', 'midnight blue', 'medium blue',
    'cobalt blue', 'violet blue', 'blue violet', 'medium violet', 'medium rose',
    'lavender', 'orchid', 'thistle', 'peach', 'salmon', 'magenta', 'red violet',
    'mahogany', 'burnt sienna', 'chestnut'
]
