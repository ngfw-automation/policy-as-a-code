"""
This module defines a dictionary of tags for various purposes. Each tag is represented as a
dictionary with the following attributes:
- 'name': The name of the tag.
- 'color': The color associated with the tag.
- 'description': A brief description of the tag.

The tags are organized in a dictionary where the key is the tag short name for easy access.
"""

from typing import TypedDict, Dict, Literal
class Tag(TypedDict):
    name: str
    color: str
    description: str

group_tags: Dict[Literal["dns-sec", "infra-essentials", "break-glass", "incident-response", "block-lists", 
                         "infra-apps", "business-apps", "managed-apps-cust", "site-specific", 
                         "managed-app-categories", "managed-url-categories", "default-web-browsing", 
                         "block-non-authorized", "block-non-sanctioned-apps", "block-non-compliant-and-anonymous", 
                         "tls-d-exceptions-static", "tls-d-exceptions-dynamic", "tls-d-enforced-decryption",
                         "tls-d-decryption", "tls-d-clean-up"], Tag] = \
{
    "dns-sec": {            # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'DNS Security',
        'color':        'red',
        'description':  'Rules for secure name resolution'
    },
    "infra-essentials": {   # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Infrastructure essentials',
        'color':        'blue',
        'description':  'Rules related to infrastructure essentials: time sync, monitoring, content updates, etc.'
    },
    "break-glass": {        # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Break-glass',
        'color':        'green',
        'description':  'Rules that allow to temporarily bypass restrictions imposed by security controls further below.'
    },
    "incident-response": {  # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Incident response',
        'color':        'red',
        'description':  'Rules to isolate potentially compromised hosts from the Internet'
    },
    "block-lists": {        # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Block lists',
        'color':        'yellow',
        'description':  'Unconditional block of known malicious IPs based on PANW threat feeds.'
    },
    "infra-apps": {         # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Infrastructure apps',
        'color':        'orchid',
        'description':  'Infrastructure-related applications'
    },
    "business-apps": {      # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Business apps',
        'color':        'purple',
        'description':  'Business applications and 3rd party apps critical for the firm'
    },
    "managed-apps-cust": {  # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Managed APP customizations',
        'color':        'cyan',
        'description':  'Individual applications from managed app categories that require customizations '
                        '(i.e. downloading of executable files, dependencies etc.)'
    },
    "site-specific": {      # <==== DO NOT RENAME WITHOUT UPDATING section_defaults IN POLICY RULES
        'name':         'Site-specific applications',
        'color':        'gray',
        'description':  'Lower priority apps required only for the single site where the firewall is physically '
                        'placed; IoT rules (i.e. printers that need Internet access)'
    },
    # ===============================================================================================================
    #                                   Tags for the Security POST section of the policy
    # ===============================================================================================================
    "managed-app-categories": {             # <=== DO NOT RENAME (referenced in the POST security policy)
        'name':         'Managed APP categories',                   # <== FEEL FREE TO RENAME
        'color':        'cyan',                                     # <== FEEL FREE TO CHANGE
        'description':  'App-ID categories that at least one of businesses has expressed interest to control. 2 rules '
                        'and 1 AD group per controlled app category'
    },
    "managed-url-categories": {             # <=== DO NOT RENAME (referenced in the POST security policy)
        'name':         'Managed URL categories',                   # <== FEEL FREE TO RENAME
        'color':        'lime',                                     # <== FEEL FREE TO CHANGE
        'description':  'URL categories that at least one of businesses has expressed interest to control. 2 rules and '
                        '1 AD group per controlled URL category'
    },
    "default-web-browsing": {               # <===  DO NOT RENAME (referenced in the POST security policy)
        'name':         'Default web browsing',                     # <== FEEL FREE TO RENAME
        'color':        'gold',                                     # <== FEEL FREE TO CHANGE
        'description':  'Rules that allow access to non-controlled URL-categories and App-ID categories - any '
                        'authenticated user from any of KKR businesses has access to these apps and URLs'
    },
    "block-non-authorized": {               # <=== DO NOT RENAME (referenced in the POST security policy)
        'name':         'Block for non-authorized access',          # <== FEEL FREE TO RENAME
        'color':        'brown',                                    # <== FEEL FREE TO CHANGE
        'description':  'Rules that would trigger for non-authorized connections (managed apps provisioned in '
                        'the policy that the user is not authorised for)'
    },
    "block-non-sanctioned-apps": {          # <=== DO NOT RENAME (referenced in the POST security policy)
        'name':         'Block for non-sanctioned apps',            # <== FEEL FREE TO RENAME
        'color':        'brown',                                    # <== FEEL FREE TO CHANGE
        'description':  'Rules that would trigger for non-sanctioned applications (apps unaccounted for in the '
                        'policy and thus requiring engineering review and a configuration change)'
    },
    "block-non-compliant-and-anonymous": {  # <=== DO NOT RENAME (referenced in the POST security policy)
        'name':         'Block for non-compliant and anonymous',    # <== FEEL FREE TO RENAME
        'color':        'brown',                                    # <== FEEL FREE TO CHANGE
        'description':  'Rules that would trigger for non-authenticated or non-compliant connections (for example, '
                        'failing HIP checks for GP/Prisma users)'
    },
    # ===============================================================================================================
    #                                       Tags for decryption policy tagging
    # ===============================================================================================================
    "tls-d-exceptions-static": {                   # <=== referenced in decryption policy rules
        'name':         'Static TLS-D exceptions',                    # <== FEEL FREE TO RENAME
        'color':        'green',                                      # <== FEEL FREE TO CHANGE
        'description':  'Manual exceptions for decryption'
    },
    "tls-d-enforced-decryption": {                   # <=== referenced in decryption policy rules
        'name':         'Auto TLS-D exceptions override',                    # <== FEEL FREE TO RENAME
        'color':        'red',                                               # <== FEEL FREE TO CHANGE
        'description':  'Override for automatic decryption exceptions'
    },
    "tls-d-exceptions-dynamic": {                   # <=== referenced in decryption policy rules
        'name':         'Auto TLS-D exceptions',                    # <== FEEL FREE TO RENAME
        'color':        'green',                                    # <== FEEL FREE TO CHANGE
        'description':  'Decryption exceptions based on auto-tagging'
    },
    "tls-d-decryption": {                   # <=== referenced in decryption policy rules
        'name':         'Decryption',                               # <== FEEL FREE TO RENAME
        'color':        'red',                                      # <== FEEL FREE TO CHANGE
        'description':  'Default decryption'
    },
    "tls-d-clean-up": {                     # <=== referenced in decryption policy rules
        'name':         'Clean-up',                                 # <== FEEL FREE TO RENAME
        'color':        'blue',                                     # <== FEEL FREE TO CHANGE
        'description':  'Decryption clean-up'
    }
}
#