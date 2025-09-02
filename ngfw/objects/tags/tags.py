"""
This module defines a dictionary of tags for various purposes. Each tag is represented as a
dictionary with the following attributes:
- 'name': The name of the tag.
- 'color': The color associated with the tag.
- 'description': A brief description of the tag.

The tags are organized in a dictionary where the key is the tag name for easy access.
"""

from typing import TypedDict, Dict, Literal
class Tag(TypedDict):
    name: str
    color: str
    description: str

tags: Dict[Literal["compromised-host", "compromised-user", "ad-dc", "sanctioned-apps", "legacy-custom-apps",
"tls-d-exceptions-auto"], Tag] = \
{
    # ===============================================================================================================
    #                                           Tags for dynamic address groups
    # ===============================================================================================================
    "compromised-host": {
        'name': 'Compromised Host',
        'color': 'salmon',
        'description': 'Source IP address that needs to be isolated in its segment because it attempted to '
                       'initiate a C&C connection (supposedly compromised)'
    },
    "compromised-user": {
        'name': 'Compromised User',
        'color': 'salmon',
        'description': 'User that needs to be isolated in their segment because their host attempted to initiate '
                       'a C&C connection (supposedly compromised)'
    },
    "ad-dc":    {
        'name': 'AD-DC',
        'color': 'green',
        'description': 'Active Directory Domain Controllers'
    },
    # ===============================================================================================================
    #                                           Tags for other purposes
    # ===============================================================================================================
    "sanctioned-apps": {
        'name': 'ACME-sanctioned',
        'color': 'olive',
        'description': 'Application sanctioned for use in ACME environment (the tag needs to be assigned to '
                       'applications and then referenced in application filters as required)'
    },
    "legacy-custom-apps": {
        'name': 'ACME-custom-app-legacy',
        'color': 'brown',
        'description': 'This tag identifies custom ACME applications that are defined at a higher level device '
                       'group level (Shared, for example) and need to be allowed by Gen2 policy'
    },
    "tls-d-exceptions-auto": {              # <=== DO NOT RENAME (referenced in log forwarding profile)
        "name": "TLS-D-no-decrypt-auto",
        'color': 'magenta',
        'description': 'Destination IP addresses that need to be excluded from decryption (used for automatic '
                       'tagging only)'
    }
}