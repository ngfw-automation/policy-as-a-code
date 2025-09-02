"""
Functions for creating and managing log forwarding profiles in PAN-OS.

This module provides functionality to:

- Create log forwarding profiles for traffic, threat, URL, and wildfire logs
- Configure automatic tagging for failed decryption attempts
- Configure automatic tagging for command and control traffic
- Set up enhanced application logging
- Handle different configurations for standalone firewalls vs. Panorama
- Support security incident response through HTTP profiles
"""

from panos.objects           import LogForwardingProfile, LogForwardingProfileMatchList, LogForwardingProfileMatchListAction
from ngfw.objects.tags.tags  import tags
from panos.firewall          import Firewall
from rich import print
import settings


def create_log_forwarding_profiles(target, panos_device):

    # We need only one LFP for all our policy rules. Therefore, it does not make much sense
    # to work on separating the code from data. We'll define all elements of the LFP
    # in this function.
    print("Creating log forwarding profile(s)...")
    # Create a base profile object
    profile = LogForwardingProfile(name=settings.LFP_DEFAULT, description='This is a default log forwarding profile. It logs all '
                                                             'Traffic, URL, Threat, and Wildfire events to '
                                                             'Panorama/CDL; also tags destination IPs that '
                                                             'cause decryption errors, and source IPs that '
                                                             'produced C&C traffic ', enhanced_logging=True)

    # This match list will identify sessions which ended with the session end reason "decrypt-error"
    # or "decrypt-unsupport-param" which means that the firewall attemted to decrypt them but
    # these attempts failed.
    tagging_match_list_tls_d = LogForwardingProfileMatchList(name='tag-failed-decryption-dst-ip',
                                                             log_type='traffic',
                                                             filter='(session_end_reason eq decrypt-error) or '
                                                                    '(session_end_reason eq decrypt-unsupport-param)',
                                                             send_to_panorama=True)

    # This match list will identify sessions that exhibited attributes of C&C connections
    # (triggered command-and-control IPS signature of High or Critical severity and were blocked
    # by respective Anti-Spyware profile)
    tagging_match_list_compromised_ips = \
        LogForwardingProfileMatchList(name='tag-compromised-host',
                                      log_type='threat',
                                      filter=f'(name-of-threatid contains "command and control") and '
                                             f'(severity geq medium) and (action neq alert) and '
                                             f'(action neq allow) and (zone.dst eq {settings.ZONE_OUTSIDE})',
                                      http_profiles=settings.SERVER_PROFILE_HTTP_SIR_IPS if settings.ENABLE_SIR_GENERATION_FOR_HOST_ISOLATION else None,
                                      send_to_panorama=True)

    # to test the isolation feature you can replace the filter string with the string below:
    # "(name-of-threatid contains "eicar") and (severity geq medium) and (action neq alert) and (action neq allow)"
    # and then attempt to download the Eicar test file from eicar.org

    #
    if isinstance(panos_device, Firewall):
        # Configuration for this LFP is created based on the assumption
        # that a standalone firewall does not need to synchronize the tagged IP addresses
        # with other devices, therefore the "target" parameter is set to "localhost".
        # This would definitely be the case for a Lab firewall.
        # However, you may have multiple firewalls without a Panorama.
        # If this is the case, and you want to synchronize the tags between all your firewalls
        # you can use UserID agent on one of the firewalls or on a Windows server. Configure the target parameter accordingly
        tagging_match_list_action_tls_d = \
            LogForwardingProfileMatchListAction(name='tag-tls-d-exception-dst-ip',
                                                action_type='tagging',
                                                action='add-tag',
                                                tags=tags["tls-d-exceptions-auto"]["name"],
                                                target='destination-address',
                                                registration='localhost',
                                                timeout=settings.TAG_TIMEOUT_AUTO_TAGGING_TLS_D)

        tagging_match_list_action_compromised_host = \
            LogForwardingProfileMatchListAction(name='tag-compromised-src-ip',
                                                action_type='tagging',
                                                action='add-tag',
                                                tags=tags["compromised-host"]["name"],
                                                target='source-address',
                                                registration='localhost',
                                                timeout=settings.TAG_TIMEOUT_AUTO_TAGGING_COMPROMISED_HOST)

    else:
        # The match lists for Panorama are identical to the firewall ones in everything but the registration target
        tagging_match_list_action_tls_d = \
            LogForwardingProfileMatchListAction(name='tag-tls-d-exception-dst-ip',
                                                action_type='tagging',
                                                action='add-tag',
                                                tags=tags["tls-d-exceptions-auto"]["name"],
                                                target='destination-address',
                                                registration='panorama',
                                                timeout=settings.TAG_TIMEOUT_AUTO_TAGGING_TLS_D)

        tagging_match_list_action_compromised_host = \
            LogForwardingProfileMatchListAction(name='tag-compromised-src-ip',
                                                action_type='tagging',
                                                action='add-tag',
                                                tags=tags["compromised-host"]["name"],
                                                target='source-address',
                                                registration='panorama',
                                                timeout=settings.TAG_TIMEOUT_AUTO_TAGGING_COMPROMISED_HOST)


    # Construction of the log forwarding profile using the components created above
    # =============================================================================

    # Adding the respective actions to the match lists
    tagging_match_list_tls_d.add(tagging_match_list_action_tls_d)
    tagging_match_list_compromised_ips.add(tagging_match_list_action_compromised_host)

    # Adding the match lists (with their actions) to the profiles
    profile.add(tagging_match_list_tls_d)
    profile.add(tagging_match_list_compromised_ips)

    # Here we add standard match lists in accordance with PANW best practices
    profile.add(LogForwardingProfileMatchList(name='traffic-enhanced-app-logging',    log_type='traffic',    filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='threat-enhanced-app-logging',     log_type='threat',     filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='url-enhanced-app-logging',        log_type='url',        filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='wildfire-enhanced-app-logging',   log_type='wildfire',   filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='data-enhanced-app-logging',       log_type='data',       filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='tunnel-enhanced-app-logging',     log_type='tunnel',     filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='auth-enhanced-app-logging',       log_type='auth',       filter='All Logs', send_to_panorama=True))
    profile.add(LogForwardingProfileMatchList(name='decryption-enhanced-app-logging', log_type='decryption', filter='All Logs', send_to_panorama=True))

    # Finally, we add the LFP to our target (Panorama device group or a firewall VSYS) and execute the apply()
    # method which will initiate XAPI call to the device
    target.add(profile).apply()
