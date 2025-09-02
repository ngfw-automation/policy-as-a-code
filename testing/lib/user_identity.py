"""
User identity utilities for PAN-OS policy testing.

This module provides utilities for managing user identity in PAN-OS firewalls.
It includes functions for mapping users to IP addresses and groups, setting source IP
addresses for testing, and configuring domain prefixes and decryption groups.

Global Variables:
    SOURCE_IP_FOR_TESTING: The source IP address used for testing.
    DOMAIN_PREFIX: The domain prefix used for user and group names.
    DECRYPTION_GROUP: The name of the decryption group.
    MAPPED_USER: The currently mapped user.
    MAPPED_GROUP: The currently mapped group.

Functions:
    map_user_to_ip_and_group: Map a user to an IP address and group.
    set_source_ip_for_testing: Set the source IP address for testing.
    set_domain_prefix: Set the domain prefix for user and group names.
    set_decryption_group: Set the decryption group name.
    create_user_group_mapping: Create a user-to-group mapping.
"""

from __future__ import annotations
import os
import re
import sys
from typing import List
from panos.userid import UserId

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


from lib.rich_output import console
import settings



# ── globals exposed for others to read (display_menu imports us) ──────────────
SOURCE_IP_FOR_TESTING = ""
DOMAIN_PREFIX = ""
DECRYPTION_GROUP = "ug-decryption"
DECRYPTION_ENABLED = False
MAPPED_USER = ""
MAPPED_GROUP = ""

# ──────────────────────────────────────────────────────────────────────────────


def map_user_to_ip_and_group(panos_device, ip, group, user="user1",
                             suppress_output=False,
                             add_decryption_group=False,
                             skip_group_name=False) -> bool:
    """
    Maps a user to an IP address and optionally assigns them to specific groups in a Palo Alto Networks
    firewall. This function ensures the user is removed from any previously assigned groups before adding them to the new group(s).
    The operation also optionally handles adding the user to a decryption group and updating login data.

    Args:
        panos_device: The firewall device object to which the user and IP mappings will be applied.
        ip: The IP address to bind the user to.
        group: The group to assign the user to, if applicable.
        user: The username to be mapped. If not provided, defaults to "user1".
        suppress_output: If True, suppresses console output throughout the process.
        add_decryption_group: If True, adds the user to the predefined decryption group along
            with the specified group. This parameter is deprecated and will be ignored if DECRYPTION_ENABLED is set.
        skip_group_name: If True, skips adding the user to the specified group and only performs
            other configured actions.

    Returns:
        bool: True if the mapping was successfully established, otherwise False.
    """
    global DOMAIN_PREFIX, DECRYPTION_GROUP, MAPPED_USER, MAPPED_GROUP, DECRYPTION_ENABLED
    if not panos_device:
        console.print("[red]No firewall object[/red]"); return False

    uid = UserId(panos_device)

    uname = f"{DOMAIN_PREFIX}\\{user}" if DOMAIN_PREFIX else user
    grp   = f"{DOMAIN_PREFIX}\\{group}" if (DOMAIN_PREFIX and group) else group
    dec   = f"{DOMAIN_PREFIX}\\{DECRYPTION_GROUP}" if DOMAIN_PREFIX else DECRYPTION_GROUP


    # Before we proceed with adding the user to the required group(s)
    # we need to insure the user is not a member of any other groups

    # First, we build a list of all groups the user is a member of
    # As we go we also store the membership data so that we do not affect
    # other users who might be in the same group
    if not suppress_output:
        console.print(f"[blue]Retrieving[/blue] group membership information...")
    groups = uid.get_groups()
    group_members_dict = {}
    groups_where_uname_is_member = []
    for g in groups:
        members = uid.get_group_members(g)
        group_members_dict[g] = set(members)
        if uname in members:
            groups_where_uname_is_member.append(g)

    if not suppress_output and groups_where_uname_is_member:
        console.print(f"[yellow]Found[/yellow] user {uname} in groups: {', '.join(groups_where_uname_is_member)}")

    # Now we remove the user from all groups where it is a member
    if not suppress_output and groups_where_uname_is_member:
        console.print(f"[yellow]Removing[/yellow] user {uname} from existing groups...")
    for g in groups_where_uname_is_member:
        # Remove the user from the group by updating the group's member list
        members = group_members_dict[g].copy()
        members.discard(uname)
        uid.set_group(g, list(members))
        if not suppress_output:
            console.print(f"  [green]Removed[/green] user {uname} from group {g}")

    # Now we add the user to the required group(s)
    ok = True
    try:
        if not skip_group_name and grp:
            if not suppress_output:
                console.print(f"[yellow]Adding[/yellow] user {uname} to group {grp}...")
            # Add the user to the group by updating the group's member list
            members = group_members_dict.get(grp, set()).copy()
            members.add(uname)
            uid.set_group(grp, list(members))
            if not suppress_output:
                console.print(f"  [green]Added[/green] user {uname} to group {grp}")

        # Use DECRYPTION_ENABLED flag to determine whether to add user to decryption group
        # Fall back to add_decryption_group parameter for backward compatibility
        should_add_to_decryption = (DECRYPTION_ENABLED or add_decryption_group) and DECRYPTION_GROUP

        if should_add_to_decryption:
            if not suppress_output:
                console.print(f"[yellow]Adding[/yellow] user {uname} to decryption group {dec}...")
            # Add the user to the decryption group by updating the group's member list
            members = group_members_dict.get(dec, set()).copy()
            members.add(uname)
            uid.set_group(dec, list(members))
            if not suppress_output:
                console.print(f"  [green]Added[/green] user {uname} to decryption group {dec}")

        # Finally, we login the user
        if not suppress_output:
            console.print(f"[yellow]Logging in[/yellow] user {uname} with IP {ip}...")
        uid.login(uname, ip, timeout=None)

        if not suppress_output:
            groups_added = []
            if not skip_group_name and grp:
                groups_added.append(grp)
            if add_decryption_group and DECRYPTION_GROUP:
                groups_added.append(dec)

            groups_str = f" to groups: {', '.join(groups_added)}" if groups_added else ""
            console.print(f"[green]Successfully mapped[/green] {uname} → {ip}{groups_str}")

        # Update the global variables for mapped user and group
        global MAPPED_USER, MAPPED_GROUP
        MAPPED_USER = user
        MAPPED_GROUP = group
    except Exception as e:
        ok = False
        if not suppress_output:
            console.print(f"[red]Error[/red] {str(e)}")
    return ok

# ── simple interactive helpers for the globals ───────────────────────────────
def set_source_ip_for_testing():
    """
    Set the source IP address for testing.

    This function prompts the user to enter a source IP address for testing and validates
    that it is in the correct format. The IP address is stored in the global variable
    SOURCE_IP_FOR_TESTING.

    Returns:
        None
    """
    global SOURCE_IP_FOR_TESTING
    while True:
        ip = input("New source IP: ")
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
            SOURCE_IP_FOR_TESTING = ip
            console.print(f"[green]Source IP set[/green] → {ip}")
            break
        console.print("[red]Bad IP[/red]")
    input("Enter to continue…")


def set_domain_prefix(panos=None):
    """
    Set the domain prefix for user and group names.

    This function prompts the user to decide whether to add a domain prefix to user and
    group names. If the user chooses to add a prefix, they can enter a custom prefix or
    use the default from settings. The prefix is stored in the global variable DOMAIN_PREFIX.
    If a user and group are already mapped, the mapping will be refreshed with the new prefix.

    Args:
        panos: The PAN-OS firewall object. If provided, user mapping will be updated immediately.

    Returns:
        None
    """
    global DOMAIN_PREFIX, MAPPED_USER, MAPPED_GROUP

    # Store the old prefix for comparison
    old_prefix = DOMAIN_PREFIX

    if input("Add domain prefix? (y/N): ").lower().startswith("y"):
        DOMAIN_PREFIX = input(f"Domain prefix [`{settings.AD_DOMAIN_NAME}`]: ") \
                        or settings.AD_DOMAIN_NAME
    else:
        DOMAIN_PREFIX = ""

    console.print(f"[green]Prefix = {DOMAIN_PREFIX or 'None'}[/green]")

    # If a user and group are already mapped and the prefix has changed,
    # refresh the mapping with the new prefix
    if MAPPED_USER and MAPPED_GROUP and SOURCE_IP_FOR_TESTING and panos and old_prefix != DOMAIN_PREFIX:
        console.print(f"[yellow]Refreshing mapping for user {MAPPED_USER} with new domain prefix...[/yellow]")
        success = map_user_to_ip_and_group(panos, SOURCE_IP_FOR_TESTING, MAPPED_GROUP, MAPPED_USER)
        if success:
            console.print(f"[green]Successfully refreshed mapping with new domain prefix[/green]")
        else:
            console.print(f"[red]Failed to refresh mapping with new domain prefix[/red]")
    elif MAPPED_USER and MAPPED_GROUP and SOURCE_IP_FOR_TESTING and old_prefix != DOMAIN_PREFIX:
        console.print(f"[yellow]Mapping will be refreshed with new domain prefix on next mapping[/yellow]")

    input("Enter to continue…")


def set_decryption_group(panos=None):
    """
    Toggle decryption on/off.

    This function toggles the decryption flag. When enabled, the user will be added to the
    decryption group. When disabled, the user will be removed from the decryption group.
    The decryption can only be enabled when a user and a group are mapped.

    Args:
        panos: The PAN-OS firewall object. If provided, group membership will be updated immediately.

    Returns:
        None
    """
    global DECRYPTION_ENABLED, MAPPED_USER, MAPPED_GROUP

    # Check if user and group are mapped
    if DECRYPTION_ENABLED:
        # If decryption is currently enabled, disable it
        DECRYPTION_ENABLED = False
        console.print("[green]Decryption disabled[/green]")

        # If user is mapped, remove from decryption group
        if MAPPED_USER and SOURCE_IP_FOR_TESTING and panos:
            console.print(f"[yellow]Removing user {MAPPED_USER} from decryption group...[/yellow]")
            # Call map_user_to_ip_and_group to update the group membership
            # We pass the current mapped group to maintain that mapping
            success = map_user_to_ip_and_group(panos, SOURCE_IP_FOR_TESTING, MAPPED_GROUP, MAPPED_USER)
            if success:
                console.print(f"[green]User {MAPPED_USER} removed from decryption group[/green]")
            else:
                console.print(f"[red]Failed to remove user {MAPPED_USER} from decryption group[/red]")
        elif MAPPED_USER and SOURCE_IP_FOR_TESTING:
            console.print(f"[yellow]User {MAPPED_USER} will be removed from decryption group on next mapping[/yellow]")
    else:
        # Can only enable decryption if user and group are mapped
        if not MAPPED_USER or not MAPPED_GROUP:
            console.print("[red]Cannot enable decryption - user and group must be mapped first[/red]")
        else:
            DECRYPTION_ENABLED = True
            console.print("[green]Decryption enabled[/green]")

            # If user is mapped, add to decryption group
            if MAPPED_USER and SOURCE_IP_FOR_TESTING and panos:
                console.print(f"[yellow]Adding user {MAPPED_USER} to decryption group...[/yellow]")
                # Call map_user_to_ip_and_group to update the group membership
                # We pass the current mapped group to maintain that mapping
                success = map_user_to_ip_and_group(panos, SOURCE_IP_FOR_TESTING, MAPPED_GROUP, MAPPED_USER)
                if success:
                    console.print(f"[green]User {MAPPED_USER} added to decryption group[/green]")
                else:
                    console.print(f"[red]Failed to add user {MAPPED_USER} to decryption group[/red]")
            elif MAPPED_USER and SOURCE_IP_FOR_TESTING:
                console.print(f"[yellow]User {MAPPED_USER} will be added to decryption group on next mapping[/yellow]")

    input("Enter to continue…")


def create_user_group_mapping(panos):
    """
    Create a user-to-group mapping.

    This function prompts the user for a group name and username, and then maps the user
    to the group and the current source IP address using the map_user_to_ip_and_group function.
    The source IP address must be set before calling this function.
    If decryption is enabled, the user will also be added to the decryption group.

    Args:
        panos: The PAN-OS firewall object

    Returns:
        None
    """
    if not panos:
        console.print("[red]Connect to firewall first[/red]"); return
    ip = SOURCE_IP_FOR_TESTING
    if not ip:
        console.print("[red]Source IP not set. Please set the source IP first (option 1)[/red]")
        input("Enter to continue…")
        return
    group = input("Group name: ")
    if not group:
        console.print("[red]Group cannot be empty[/red]"); return
    user = input("User name [user1]: ") or "user1"

    # Map user to group and IP
    # The map_user_to_ip_and_group function will check DECRYPTION_ENABLED
    # to determine whether to add the user to the decryption group
    success = map_user_to_ip_and_group(panos, ip, group, user)

    # If mapping was successful and decryption is enabled, show a message
    if success and DECRYPTION_ENABLED:
        console.print(f"[green]User {user} added to decryption group because decryption is enabled[/green]")

    input("Enter to continue…")
