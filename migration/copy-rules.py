"""
Copy security policy rules with dependencies between Panorama Device Groups.

This module provides functionality to copy security policy rules that have a specific tag
from one Panorama Device Group to another, including all referenced objects and their
dependencies. The script handles complex dependency resolution for nested object groups
and ensures proper object creation order.

Support:
    * Targets PAN-OS/Panorama 10.1 and later. At startup, the script queries Panorama's
      system information and warns if the version is below 10.1.

Features:
    - Copies security rules based on tag matching
    - Recursively resolves and copies all object dependencies
    - Handles Address/AddressGroup, Service/ServiceGroup, Application/ApplicationGroup objects
    - Supports External Dynamic Lists, Custom URL Categories, Application Filters
    - Provides conflict resolution strategies (skip or overwrite)
    - Supports dry-run mode for preview
    - Maintains rule positioning in destination policy
    - Reuses existing objects by searching Shared first, then the destination DG

Only objects that do not already exist in the special 'Shared' Device Group are copied.
If an object with the same name already exists in the destination DG (or Shared),
behavior is controlled by the --on-conflict parameter. Shared objects are never deleted.

Example:
    python copy-rules.py \\
        --panorama 192.0.2.10 --username admin \\
        --src-dg "Engineering" --dst-dg "Staging" \\
        --tag "migrate" --on-conflict overwrite --commit

Requirements:
    pip install pan-os-python

Note:
    This script requires appropriate administrative privileges on the Panorama device
    and network connectivity to the management interface.
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys
from typing import List, Optional, Sequence, Tuple, Type

from panos.base import PanObject
from panos.errors import PanDeviceError
from panos.panorama import DeviceGroup, Panorama
from panos.policies import SecurityRule
from panos.objects import (
    AddressGroup,
    AddressObject,
    ApplicationObject,
    ApplicationFilter,
    ApplicationGroup,
    CustomUrlCategory,
    Edl,
    ServiceGroup,
    ServiceObject,
    Tag,
)


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

class Config:
    """Configuration for the rule copying process.

    This class encapsulates configuration options that control the behavior of the
    rule copying algorithm, including conflict resolution and execution mode.

    Attributes:
        on_conflict (str): Strategy for handling existing objects ('skip' or 'overwrite').
        dry_run (bool): Whether to run in preview mode without making actual changes.
        verbose (bool): If True, emit extra diagnostics (e.g., XML previews).
    """

    def __init__(self):
        """Initialize configuration with default values.

        The default configuration uses 'skip' conflict resolution and normal execution mode.
        These values are typically overridden by command-line arguments.
        """
        self.on_conflict = "skip"  # Default value, will be overridden by CLI args
        self.dry_run = False
        self.verbose = False


# -----------------------------------------------------------------------------
# Version helpers (Panorama 10.1+)
# -----------------------------------------------------------------------------

def _parse_semver(v: str) -> Tuple[int, int, int]:
    """Parse a PAN-OS-style version string into (major, minor, patch) integers.

    The function extracts the first three numeric components and ignores any
    build suffixes (e.g., '-h4').

    Args:
        v (str): Version string, for example '11.0.2-h3' or '10.1.0'.

    Returns:
        Tuple[int, int, int]: Parsed (major, minor, patch). Missing parts default to zero.
    """
    nums = re.findall(r"\d+", v or "")
    major = int(nums[0]) if len(nums) > 0 else 0
    minor = int(nums[1]) if len(nums) > 1 else 0
    patch = int(nums[2]) if len(nums) > 2 else 0
    return major, minor, patch


def _is_version_at_least(version: str, minimum: str) -> bool:
    """Return True if `version` >= `minimum` based on numeric components.

    Args:
        version (str): Actual version string reported by Panorama.
        minimum (str): Minimum required version string.

    Returns:
        bool: True if version is greater than or equal to the minimum.
    """
    v = _parse_semver(version)
    m = _parse_semver(minimum)
    return v >= m


def warn_if_panorama_too_old(pano: Panorama, minimum: str = "10.1") -> None:
    """Warn if Panorama software version is below `minimum`.

    This function issues an operational warning only. It does not block execution.

    Args:
        pano (Panorama): Connected Panorama object.
        minimum (str): Minimum supported Panorama version (major.minor[.patch]).
    """
    try:
        res = pano.op("show system info", xml=True)
        ver = None
        try:
            ver = res.findtext(".//system/sw-version") or res.findtext(".//sw-version")
        except Exception:
            ver = None
        if ver and not _is_version_at_least(ver, minimum):
            print(
                f"⚠ Warning: Panorama reports version '{ver}', which is below {minimum}. "
                "This script targets PAN-OS/Panorama 10.1+ and may not function correctly."
            )
    except Exception:
        # If version lookup fails, proceed without blocking; some environments restrict op commands.
        pass


# -----------------------------------------------------------------------------
# Low-level helpers
# -----------------------------------------------------------------------------

def connect(host: str, user: str, pw: str) -> Panorama:
    """Establish an authenticated connection to a Panorama management server.

    This function creates and initializes a connection to a Palo Alto Networks Panorama
    management platform, which is essential for all subsequent device group operations,
    rule copying, and object management tasks. The connection includes authentication
    validation and system information retrieval to ensure the Panorama instance is
    ready for API operations.

    The returned Panorama instance serves as the entry point for all device group
    discovery, rule querying, object copying, and configuration commit operations
    throughout the rule migration workflow.

    Args:
        host (str): Hostname or IP address of the Panorama management server.
        user (str): Administrative username with sufficient privileges for rule and object operations.
        pw (str): Password for the specified administrative user account.

    Returns:
        Panorama: Ready-to-use Panorama instance, prepared for device group and policy operations.

    Raises:
        PanDeviceError: If connection fails due to network/auth issues or insufficient privileges.
    """
    pano = Panorama(host, user, pw)
    pano.refresh_system_info()
    return pano


def get_device_group(pano: Panorama, dg_name: str) -> DeviceGroup:
    """Retrieve and validate a specific Device Group from Panorama for rule operations.

    This function serves as a critical validation step in the rule copying workflow by
    locating and preparing a Device Group for subsequent operations. It not only fetches
    the Device Group by name but also refreshes its configuration to ensure all child
    objects (security rules, address objects, service objects, etc.) are current and
    accessible for the migration process.

    The function acts as a safeguard against invalid Device Group names and ensures
    that both source and destination Device Groups exist and are accessible before
    attempting any rule or object copying operations. This prevents partial migrations
    and provides early error detection.

    Args:
        pano (Panorama): The connected Panorama instance with established authentication.
        dg_name (str): Name of the Device Group to locate and validate (case-sensitive).

    Returns:
        DeviceGroup: The refreshed DeviceGroup with child objects loaded for migration.

    Raises:
        SystemExit: If the Device Group cannot be found or accessed.
    """
    dg = DeviceGroup(dg_name)
    pano.add(dg)
    try:
        dg.refresh()
    except PanDeviceError as exc:
        sys.exit(f"❌ Device group '{dg_name}' not found: {exc}")
    return dg


def rules_with_tag(src_dg: DeviceGroup, tag: str) -> List[SecurityRule]:
    """Discover and filter security rules by tag for selective rule migration.

    This function implements the core rule selection logic for the migration workflow
    by identifying all security rules in a Device Group that contain a specific tag.
    It serves as the entry point for rule discovery, determining exactly which rules
    will be included in the migration process based on the user-specified tag criteria.

    The function refreshes the Device Group's security rule collection to ensure
    it operates on the most current rule set, then performs case-sensitive tag
    matching to identify rules marked for migration. This selective approach allows
    administrators to control exactly which rules are copied, enabling phased
    migrations and targeted rule deployments.

    The tag-based filtering is essential for maintaining control over large rule
    sets and preventing unintended rule copying in production environments.

    Args:
        src_dg (DeviceGroup): Source device group containing the security rules to search.
        tag (str): Tag string to match (case-sensitive, exact match).

    Returns:
        List[SecurityRule]: Rules that contain the specified tag (may be empty).

    Note:
        The function performs exact string matching on rule tags. Rules without
        tags or with non-matching tags are excluded.
    """
    # Keep the original behavior of refreshing the DG's rule collection
    src_dg.refresh_children(SecurityRule)
    return [r for r in src_dg.security_rules if tag in (r.tag or [])]


# -----------------------------------------------------------------------------
# Object-handling helpers
# -----------------------------------------------------------------------------

def _first_existing(parent: DeviceGroup, cls: Type[PanObject], name: str) -> Optional[PanObject]:
    """Find the first existing object of specified type and name in Shared or parent DG.

    This function implements the Panorama object resolution hierarchy by searching first
    in the Shared scope (Panorama root), then in the specified parent device group. This
    matches Panorama's natural inheritance behavior and prevents unnecessary duplication.

    Args:
        parent (DeviceGroup): The parent device group to search in.
        cls (Type[PanObject]): The PanObject class type to search for.
        name (str): The name of the object to find.

    Returns:
        Optional[PanObject]: The first matching object found, or None if no object exists.
    """
    # Search order: Panorama root (Shared) first, then this DG.
    root = parent.nearest_pandevice()  # Panorama root
    for space in (root, parent):
        if space is None:
            continue
        # Correct signature: find(name, class_type)
        found = space.find(name, cls)
        if found is not None:
            return found
    return None


def _can_be_tagged(obj: PanObject) -> bool:
    """Determine if a PAN-OS object supports tag assignment.

    This function identifies object types that do not support tagging in PAN-OS.
    Some object types like Custom URL Categories, External Dynamic Lists, and
    Service objects have limitations on tag assignment due to platform constraints.

    Args:
        obj (PanObject): The PAN-OS object to check for tag support.

    Returns:
        bool: True if the object supports tagging, False otherwise.

    Note:
        The list of non-taggable types is based on PAN-OS platform limitations
        and may vary between software versions.
    """
    non_taggable_types = (
        CustomUrlCategory,  # URL categories don't support tags
        Edl,                # External Dynamic Lists don't support tags
        ServiceGroup,       # Service groups don't support tags
        ServiceObject,      # Service objects don't support tags
    )
    return not isinstance(obj, non_taggable_types)


def _ensure_tags_exist(dest_parent: DeviceGroup, obj: PanObject, config: Config) -> bool:
    """Ensure all tags assigned to an object exist in the destination device group.

    This function checks if all tags referenced by a source object exist in the destination
    device group and creates any missing tags. This is essential because object creation
    will fail if referenced tags don't exist in the destination.

    Args:
        dest_parent (DeviceGroup): Destination device group that should contain the tags.
        obj (PanObject): The source object instance (or SecurityRule) that may have tag assignments.
        config (Config): Runtime configuration controlling dry-run mode and other behaviors.

    Returns:
        bool: True if all tags were created successfully or already exist, False if any
        tag creation failed.

    Note:
        Tag creation failures are logged but don't prevent object creation from
        being attempted, as some tags might be optional or recoverable.
    """
    if not _can_be_tagged(obj):
        return True
    if not hasattr(obj, "tag") or not obj.tag:
        return True

    Tag.refreshall(dest_parent)
    success = True
    for tag_name in obj.tag:
        # Correct signature: find(name, class_type)
        existing_tag = dest_parent.find(tag_name, Tag)
        if existing_tag is None:
            if config.dry_run:
                print(f"    ↳ would create tag '{tag_name}'")
                continue
            try:
                new_tag = Tag(name=tag_name)
                dest_parent.add(new_tag)
                new_tag.create()  # Commit tag creation to Panorama
                print(f"    ↳ created tag '{tag_name}'")
            except PanDeviceError as e:
                print(f"    ❌ Error creating tag '{tag_name}': {e}")
                success = False
        elif config.verbose:
            print(f"    ↳ tag '{tag_name}' exists")
    return success


def ensure_object(dest_parent: DeviceGroup, obj: PanObject, config: Config) -> bool:
    """Ensure an object exists in the destination device group with conflict resolution.

    This function implements the core object copying logic with configurable conflict
    resolution. It handles existing object detection, tag dependency resolution, and
    actual object creation in the correct order.

    The behavior depends on the config.on_conflict value:
      - 'skip': Leave existing objects unchanged and skip copying.
      - 'overwrite': Delete existing DG objects and recreate from source.
        Shared objects are never deleted and are always reused.

    Args:
        dest_parent (DeviceGroup): Destination device group that should contain the object.
        obj (PanObject): The source object instance to clone to the destination.
        config (Config): Runtime configuration controlling conflict resolution and dry-run mode.

    Returns:
        bool: True if object was created successfully or already exists, False on error.

    Note:
        Tag dependencies are resolved before object creation to prevent failures.
        Object creation continues even if some tag creation fails.
    """
    existing = _first_existing(dest_parent, obj.__class__, obj.name)
    if existing is not None:
        # Do not delete or recreate Shared objects; always reuse them
        if isinstance(getattr(existing, "parent", None), Panorama):
            if config.verbose:
                print(f"    ↳ {obj.__class__.__name__} '{obj.name}' found in Shared – reusing")
            return True

        if config.on_conflict == "skip":
            print(f"    ↳ {obj.__class__.__name__} '{obj.name}' exists – skipping")
            return True
        elif config.on_conflict == "overwrite":
            print(f"    ↳ {obj.__class__.__name__} '{obj.name}' exists – overwriting")
            if config.dry_run:
                print(f"    ↳ would delete and recreate '{obj.name}'")
                return True
            try:
                existing.delete()
            except PanDeviceError as e:
                print(f"    ❌ Error deleting existing {obj.__class__.__name__} '{obj.name}': {e}")
                return False
        else:  # pragma: no cover – argparser guarantees validation
            raise ValueError(f"Unknown on_conflict mode '{config.on_conflict}'")

    # Resolve tag dependencies before object creation to prevent failures
    if not _ensure_tags_exist(dest_parent, obj, config):
        print(f"    ⚠ Warning: Some tags for {obj.__class__.__name__} '{obj.name}' could not be created")
        # Continue with object creation even if tag creation failed

    if config.dry_run:
        print(f"    ↳ would copy {obj.__class__.__name__} '{obj.name}'")
        if config.verbose:
            try:
                print(obj.element_str().strip())
            except Exception:
                pass
        return True

    # Create a clone of the source object with all its attributes
    clone = obj.__class__(**obj.about())  # Shallow copy of all object attributes
    dest_parent.add(clone)

    try:
        clone.create()
        print(f"    ↳ copied {obj.__class__.__name__} '{obj.name}'")
        return True
    except PanDeviceError as e:
        print(f"    ❌ Error creating {obj.__class__.__name__} '{obj.name}': {e}")
        return False


# -----------------------------------------------------------------------------
# Recursive dependency helpers
# -----------------------------------------------------------------------------

def copy_app_dependencies(app_obj: PanObject, src_dg: DeviceGroup, dest_dg: DeviceGroup, config: Config) -> bool:
    """Recursively copy application object dependencies with proper ordering.

    This function handles the complex dependency resolution for Application Groups,
    which can contain nested Application Groups, Application Objects, and Application
    Filters. It uses a bottom-up recursive approach to ensure all dependencies are
    created before their parent objects.

    Args:
        app_obj (PanObject): ApplicationObject, ApplicationGroup, or ApplicationFilter.
        src_dg (DeviceGroup): Source device group containing the objects to copy.
        dest_dg (DeviceGroup): Destination device group where objects should be created.
        config (Config): Runtime configuration controlling conflict resolution and dry-run mode.

    Returns:
        bool: True if all dependencies were copied successfully; False otherwise.

    Note:
        Only ApplicationGroup objects have dependencies; other application object types
        return True immediately as they have no nested members to process.
    """
    if isinstance(app_obj, ApplicationGroup):
        # ApplicationGroup uses 'value' for members
        members: Sequence[str] = app_obj.value or []
        success = True

        for member_name in members:
            # Correct signature: find(name, class_type)
            member = (
                src_dg.find(member_name, ApplicationObject)      # Standard application
                or src_dg.find(member_name, ApplicationGroup)    # Nested application group
                or src_dg.find(member_name, ApplicationFilter)   # Application filter
            )
            if member is None:
                # Also check Shared (Panorama root) to avoid false warnings.
                root = src_dg.nearest_pandevice()
                shared_member = (
                    (root and root.find(member_name, ApplicationObject))
                    or (root and root.find(member_name, ApplicationGroup))
                    or (root and root.find(member_name, ApplicationFilter))
                )
                if shared_member is not None:
                    if config.verbose:
                        print(f"    ↳ using Shared application '{member_name}' (no copy needed)")
                    continue
                print(f"    ⚠ Warning: Application member '{member_name}' not found")
                continue

            if isinstance(member, ApplicationGroup):
                if not copy_app_dependencies(member, src_dg, dest_dg, config):
                    success = False

            if not ensure_object(dest_dg, member, config):
                success = False

        return success

    return True  # Non-group application objects have no dependencies


def copy_address_dependencies(addr_obj: PanObject, src_dg: DeviceGroup, dest_dg: DeviceGroup, config: Config) -> bool:
    """Recursively copy address object dependencies with proper ordering.

    This function handles the dependency resolution for Address Groups, which can contain
    nested Address Groups, Address Objects, and External Dynamic Lists (EDLs). It uses
    a bottom-up recursive approach to ensure all dependencies are created before their
    parent objects.

    Args:
        addr_obj (PanObject): AddressObject, AddressGroup, or Edl.
        src_dg (DeviceGroup): Source device group containing the objects to copy.
        dest_dg (DeviceGroup): Destination device group where objects should be created.
        config (Config): Runtime configuration controlling conflict resolution and dry-run mode.

    Returns:
        bool: True if all dependencies were copied successfully; False otherwise.

    Note:
        Only AddressGroup objects have dependencies; AddressObject and Edl objects
        return True immediately as they have no nested members to process.
    """
    if isinstance(addr_obj, AddressGroup):
        # AddressGroup uses 'static_value' for static member names
        static_members: Sequence[str] = addr_obj.static_value or []
        success = True

        for member_name in static_members:
            # Correct signature: find(name, class_type)
            member = (
                src_dg.find(member_name, AddressObject)   # Standard address object
                or src_dg.find(member_name, AddressGroup) # Nested address group
                or src_dg.find(member_name, Edl)          # External Dynamic List
            )
            if member is None:
                # Also check Shared (Panorama root) to avoid false warnings.
                root = src_dg.nearest_pandevice()
                shared_member = (
                    (root and root.find(member_name, AddressObject))
                    or (root and root.find(member_name, AddressGroup))
                    or (root and root.find(member_name, Edl))
                )
                if shared_member is not None:
                    if config.verbose:
                        print(f"    ↳ using Shared address object '{member_name}' (no copy needed)")
                    continue
                print(f"    ⚠ Warning: Address member '{member_name}' not found")
                continue

            if isinstance(member, AddressGroup):
                if not copy_address_dependencies(member, src_dg, dest_dg, config):
                    success = False

            if not ensure_object(dest_dg, member, config):
                success = False

        return success

    return True  # Non-group address objects have no dependencies


def copy_service_dependencies(svc_obj: PanObject, src_dg: DeviceGroup, dest_dg: DeviceGroup, config: Config) -> bool:
    """Recursively copy service object dependencies with proper ordering.

    This function handles the dependency resolution for Service Groups, which can contain
    nested Service Groups and Service Objects. It uses a bottom-up recursive approach
    to ensure all dependencies are created before their parent objects.

    Args:
        svc_obj (PanObject): ServiceObject or ServiceGroup.
        src_dg (DeviceGroup): Source device group containing the objects to copy.
        dest_dg (DeviceGroup): Destination device group where objects should be created.
        config (Config): Runtime configuration controlling conflict resolution and dry-run mode.

    Returns:
        bool: True if all dependencies were copied successfully; False otherwise.

    Note:
        Only ServiceGroup objects have dependencies; ServiceObject objects return True
        immediately as they have no nested members to process.
    """
    if isinstance(svc_obj, ServiceGroup):
        # ServiceGroup uses 'value' for member names
        members: Sequence[str] = svc_obj.value or []
        success = True

        for member_name in members:
            # Correct signature: find(name, class_type)
            member = (
                src_dg.find(member_name, ServiceObject)   # Standard service object
                or src_dg.find(member_name, ServiceGroup) # Nested service group
            )
            if member is None:
                # Also check Shared (Panorama root) to avoid false warnings.
                root = src_dg.nearest_pandevice()
                shared_member = (
                    (root and root.find(member_name, ServiceObject))
                    or (root and root.find(member_name, ServiceGroup))
                )
                if shared_member is not None:
                    if config.verbose:
                        print(f"    ↳ using Shared service object '{member_name}' (no copy needed)")
                    continue
                print(f"    ⚠ Warning: Service member '{member_name}' not found")
                continue

            if isinstance(member, ServiceGroup):
                if not copy_service_dependencies(member, src_dg, dest_dg, config):
                    success = False

            if not ensure_object(dest_dg, member, config):
                success = False

        return success

    return True  # Non-group service objects have no dependencies


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _as_list(x) -> List[str]:
    """Normalize a possibly-None or scalar field to a list of strings.

    Args:
        x: Input value that can be None, a scalar, or an iterable.

    Returns:
        List[str]: A list of strings (empty list if input is None).
    """
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]


# -----------------------------------------------------------------------------
# Rule processing
# -----------------------------------------------------------------------------

def copy_referenced_objects(
    rule: SecurityRule, *, src_dg: DeviceGroup, dest_dg: DeviceGroup, config: Config
) -> bool:
    """Copy all objects referenced by a security rule with dependency resolution.

    This function implements the core object copying workflow by analyzing a security
    rule and copying all referenced objects to the destination device group. It handles
    complex dependency chains and ensures proper creation order.

    The function processes these object types:
      - Address objects (source/destination fields): AddressObject, AddressGroup, EDL
      - Service objects (service field): ServiceObject, ServiceGroup
      - URL categories (category field): CustomUrlCategory
      - Application objects (application field): ApplicationObject, ApplicationGroup, ApplicationFilter

    Args:
        rule (SecurityRule): The security rule whose referenced objects should be copied.
        src_dg (DeviceGroup): Source device group containing the objects to copy.
        dest_dg (DeviceGroup): Destination device group where objects should be created.
        config (Config): Runtime configuration controlling conflict resolution and dry-run mode.

    Returns:
        bool: True if all objects were copied successfully; False otherwise.

    Note:
        The function uses a bottom-up approach, resolving dependencies before creating
        parent objects. Built-in objects like "any" and "application-default" are skipped.
    """
    success = True
    root = src_dg.nearest_pandevice()  # Panorama root (Shared scope)

    # Addresses: source + destination. Normalize to lists to avoid None issues.
    for name in (_as_list(rule.source) + _as_list(rule.destination)):
        if isinstance(name, str) and name.lower() == "any":
            continue

        obj = (
            src_dg.find(name, AddressObject)
            or src_dg.find(name, AddressGroup)
            or src_dg.find(name, Edl)
        )
        if obj is None:
            # Also check Shared to avoid false warnings.
            shared_obj = (
                (root and root.find(name, AddressObject))
                or (root and root.find(name, AddressGroup))
                or (root and root.find(name, Edl))
            )
            if shared_obj is not None:
                if config.verbose:
                    print(f"    ↳ using Shared address object '{name}' (no copy needed)")
                continue
            print(f"    ⚠ Warning: Address object '{name}' not found")
            continue

        if isinstance(obj, AddressGroup):
            if not copy_address_dependencies(obj, src_dg, dest_dg, config):
                success = False

        if not ensure_object(dest_dg, obj, config):
            success = False

    # Services (strings or list). Skip built-ins.
    for name in _as_list(rule.service):
        if isinstance(name, str) and name.lower() in {"any", "application-default"}:
            continue

        obj = src_dg.find(name, ServiceObject) or src_dg.find(name, ServiceGroup)
        if obj is None:
            shared_obj = (
                (root and root.find(name, ServiceObject))
                or (root and root.find(name, ServiceGroup))
            )
            if shared_obj is not None:
                if config.verbose:
                    print(f"    ↳ using Shared service object '{name}' (no copy needed)")
                continue
            print(f"    ⚠ Warning: Service object '{name}' not found")
            continue

        if isinstance(obj, ServiceGroup):
            if not copy_service_dependencies(obj, src_dg, dest_dg, config):
                success = False

        if not ensure_object(dest_dg, obj, config):
            success = False

    # URL categories (if present). Skip "any".
    categories = getattr(rule, "category", []) or []
    for name in categories:
        if isinstance(name, str) and name.lower() == "any":
            continue

        obj = src_dg.find(name, CustomUrlCategory)
        if obj is None:
            shared_obj = root and root.find(name, CustomUrlCategory)
            if shared_obj is not None:
                if config.verbose:
                    print(f"    ↳ using Shared URL category '{name}' (no copy needed)")
                continue
            print(f"    ⚠ Warning: URL category '{name}' not found")
            continue

        if not ensure_object(dest_dg, obj, config):
            success = False

    # Applications (strings or list). Skip "any".
    for name in _as_list(rule.application):
        if isinstance(name, str) and name.lower() == "any":
            continue

        app_obj = (
            src_dg.find(name, ApplicationObject)
            or src_dg.find(name, ApplicationGroup)
            or src_dg.find(name, ApplicationFilter)
        )
        if app_obj is None:
            shared_app = (
                (root and root.find(name, ApplicationObject))
                or (root and root.find(name, ApplicationGroup))
                or (root and root.find(name, ApplicationFilter))
            )
            if shared_app is not None:
                if config.verbose:
                    print(f"    ↳ using Shared application '{name}' (no copy needed)")
                continue
            print(f"    ⚠ Warning: Application '{name}' not found")
            continue

        if isinstance(app_obj, ApplicationGroup):
            if not copy_app_dependencies(app_obj, src_dg, dest_dg, config):
                success = False

        if not ensure_object(dest_dg, app_obj, config):
            success = False

    return success


def copy_rule(rule: SecurityRule, dest_dg: DeviceGroup, config: Config, position: Optional[str] = None) -> bool:
    """Copy a security rule to the destination device group with position control.

    This function creates a complete copy of a security rule in the destination device
    group. It preserves all rule attributes and allows control over rule positioning
    within the security policy. Positioning is performed in two steps for resiliency:
    first `create()`, then `move()` to 'top', 'bottom', or 'before/after:<name>'.

    Args:
        rule (SecurityRule): The source security rule to copy.
        dest_dg (DeviceGroup): Destination device group where the rule should be created.
        config (Config): Runtime configuration controlling dry-run mode and other behaviors.
        position (Optional[str]): 'top' | 'bottom' | 'before:<rule_name>' | 'after:<rule_name>'.

    Returns:
        bool: True if the rule was created successfully; False otherwise.

    Note:
        In dry-run mode, this function only reports what would happen without
        making actual changes. Rule positioning defaults to 'bottom' if not specified.
    """
    if config.dry_run:
        print(f"✔ would copy rule '{rule.name}' to position '{position or 'bottom'}'")
        if config.verbose:
            try:
                print(rule.element_str().strip())
            except Exception:
                pass
        return True

    # Ensure rule tags exist prior to creation to avoid reference errors.
    _ensure_tags_exist(dest_dg, rule, config)

    clone = SecurityRule(**rule.about())  # Copy all rule configuration
    dest_dg.add(clone)

    try:
        clone.create()
        # Normalize and apply movement
        pos_cmd, ref = _normalize_position(position or "bottom")
        if pos_cmd in ("top", "bottom"):
            clone.move(pos_cmd)
        elif pos_cmd in ("before", "after") and ref:
            clone.move(pos_cmd, ref=ref)
        else:
            clone.move("bottom")
        print(f"✔ copied rule '{rule.name}'")
        return True
    except PanDeviceError as e:
        print(f"❌ Error creating/moving rule '{rule.name}': {e}")
        return False


def _normalize_position(position: str) -> Tuple[str, Optional[str]]:
    """Parse a position string into (command, reference).

    Accepts:
        'top' | 'bottom' | 'before:<name>' | 'after:<name>'.

    Args:
        position (str): Position specifier.

    Returns:
        Tuple[str, Optional[str]]: Move command and optional reference name.
    """
    pos = (position or "").strip()
    if pos in ("top", "bottom"):
        return pos, None
    if pos.startswith("before:"):
        return "before", pos.split(":", 1)[1]
    if pos.startswith("after:"):
        return "after", pos.split(":", 1)[1]
    return "bottom", None


# -----------------------------------------------------------------------------
# CLI driver
# -----------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """Build and configure the command-line argument parser.

    This function creates a comprehensive argument parser that defines all command-line
    options for the rule copying script. It includes connection parameters, source/destination
    configuration, rule selection criteria, conflict resolution, and execution options.

    Returns:
        argparse.ArgumentParser: Parser with all required and optional arguments.

    Note:
        The parser uses ArgumentDefaultsHelpFormatter to show default values in help text.
        Required arguments are marked appropriately and validated by argparse.
    """
    parser = argparse.ArgumentParser(
        description="Copy tagged security rules (and their objects) between Panorama device groups",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,  # Show defaults in help
    )

    # Connection and authentication parameters
    parser.add_argument("--panorama", required=True, help="Panorama hostname or IP")
    parser.add_argument("--username", required=True, help="Panorama admin username")
    parser.add_argument("--password", help="Panorama password (omit to prompt)")

    # Source and destination configuration
    parser.add_argument("--src-dg", required=True, help="Source device group name")
    parser.add_argument("--dst-dg", required=True, help="Destination device group name")

    # Rule selection criteria
    parser.add_argument("--tag", required=True, help="Tag used to select rules")

    # Conflict resolution strategy
    parser.add_argument(
        "--on-conflict",
        choices=["skip", "overwrite"],
        default="skip",
        help="What to do if an object with the same name already exists at destination",
    )

    # Rule positioning options
    parser.add_argument(
        "--position",
        choices=["top", "bottom", "before", "after"],
        default="bottom",
        help="Position where rules should be placed in the destination policy",
    )
    parser.add_argument(
        "--relative-to",
        help="Name of the rule to position relative to (required when using 'before' or 'after')",
    )

    # Execution mode options
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be copied without making actual changes",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional details, including XML previews where available",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Commit to Panorama after copying (otherwise leave in candidate config)",
    )

    return parser


def main() -> None:
    """Main entry point for the CLI application.

    This function orchestrates the complete rule copying workflow including:
      - Command-line argument parsing and validation
      - Panorama connection establishment
      - Panorama version check (warn if below 10.1)
      - Device group validation and setup
      - Rule discovery and filtering by tag
      - Dependency resolution and object copying
      - Rule creation with positioning
      - Optional commit to Panorama

    The function handles all error cases gracefully and provides comprehensive
    status reporting throughout the process.

    Raises:
        SystemExit: If critical errors occur (invalid arguments, connection failures,
            no matching rules found, or commit failures).
    """
    # Parse and validate command-line arguments
    parser = build_arg_parser()
    args = parser.parse_args()

    # Initialize configuration object with parsed arguments
    config = Config()
    config.on_conflict = args.on_conflict  # Set conflict resolution strategy
    config.dry_run = args.dry_run          # Set execution mode
    config.verbose = args.verbose

    # Validate argument dependencies
    if args.position in ("before", "after") and not args.relative_to:
        sys.exit(f"❌ Error: --relative-to is required when using --position={args.position}")

    # Handle password input (prompt if not provided via command line)
    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.panorama}: ")

    # Establish connection to Panorama and warn if version < 10.1
    pano = connect(args.panorama, args.username, args.password)
    warn_if_panorama_too_old(pano, minimum="10.1")

    # Get and validate source and destination device groups
    src_dg = get_device_group(pano, args.src_dg)
    dst_dg = get_device_group(pano, args.dst_dg)

    # Discover rules matching the specified tag
    rules = rules_with_tag(src_dg, args.tag)
    if not rules:
        sys.exit(f"No rules with tag '{args.tag}' found in '{args.src_dg}'")

    print(f"Found {len(rules)} rule(s) to copy…")

    # Prepare rule positioning parameter
    position = args.position
    if position in ("before", "after"):
        # Combine position type with reference rule name
        position = f"{position}:{args.relative_to}"

    # Main processing loop: copy rules and their dependencies
    success_count = 0
    for rule in rules:
        # Phase 1: Copy all referenced objects with dependency resolution
        objects_success = copy_referenced_objects(rule, src_dg=src_dg, dest_dg=dst_dg, config=config)
        if not objects_success:
            print(f"⚠ Warning: Some objects for rule '{rule.name}' could not be copied")

        # Phase 2: Copy the rule itself after dependencies are resolved
        if copy_rule(rule, dst_dg, config, position):
            success_count += 1

    # Report final results
    print(f"Successfully copied {success_count} of {len(rules)} rules")

    # Handle commit operation if requested
    if args.commit and not config.dry_run:
        print("Committing – this may take a while…")
        try:
            # Commit with descriptive comment including operation details
            pano.commit_all(description=(
                f"Copied rules tagged '{args.tag}' from {args.src_dg} to {args.dst_dg} "
                f"(on-conflict: {config.on_conflict})"
            ))
            print("✅ commit complete!")
        except PanDeviceError as e:
            sys.exit(f"❌ Commit failed: {e}")
    elif not config.dry_run:
        # Changes made but not committed - inform user
        print("Changes are in the candidate config; review & commit when ready.")
    else:
        # Dry run mode - no changes made
        print("Dry run completed. No changes were made to the configuration.")


if __name__ == "__main__":  # pragma: no cover
    main()
