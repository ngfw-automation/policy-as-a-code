"""
Core module for building and deploying firewall policies to PAN-OS devices.

This module orchestrates the entire policy deployment process, including:

- Setting up connections to Panorama or Firewall devices
- Managing configuration and commit locks
- Deleting objects
- Creating and configuring all required objects (tags, filters, groups, profiles etc.)
- Building and deploying policy rules
- Handling address objects and groups
- Managing security profiles and profile groups

It serves as the main entry point for policy deployment operations and
coordinates the functionality provided by other modules.
"""

from panos.firewall import Firewall
from panos.policies                     import SecurityRule, DecryptionRule, NatRule, AuthenticationRule, PolicyBasedForwarding, ApplicationOverride
from tqdm                               import tqdm
from lib.rich_output                    import console
from rich.panel                         import Panel

from panos.panorama import DeviceGroup, Panorama, Template
from panos.device   import Vsys
from panos.policies import PreRulebase, PostRulebase, Rulebase

from panos.objects import (Tag, ApplicationFilter, ApplicationGroup, Edl, CustomUrlCategory, ServiceObject, ServiceGroup,
                           LogForwardingProfile)

from panos.errors import PanDeviceXapiError

import settings
import sys

from lib.security_policy_pre            import security_policy_pre
from lib.security_policy_post           import security_policy_post
from lib.decryption_policy              import decryption_policy
from lib.manage_tags                    import create_tags, tag_applications
from lib.application_filters            import create_application_filters
from lib.application_groups             import create_application_groups
from lib.security_profile_groups        import create_security_profile_groups
from lib.edls                           import create_edls
from lib.url_categories                 import create_custom_url_categories
from lib.address_objects_staging        import handle_address_objects_and_groups
from lib.service_objects                import create_service_objects
from lib.security_profile_url_filtering import create_url_filtering_static_profiles, create_url_filtering_auto_profiles
from lib.log_forwarding_profiles        import create_log_forwarding_profiles
from lib.service_now                    import generate_categories_for_servicenow
from lib.auxiliary_functions            import (delete_objects, delete_non_sdk_objects, create_non_sdk_objects,
                                                execute_multi_config_api_call)
from lib.custom_objects                 import import_custom_signatures, import_custom_response_pages


def discover_and_delete_policy_rules(panos_device, target, rule_type):
    """
    Fetches and deletes policy rules of a specific type on a Palo Alto Networks device.

    This function performs operations like fetching existing rules for a given
    target, displaying them, optionally deleting them, and returning the
    relevant rules and their UUIDs. The behavior varies depending on whether
    the device is a standalone device or Panorama, as well as on the configuration
    settings provided.

    Args:
        panos_device: The Palo Alto Networks device on which the rules are set.
            It can either be a Firewall or a Panorama instance.
        target: The target object for which the policy rules will be managed.
            This can be either a Vsys or a DeviceGroup object.
        rule_type: The type of policy rule to manage. Supported types include
            'security', 'decryption', 'nat', 'authentication', 'override', and 'pbf'.

    Returns:
        tuple: A tuple containing two elements:
            - A list of current rules gathered from the target and, optionally, deleted.
            - A dictionary mapping rule names to their UUIDs for rules
              that support UUIDs.

    Raises:
        ValueError: If an unsupported rule type is specified.
    """
    rule_classes = {
        'security': SecurityRule,
        'decryption': DecryptionRule,
        'nat': NatRule,
        'authentication': AuthenticationRule,
        'override': ApplicationOverride,
        'pbf': PolicyBasedForwarding
    }

    rule_class = rule_classes.get(rule_type)
    if not rule_class:
        raise ValueError(f"Unsupported rule type: {rule_type}")

    # Get friendly name for output
    friendly_name = rule_type.replace('_', ' ')

    # Get current rules
    print(f'Looking for existing {friendly_name} policy rules...', end='')

    current_rules = []
    current_rules_pre = []
    current_rules_post = []

    if isinstance(panos_device, Panorama):
        current_rules_pre  = rule_class.refreshall(target.get('pre'))
        current_rules_post = rule_class.refreshall(target.get('post'))
        current_rules      = current_rules_pre + current_rules_post
        print(f'found {len(current_rules)} rule(s)')
    else:
        current_rules = rule_class.refreshall(target)
        print(f'found {len(current_rules)} rule(s)')

    # Store UUIDs if the policy type supports that (ApplicationOverride class does not)
    rule_uuids = {}
    if rule_type in ['security', 'decryption', 'nat', 'pbf', 'authentication'] and settings.VERBOSE_OUTPUT:
        print(f"Existing {friendly_name} rules:")
        if isinstance(panos_device, Panorama):
            for prerule in current_rules_pre:
                if settings.VERBOSE_OUTPUT: console.print(f"\t{prerule.name}")
                rule_uuids[prerule.name] = prerule.uuid
            if len(current_rules_post) != 0:
                console.print("-" * 64)
            for postrule in current_rules_post:
                if settings.VERBOSE_OUTPUT: console.print(f"\t{postrule.name}")
                rule_uuids[postrule.name] = postrule.uuid
        else:
            for rule in current_rules:
                if settings.VERBOSE_OUTPUT: console.print(f"\t{rule.name}")
                rule_uuids[rule.name] = rule.uuid
    elif settings.VERBOSE_OUTPUT:
        if isinstance(panos_device, Panorama):
            if len(current_rules_pre) != 0:
                for prerule in current_rules_pre: console.print(f"\t{prerule.name}")
            if len(current_rules_post) != 0:
                console.print("-" * 64)
                for postrule in current_rules_post: console.print(f"\t{postrule.name}")
        else:
            if len(current_rules) != 0:
                for rule in current_rules: console.print(f"\t{rule.name}")

    # Delete rules if needed
    # (if there is no explicit flag DELETE_CURRENT_<rule type>_POLICY = True, the rules won't be deleted)
    delete_flag = getattr(settings, f"DELETE_CURRENT_{rule_type.upper()}_POLICY", False)

    if current_rules and delete_flag:
        if settings.BULK_RULE_DELETION:
            delete_objects(panos_device, current_rules)
            if isinstance(panos_device, Panorama):
                rule_class.refreshall(target.get('pre'))
                rule_class.refreshall(target.get('post'))
            else:
                rule_class.refreshall(target)
        else:
            console.print(f"Deleting existing {friendly_name} rules one by one (this may take a while)...")
            for rule in tqdm(current_rules, desc=f"Deleting {friendly_name} rules", ncols=100, colour='white'):
                rule.delete()

    return current_rules, rule_uuids


def create_security_rules(panos_device, app_categories_requirements, url_categories_requirements, rule_uuids, target_environment):
    """Create security policy rules"""
    policy_rules_pre,  security_pre_group_tags = security_policy_pre(app_categories_requirements, rule_uuids, panos_device, target_environment)
    policy_rules_post, security_post_group_tags = security_policy_post(app_categories_requirements, url_categories_requirements, rule_uuids, panos_device, target_environment)
    return policy_rules_pre, policy_rules_post


def create_decryption_rules(panos_device, target_environment):
    """Create decryption policy rules"""
    decryption_rules_pre, decryption_pre_group_tags = decryption_policy(panos_device, settings.DECRYPTION_RULES_PRE_FOLDER, target_environment)
    decryption_rules_post, decryption_post_group_tags = decryption_policy(panos_device, settings.DECRYPTION_RULES_POST_FOLDER, target_environment)
    return decryption_rules_pre, decryption_rules_post


def create_nat_rules(panos_device, target_environment):
    """Create NAT policy rules - placeholder for future implementation"""
    # TODO: Implement NAT rule creation logic
    # When implemented, it should call nat_policy with target_environment
    # Example: nat_rules_pre, nat_pre_group_tags = nat_policy(panos_device, "path/to/nat/rules/pre", target_environment)
    return [], []


def create_authentication_rules(panos_device, target_environment):
    """Create authentication policy rules - placeholder for future implementation"""
    # TODO: Implement authentication rule creation logic
    # When implemented, it should use target_environment to determine domain prefix
    return [], []


def create_override_rules(panos_device, target_environment):
    """Create application override policy rules - placeholder for future implementation"""
    # TODO: Implement application override rule creation logic
    # When implemented, it should use target_environment to determine domain prefix
    return [], []


def create_pbf_rules(panos_device, target_environment):
    """Create Policy-Based Forwarding policy rules - placeholder for future implementation"""
    # TODO: Implement Policy-Based Forwarding rule creation logic
    # When implemented, it should use target_environment to determine domain prefix
    return [], []


def build_policy(panos_device, policy_container, policy_template, app_categories_requirements, url_categories_requirements, current_url_categories, target_environment):
    """
    Constructs and manages security and decryption policies, address objects, and address groups on a PAN-OS device.
    (Panorama + Device Group or Firewall + VSYS)

    Args:
        panos_device:                   Firewall or Panorama device object.
        policy_container:               The name of the device group or VSYS where the policies will be applied.
        policy_template:                The name of Panorama template where custom objects will be imported into
        app_categories_requirements:    Requirements for each app subcategory.
        url_categories_requirements:    Requirements for each URL-category.
        current_url_categories:         The current list of URL categories retrieved from Panorama
        target_environment:             The target environment for applying the policies (prod|lab etc.)
    """

    # Get system info
    panos_device.refresh_system_info()

    if settings.PRIVACY_MODE:
        console.print(Panel.fit(f"Connected to {panos_device.platform} (PAN-OS {panos_device.version}, Content v{panos_device.content_version}, S/N {panos_device.serial})"))
    else:
        console.print(Panel.fit(f"Connected to {panos_device.platform} (PAN-OS {panos_device.version}, Content v{panos_device.content_version})"))
    console.print(Panel.fit(f"Target for the policy: {policy_container}"))


    # Create Device Group or VSYS object
    if isinstance(panos_device, Panorama):
        # for Panorama the target is a DeviceGroup, and the target_template is a Template
        target          = DeviceGroup(policy_container)
        target_template = Template(policy_template)
    else:
        # for a firewall both the target and the target_template must be the same object - a VSYS
        target          = Vsys(policy_container)
        target_template = target

    # Associate the DG/VSYS/Template with the Panorama/Firewall object
    panos_device.add(target)
    panos_device.add(target_template)

    # =================================================================================================================
    # =================================================================================================================
    # Set the target template for Panorama for commit and config locks to be taken
    console.print(f"Setting the target ", end="")
    if isinstance(panos_device, Panorama):
        console.print("template...", end="")
        try:
            tp_target_result    = panos_device.op(cmd=f"<set><system><setting><target><template><name>{policy_template}</name></template></target></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            console.print(f'Error while setting the policy target: {e}\n')
            sys.exit(1)
        else:
            console.print(f"{tp_target_result.attrib["status"]}")

    # Set the target VSYS for firewall for commit and config locks to be taken
    else:
        console.print("VSYS...", end="")
        try:
            vsys_target_result = panos_device.op(cmd=f"<set><system><setting><target-vsys>{policy_template}</target-vsys></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            console.print(f'Error while setting the policy target: {e}\n')
            sys.exit(1)
        else:
            console.print(f"{vsys_target_result.attrib["status"]}")

    # Take the config and commit lock for the set target (Template or VSYS))
    console.print(f'Taking CONFIG and COMMIT locks on the target...', end='')
    try:
        config_lock_result  = panos_device.op(cmd=f"<request><config-lock><add><comment>Policy revision {settings.POLICY_VERSION} ({settings.POLICY_DATE}) rollout</comment></add></config-lock></request>", cmd_xml=False)
        commit_lock_result  = panos_device.op(cmd=f"<request><commit-lock><add><comment>Policy revision {settings.POLICY_VERSION} ({settings.POLICY_DATE}) rollout</comment></add></commit-lock></request>", cmd_xml=False)
    except PanDeviceXapiError as e:
        if "You already own a config lock for scope" in str(e):
            console.print("Already have the lock, continuing...\n")
            # Maybe do something else or just carry on here
        else:
            console.print(f"Error while taking the lock: {e}\n")
            sys.exit(1)
    else:
        console.print(f"[{config_lock_result.attrib['status']}] for config lock and [{commit_lock_result.attrib['status']}] for commit lock.")


    # Now we set the target Device Group on Panorama for commit and config locks to be taken
    # we do not need to do this for the VSYS as all possible locks have already been taken
    console.print(f"Setting the target ", end="")
    if isinstance(panos_device, Panorama):
        console.print("device group...", end="")
        try:
            dg_target_result    = panos_device.op(cmd=f"<set><system><setting><target><device-group>{policy_container}</device-group></target></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            console.print(f'Error while setting the policy target: {e}\n')
            sys.exit(1)
        else:
            console.print(f"{dg_target_result.attrib["status"]}")

        # Take the config and commit lock for the specified target
        console.print(f'Taking CONFIG and COMMIT locks on the target...', end='')
        try:
            config_lock_result  = panos_device.op(cmd=f"<request><config-lock><add><comment>Policy revision {settings.POLICY_VERSION} ({settings.POLICY_DATE}) rollout</comment></add></config-lock></request>", cmd_xml=False)
            commit_lock_result  = panos_device.op(cmd=f"<request><commit-lock><add><comment>Policy revision {settings.POLICY_VERSION} ({settings.POLICY_DATE}) rollout</comment></add></commit-lock></request>", cmd_xml=False)
        except PanDeviceXapiError as e:
            if "You already own a config lock for scope" in str(e):
                console.print("Already have the lock, continuing...\n")
            else:
                console.print(f"Error while taking the lock: {e}\n")
                sys.exit(1)
        else:
            console.print(f"[{config_lock_result.attrib['status']}] for config lock and [{commit_lock_result.attrib['status']}] for commit lock.")

    # By this point we should have 4 locks on Panorama (commit and config on Template and Device Group)
    # and 2 locks on firewall (commit and config on VSYS)
    # =================================================================================================================
    # =================================================================================================================

    # Setup rulebases
    if isinstance(panos_device, Panorama):
        rulebase_pre = PreRulebase()
        rulebase_post = PostRulebase()
        target.add(rulebase_pre)
        target.add(rulebase_post)
        rulebases = {'pre': rulebase_pre, 'post': rulebase_post}
    else:
        rulebase = Rulebase()
        target.add(rulebase)
        rulebases = rulebase

    # Discover all policy types and delete them if required (controlled by DELETE_CURRENT_<type>_POLICY flags)
    _, security_rules_uuids     = discover_and_delete_policy_rules(panos_device, rulebases, 'security')
    _, decryption_rules_uuids   = discover_and_delete_policy_rules(panos_device, rulebases, 'decryption')
    _, nat_rules_uuids          = discover_and_delete_policy_rules(panos_device, rulebases, 'nat')
    _, auth_rules_uuids         = discover_and_delete_policy_rules(panos_device, rulebases, 'authentication')
    _, pbf_rules_uuids          = discover_and_delete_policy_rules(panos_device, rulebases, 'pbf')
    _, _                        = discover_and_delete_policy_rules(panos_device, rulebases, 'override')

    # =====================================================================================================
    print("Proceeding with the policy creation...")

    # The numbering below corresponds to the numbering in the section Firewall policy creation algorithm
    # in Chapter 8 of the project companion book

    # 1) Before we deal with any object types we need to ensure that all tags these objects may reference are created
    with console.status("Retrieving current tags...", spinner="dots") as status_spinner:
        current_tags = Tag.refreshall(target)
        status_spinner.update("Retrieving current tags...completed")
    if settings.BULK_TAG_DELETION:
        delete_objects(panos_device, current_tags, "soft")
        for tag in current_tags or []: target.remove(tag)
    else:
        for tag in tqdm(current_tags or [], desc="Deleting tags", ncols=100, colour='white'):
            try:
                tag.delete()
            except PanDeviceXapiError as e:
                tqdm.write(f"Failed to delete the tag [{tag.name}]")
                if settings.DEBUG_OUTPUT:
                    tqdm.write(str(e))
    # now, as all old tasgs are deleted, we proceed with (re)creating tags from code
    create_tags(target, panos_device)

    # 2,3) Delete Application Groups and Filters
    #
    # Groups must be deleted first as they may contain filters
    # Some groups may contain nested application groups. If we attempt to delete
    # nested application group before we delete their parents (even within the same multi-config operation)
    # the whole operation will fail. The workaround is to identify these container groups and delete them first.
    #
    # There is no recursion beyond one nested level in the algorythm below.
    # For example, if you have a group within a group within another group, the deletion may fail on one of them.
    #
    # a) enumerate all container application groups
    with console.status("Retrieving current application groups...", spinner="dots") as status_spinner:
        current_application_groups = ApplicationGroup.refreshall(target)
        status_spinner.update("Retrieving application groups...completed")
    application_groups = {} # dictionary

    # b) store their names and values in a dictionary
    for application_group in current_application_groups:
        application_groups[application_group.name] = application_group.value

    # c) identify names of the application groups that contain other application groups
    container_application_group_names = set() # set
    for name in application_groups.keys():
        for value in application_groups[name]:
            if value in application_groups.keys():
                container_application_group_names.add(name)

    # d) find application group objects with these names
    container_application_groups = []
    for name in container_application_group_names:
        container_application_groups.append(target.find(name, ApplicationGroup))

    # e) delete them
    delete_objects(panos_device, container_application_groups)

    # f) delete the remaining (non-container) app groups and filters
    current_application_groups = ApplicationGroup.refreshall(target)
    current_application_filters = ApplicationFilter.refreshall(target)
    delete_objects(panos_device, current_application_groups)
    delete_objects(panos_device, current_application_filters)
    for application_group  in current_application_groups  or []: target.remove(application_group)
    for application_filter in current_application_filters or []: target.remove(application_filter)

    # 4,5,6) Now we need to delete security profiles (amongst other objects) because they may reference an address object
    # or EDL that we may need to delete at the next steps
    delete_non_sdk_objects(target, panos_device, objects_to_delete=("application-tag", "profile-group", "vulnerability",
                                                                    "virus", "spyware", "wildfire-analysis",
                                                                    "url-filtering", "file-blocking", "data-filtering",
                                                                    "data-objects", "decryption"))

    # 7) delete and (re)create Log Forwarding Profiles (LFP)
    current_log_forwarding_profiles = LogForwardingProfile.refreshall(target)
    if settings.BULK_LFP_DELETION:
        delete_objects(panos_device, current_log_forwarding_profiles, "soft")
        for log_forwarding_profile in current_log_forwarding_profiles or []: target.remove(log_forwarding_profile)
    else:
        for log_forwarding_profile in tqdm(current_log_forwarding_profiles or [], desc="Deleting log forwarding profiles", ncols=100, colour='white'):
            try:
                log_forwarding_profile.delete()
            except PanDeviceXapiError as e:
                tqdm.write(f"Failed to delete the Log Forwarding Profile [{log_forwarding_profile.name}]")
                if settings.DEBUG_OUTPUT: tqdm.write(str(e))
    create_log_forwarding_profiles(target, panos_device)

    # 8-9) Then we "synchronize" objects in the code and on the device.
    # We do not simply delete and recreate address objects as there can be tens of thousands of them
    # we establish the delta and work with it: extra objects found on the device are deleted and
    # missing objects are created
    handle_address_objects_and_groups(target, panos_device)

    # We already ensured that required tags and address objects are in place
    # Now, it's time for more complex objects

    # 10) Delete and then (re)import custom application, vulnerability and spyware signatures
    if settings.IMPORT_APP_VULN_SPYWARE_SIGNATURES:
        delete_non_sdk_objects(target, panos_device, objects_to_delete=("application", "threat-vulnerability", "threat-spyware"))
        import_custom_signatures(target, panos_device)

    # 11) Tag the imported and standard application signatures
    tag_applications(target, panos_device)

    # 12-13) create app filters and groups
    # filters must be created before groups because they are referenced in the groups
    # groups may contain custom applications imported at the previous step
    create_application_filters(target, panos_device, app_categories_requirements)
    create_application_groups(target, panos_device, app_categories_requirements)

    # 14) Import custom response pages
    # (target_template here is either a Template or Vsys class instance)
    import_custom_response_pages(target_template, panos_device, target_environment)


    # 15) delete and (re)create all EDLs
    current_edls = Edl.refreshall(target)
    delete_objects(panos_device, current_edls)
    for edl in current_edls or []: target.remove(edl)
    create_edls(target, panos_device, target_environment)
    #                                 ^^^^^^^^^^^^^^^^^^
    # target_environment parameter is effectively a string that substitutes
    # the substring "<target_environment>" in the definitions of the EDLs
    # in the file [ngfw/objects/external dynamic lists/edls.csv]
    # This is used to host two (or more!) EDL sets with EDLs named identically but
    # with different URL specific to each environment. This allows you to have one
    # EDL hosting environment, one firewall policy, but several sets of EDLs (one per environment).
    # Thus, you can have a Lab firewall with a policy identical to your Prod and be able to test the policy
    # elements referencing the EDLs by changing the Lab instances of the EDLs instead of Prod.

    # 16) delete and (re)create all custom URL categories
    current_custom_url_categories = CustomUrlCategory.refreshall(target)
    delete_objects(panos_device, current_custom_url_categories)
    for custom_url_category in current_custom_url_categories or []: target.remove(custom_url_category)
    create_custom_url_categories(target, panos_device, url_categories_requirements)

    # 17) delete and (re)create all service objects and groups
    current_service_groups = ServiceGroup.refreshall(target)
    delete_objects(panos_device, current_service_groups)
    for service_group in current_service_groups or []: target.remove(service_group)

    # service groups must be deleted before the service object
    current_service_objects = ServiceObject.refreshall(target)
    delete_objects(panos_device, current_service_objects)
    for service_object in current_service_objects or []: target.remove(service_object)

    create_service_objects(target, panos_device)

    # 18,19) create all security profiles
    # we already deleted existing objects of these types earlier
    # create_data_objects(target, panos_device)
    # create_data_filtering_profiles(target, panos_device)

    create_non_sdk_objects(target, panos_device, objects_to_create=("data-patterns",
                                                                    "spyware-profiles",
                                                                    "av-profiles",
                                                                    "decryption-profiles",
                                                                    "vulnerability-profiles",
                                                                    "file-profiles",
                                                                    "wf-profiles",
                                                                    "data-profiles"))

    #  create URL filtering profiles based on static definitions in JSON files
    #
    #  As we proceed with creating them, we use the list of categories known to the PAN-OS device to perform
    #  some basic sanity checks of the files (ensure that actions are not defined twice for the same category,
    #  and ensure correct spelling of categories)
    #
    create_url_filtering_static_profiles(target, current_url_categories, panos_device)
    create_url_filtering_auto_profiles(target, url_categories_requirements, current_url_categories, panos_device)

    # 20) create security profile groups
    create_security_profile_groups(target, panos_device)  # creation of security profile groups

    # 21) create policy rules
    print("CREATING POLICY RULES...")

    # Initialize policy rule lists
    policy_rules_pre = []
    policy_rules_post = []

    # Stage security rules (always created in the original code)
    print("Staging security policy rules:")
    if settings.CREATE_SECURITY_POLICY:
        sec_pre, sec_post = create_security_rules(panos_device, app_categories_requirements, url_categories_requirements, security_rules_uuids, target_environment)
        policy_rules_pre.extend(sec_pre)
        policy_rules_post.extend(sec_post)

    # Stage decryption policy rules (if required)
    if ((isinstance(panos_device, Panorama) and settings.CREATE_DECRYPTION_POLICY_PANORAMA) or
            (isinstance(panos_device, Firewall) and settings.CREATE_DECRYPTION_POLICY_FIREWALL)):
        print("Staging decryption policy rules:")
        dec_pre, dec_post = create_decryption_rules(panos_device, target_environment)
        policy_rules_pre.extend(dec_pre)
        policy_rules_post.extend(dec_post)

    # Stage NAT rules if required
    if settings.CREATE_NAT_POLICY:
        print("Staging NAT policy rules:")
        nat_pre, nat_post = create_nat_rules(panos_device, target_environment)
        policy_rules_pre.extend(nat_pre)
        policy_rules_post.extend(nat_post)

    # Stage authentication rules if required
    if settings.CREATE_AUTHENTICATION_POLICY:
        print("Staging authentication policy rules:")
        auth_pre, auth_post = create_authentication_rules(panos_device, target_environment)
        policy_rules_pre.extend(auth_pre)
        policy_rules_post.extend(auth_post)

    # Stage application override rules if required
    if settings.CREATE_OVERRIDE_POLICY:
        print("Staging application override policy rules:")
        override_pre, override_post = create_override_rules(panos_device, target_environment)
        policy_rules_pre.extend(override_pre)
        policy_rules_post.extend(override_post)

    # Stage Policy-Based Forwarding rules if required
    if settings.CREATE_PBF_POLICY:
        print("Staging PBF policy rules:")
        bpf_pre, pbf_post = create_pbf_rules(panos_device, target_environment)
        policy_rules_pre.extend(bpf_pre)
        policy_rules_post.extend(pbf_post)

    # Attach policy rules to the rulebase
    print("Staging policy rules...", end='')

    if isinstance(panos_device, Panorama):
        for rule in policy_rules_pre:   rulebase_pre.add(rule)
        for rule in policy_rules_post:  rulebase_post.add(rule)
    else:
        for rule in policy_rules_pre:   rulebase.add(rule)
        for rule in policy_rules_post:  rulebase.add(rule)

    # Now we create Multi-Config Element XML for all staged rules
    # as we build the XML we also collect all source_user values
    action_id = 1
    source_users = list()
    multi_config_xml = '<multi-config>'
    for rule in policy_rules_pre + policy_rules_post:
        # First, we collect the User-ID value used in the rule.
        # This is required for future reference.
        # NOTE: Source User field is different in the rules of different types ("source_user" vs "source_users")
        # hence the need for the IF statement
        if isinstance(rule, SecurityRule):
            source_users.append(rule.source_user.lower())
        elif isinstance(rule, DecryptionRule) or isinstance(rule, PolicyBasedForwarding):
            source_users.append(rule.source_users.lower())  # Note: the attribute source_userS here is different
                                                            # from the equivalent attribute source_user in the Security rule
        # Second, we grab the Element definition of the rule
        element = rule.element_str().decode()
        #  Third, we construct XML for the whole sub-operation
        multi_config_xml += f'<edit id="{action_id}" xpath="{rule.xpath()}">{element}</edit>'
        action_id += 1
    multi_config_xml += '</multi-config>'
    print('done.')

    # creation of the policy rules
    execute_multi_config_api_call(panos_device, multi_config_xml, "Creating the staged rules...", 0)
    print("Building new policy: COMPLETED")

    # =================================================================================================================
    # =================================================================================================================
    # 22) Now, we remove all locks
    # First, we do this for templates and VSYSes
    print(f"Setting the target ", end="")
    if isinstance(panos_device, Panorama):
        print("template for lock removal...", end="")
        try:
            tp_target_result    = panos_device.op(cmd=f"<set><system><setting><target><template><name>{policy_template}</name></template></target></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            print(f'Error while setting the operation target: {e}\n')
            sys.exit(1)
        else:
            print(f"{tp_target_result.attrib["status"]}")
    # Set the target VSYS for firewall for commit and config locks to be taken
    else:
        print("VSYS for lock removal...", end="")
        try:
            vsys_target_result = panos_device.op(cmd=f"<set><system><setting><target-vsys>{policy_template}</target-vsys></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            print(f'Error while setting the operation target: {e}\n')
            sys.exit(1)
        else:
            print(f"{vsys_target_result.attrib["status"]}")

    # Remove the config and commit lock for the set target (Template or VSYS))
    print(f'Removing CONFIG and COMMIT locks from the target...', end='')
    try:
        config_lock_result  = panos_device.op(cmd=f"<request><config-lock><remove></remove></config-lock></request>", cmd_xml=False)
        commit_lock_result  = panos_device.op(cmd=f"<request><commit-lock><remove></remove></commit-lock></request>", cmd_xml=False)
    except PanDeviceXapiError as e:
        print(f'Error while removing the lock: {e}\n')
        sys.exit(1)
    else:
        print(f"[{config_lock_result.attrib['status']}] for config lock removal and [{commit_lock_result.attrib['status']}] for commit lock removal.")


    # Now we set the target Device Group on Panorama for commit and config locks to be removed
    # we do not need to do this for the VSYS as all possible locks have already been removed
    if isinstance(panos_device, Panorama):
        print("Setting the target device group for lock removal...", end="")
        try:
            dg_target_result    = panos_device.op(cmd=f"<set><system><setting><target><device-group>{policy_container}</device-group></target></setting></system></set>", cmd_xml=False)
        except PanDeviceXapiError as e:
            print(f'Error while setting the operation target: {e}\n')
            sys.exit(1)
        else:
            print(f"{dg_target_result.attrib["status"]}")

        # Take the config and commit lock for the specified target
        print(f'Removing CONFIG and COMMIT locks from the target...', end='')
        try:
            config_lock_result  = panos_device.op(cmd=f"<request><config-lock><remove></remove></config-lock></request>", cmd_xml=False)
            commit_lock_result  = panos_device.op(cmd=f"<request><commit-lock><remove></remove></commit-lock></request>", cmd_xml=False)
        except PanDeviceXapiError as e:
            print(f'Error while removing the lock: {e}\n')
            sys.exit(1)
        else:
            print(f"[{config_lock_result.attrib['status']}] for config lock removal and [{commit_lock_result.attrib['status']}] for commit lock removal.")
    #
    # Now all set locks should be removed
    # ================================================================================================================
    # ================================================================================================================
    # Deduplicate and sort source_users (also remove None entries if found before turning into set)
    source_users = sorted(set([x for x in source_users if x is not None]))

    # Remove specific entries: "any", "pre-logon", "known-user", "unknown" from the source_users list, if found
    source_users = [user for user in source_users if user not in {"any", "pre-logon", "known-user", "unknown"}]

    # Print deduplicated and sorted users
    print("=" * 64)
    print("Users and groups used in the policy (deduplicated and sorted):")
    for user in source_users:
        print(f"\t{user}")
    print("=" * 64)

    print("The users and/or user groups listed above have been referenced in the policy. "
          "\nThey must be provided by the User-ID subsystem (i.e. be provided via AD "
          "integration or created in the Local User Database).")

    generate_categories_for_servicenow(app_categories_requirements, url_categories_requirements)
