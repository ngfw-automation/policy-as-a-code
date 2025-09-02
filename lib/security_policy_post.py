"""
Functions for creating and managing post-rulebase security policies in PAN-OS.

This module provides functionality to:

- Create security rules for the post-rulebase section of the policy
- Handle managed and non-managed application categories
- Handle managed and non-managed URL categories
- Create rules for different risk levels (very high, high, medium, low, very low)
- Configure rules for authenticated and non-authenticated users
- Apply appropriate security profiles to each rule
- Support domain prefixing for user identities
- Implement intelligent default deny rules for non-sanctioned applications
"""

from panos.policies import SecurityRule as R
from ngfw.objects.tags.group_tags import group_tags
from panos.panorama import Panorama
from panos.firewall import Firewall
from rich import print
from rich.console import Console
from rich.table import Table
import settings


def security_policy_post(app_categories, url_categories, security_rules_uuids, panos_device, target_environment):
    """
    Creates firewall rules based on application and URL categories provided as input.
    For each category, multiple rules are generated to handle various scenarios of
    traffic, such as managed or unmanaged application categories, and traffic to URLs
    of different risk levels. The function supports customization of source user domains
    and actions depending on the configuration settings and calling function context.

    Args:
        app_categories: List[Dict[str, str]]. A list of dictionaries representing
            application categories. Each dictionary contains keys such as 'UserID',
            'Action', 'SubCategory', and 'Description' to define the application
            traffic rule specifics.

        url_categories: List[Dict[str, str]]. A list of dictionaries representing URL
            categories. Each dictionary includes keys like 'UserID', 'Action', 'Category',
            'Abbreviation', and 'Description' to specify URL traffic rule details.

        security_rules_uuids: A dictionary mapping rule names to their UUIDs.

        panos_device: The PAN-OS device object (Firewall or Panorama).

        target_environment: The target environment for the policy (e.g., "lab" or "prod").

    Returns:
        tuple: A tuple containing two elements:
            - A list of security rule objects for the POST section.
            - A set of deduplicated group tags used in the POST section of the policy.
    """
    rules = []

    # Determine domain prefix based on target environment
    if target_environment.lower() == "lab" and settings.ADD_DOMAIN_PREFIX_FOR_LAB:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    elif target_environment.lower() == "prod" and settings.ADD_DOMAIN_PREFIX_FOR_PROD:
        domain_prefix = settings.AD_DOMAIN_NAME + '\\'
    else:
        domain_prefix = ''

    # Managed APP categories (the loop creates two rules per managed App category - regular traffic, and http(s)-based traffic to Medium/High-risk URLs)
    # The risk-based differentiation would only apply to HTTP-based applications
    for category in app_categories:

        # add domain prefix to the username if required (unless it's one of the predefined PAN-OS values)
        if category["UserID"].lower() not in ['any', 'known-user', 'unknown', 'pre-logon', None] and domain_prefix:
            source_user = domain_prefix + category["UserID"].lower()
        else:
            source_user = category["UserID"].lower()

        if category["Action"].lower() == settings.APP_ACTION_MANAGE:
            # This rule covers Medium and High risk URLs for a managed app category
            name = 'managed-apps-' + category["SubCategory"].lower() + '-risky'
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                           group='PG-apps-risky', fromzone=settings.ZONE_INSIDE,
                           category=['high-risk', 'medium-risk'],
                           tozone=settings.ZONE_OUTSIDE, application='APG-' + category["SubCategory"].lower(),
                           service=['service-http', 'service-https'], action='allow',
                           tag=group_tags["managed-app-categories"]["name"],
                           group_tag=group_tags["managed-app-categories"]["name"],
                           description=category["Description"]+' This rule covers only connections to URLs classified as Medium or High risk for HTTP-based applications in this category',
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))
            # This rule covers all other URLs and non-http traffic for a managed app category
            name = 'managed-apps-' + category["SubCategory"].lower() + '-regular'
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                           group='PG-apps-regular', fromzone=settings.ZONE_INSIDE,
                           tozone=settings.ZONE_OUTSIDE, application='APG-' + category["SubCategory"].lower(),
                           service='application-default', action='allow',
                           tag=group_tags["managed-app-categories"]["name"],
                           group_tag=group_tags["managed-app-categories"]["name"],
                           description=category["Description"],
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))

    # Managed URL categories (the loop creates two rules per managed URL category - regular traffic, and traffic to Medium/High-risk URLs)
    # ==================================================================================================================
    for category in url_categories:

        # add domain prefix to the username if required (unless it's one of the predefined PAN-OS values)
        if category["UserID"].lower() not in ['any', 'known-user', 'unknown', 'pre-logon', None] and domain_prefix:
            source_user = domain_prefix + category["UserID"].lower()
        else:
            source_user = category["UserID"].lower()

        # We have a special treatment for the Unknown category to apply a custom Vulnerability profile 
        if (category["Category"].lower() == 'unknown') and (category["Action"].lower() == settings.URL_ACTION_MANAGE):
            if category["UserID"].lower() != 'known-user':
                name = 'managed-urls-'+category["Category"].lower()+'-very-risky'
                uuid = security_rules_uuids.get(name, None)
                rules.append(R(name=name, uuid=uuid,
                               source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                               category=['unknown'],
                               group='PG-managed-urls-very-risky', fromzone=settings.ZONE_INSIDE,
                               tozone=settings.ZONE_OUTSIDE, application='APG-web-browsing-risky',
                               service='application-default', action='allow',
                               tag=group_tags["managed-url-categories"]["name"],
                               group_tag=group_tags["managed-url-categories"]["name"],
                               description=category["Description"]+' This is a purpose-built rule specifically for Unknown category',
                               log_setting=settings.LFP_DEFAULT,
                               log_start=False, log_end=True))
            else:
                name = 'managed-urls-'+category["Category"].lower()+'-very-risky'
                uuid = security_rules_uuids.get(name, None)
                rules.append(R(name=name, uuid=uuid,
                               source=settings.DEFAULT_INSIDE_ADDRESS, source_user='known-user',
                               category=['unknown'],
                               group='PG-managed-urls-very-risky', fromzone=settings.ZONE_INSIDE,
                               tozone=settings.ZONE_OUTSIDE, application='APG-web-browsing-risky',
                               service='application-default', action='allow',
                               tag=group_tags["managed-url-categories"]["name"],
                               group_tag=group_tags["managed-url-categories"]["name"],
                               description=category["Description"]+' This is a purpose-built rule specifically for Unknown category',
                               log_setting=settings.LFP_DEFAULT,
                               log_start=False, log_end=True))

        # Now we create rules for all other managed categories as required
        elif (category["Action"].lower() == settings.URL_ACTION_MANAGE) and ('UCL-' not in category["Category"]) and ('UCM-' not in category["Category"]):
            # This rule is for the managed URL category that is High or Medium risk
            name = 'managed-urls-'+category["Category"].lower()+'-risky'
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                           category=['UCM-'+category["Abbreviation"].lower()+'_high-risk', 'UCM-'+category["Abbreviation"].lower()+'_med-risk'],
                           group='PG-managed-urls-risky', fromzone=settings.ZONE_INSIDE,
                           tozone=settings.ZONE_OUTSIDE, application='APG-web-browsing-risky',
                           service='application-default', action='allow',
                           tag=group_tags["managed-url-categories"]["name"],
                           group_tag=group_tags["managed-url-categories"]["name"],
                           description=category["Description"]+' This rule covers only connections to URLs classified as Medium or High risk in this category',
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))
            name = 'managed-urls-'+category["Category"].lower()+'-regular'
            uuid = security_rules_uuids.get(name, None)
            # This rule is for the managed URL category that is of any risk level (effectively it's going to be matched for Low risk only)
            rules.append(R(name=name, uuid=uuid,
                           source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                           category=category["Category"].lower(),
                           group='PG-managed-urls', fromzone=settings.ZONE_INSIDE,
                           tozone=settings.ZONE_OUTSIDE, application='APG-web-browsing',
                           service='application-default', action='allow',
                           tag=group_tags["managed-url-categories"]["name"],
                           group_tag=group_tags["managed-url-categories"]["name"],
                           description=category["Description"],
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))
        elif (category["Action"].lower() == settings.URL_ACTION_MANAGE) and (('UCL-' in category["Category"]) or ('UCM-' in category["Category"])):

            name = 'managed-urls-'+category["Category"].lower()+'-regular'
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source=settings.DEFAULT_INSIDE_ADDRESS, source_user=source_user,
                           category=category["Category"],
                           group='PG-managed-urls', fromzone=settings.ZONE_INSIDE,
                           tozone=settings.ZONE_OUTSIDE, application='APG-web-browsing',
                           service='application-default', action='allow',
                           tag=group_tags["managed-url-categories"]["name"],
                           group_tag=group_tags["managed-url-categories"]["name"],
                           description=category["Description"],
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))

    # ==================================================================================================================
    # Non-managed apps - these rules cover Application categories marked in the CSV template as "do not manage" (meaning they would be allowed for all authenticated users)
    # This is achieved by aggregating all non-managed categories under a single Application Group - "APG-non-managed-apps"

    uuid = security_rules_uuids.get('non-managed-apps-risky', None)
    rules.append(R(name='non-managed-apps-risky', uuid=uuid, source_user='known-user', group='PG-apps-risky',
                   fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS,
                   application='APG-non-managed-apps', category=['high-risk', 'medium-risk'],
                   service=['service-http', 'service-https'], action='allow',
                   tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='Applications from all categories marked as "non-managed" that are based on HTTP(S) with '
                               'URLs that are classified as Medium or High risk'))

    uuid = security_rules_uuids.get('non-managed-apps-regular', None)
    rules.append(R(name='non-managed-apps-regular', uuid=uuid, source_user='known-user', group='PG-apps-regular',
                   fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS,
                   application='APG-non-managed-apps', service='application-default', action='allow',
                   tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='Applications from all categories marked as "non-managed" (both HTTP(S) and non-HTTP(S)).'
                               ' If an application falls under a non-managed category but does not fully match '
                               'respective application filter and application group, it will be classified as '
                               'non-sanctioned and blocked. MOST of our egress web traffic is expected to hit either '
                               'this rule or the "non-managed-url-categories" rule below'))

    # ==================================================================================================================
    # Non-managed URL categories - these rules cover URL-categories marked in the CSV template as "do not manage"
    # (meaning they would be allowed for all authenticated users)
    # URL profiles in the profile groups assigned to these rules are dynamically generated based on what categories
    # need to be managed

    uuid = security_rules_uuids.get('non-managed-url-categories-risky', None)
    rules.append(R(name='non-managed-url-categories-risky', uuid=uuid, source_user='known-user',
                   category=['high-risk', 'medium-risk'], group='PG-non-managed-urls-risky',
                   fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS,
                   application='APG-web-browsing-risky', service='application-default', action='allow',
                   tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='HTTP(S) traffic for non-managed URL-categories with URLs that are classified as Medium or High risk'))

    uuid = security_rules_uuids.get('non-managed-url-categories-regular', None)
    rules.append(R(name='non-managed-url-categories-regular', uuid=uuid, source_user='known-user', category='any',
                   group='PG-non-managed-urls', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE,
                   source=settings.DEFAULT_INSIDE_ADDRESS, application='APG-web-browsing', service='application-default',
                   action='allow', tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='HTTP(S) traffic for non-managed URL-categories. MOST of egress web traffic is '
                               'expected to hit either this rule or the "non-managed-apps" rule above'))

    uuid = security_rules_uuids.get('non-managed-url-categories-non-standard-port-risky', None)
    rules.append(R(name='non-managed-url-categories-non-standard-port-risky', uuid=uuid, source_user='known-user',
                   category=['high-risk', 'medium-risk'], group='PG-non-managed-urls-risky',
                   fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS,
                   application='APG-web-browsing-risky', service='any', action='allow',
                   tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='HTTP(S) traffic for non-managed URL-categories with URLs that are classified as Medium '
                               'or High risk AND port number is NOT 80 or 443'))

    uuid = security_rules_uuids.get('non-managed-url-categories-non-standard-port-regular', None)
    rules.append(R(name='non-managed-url-categories-non-standard-port-regular', uuid=uuid, source_user='known-user',
                   category='any', group='PG-non-managed-urls', fromzone=settings.ZONE_INSIDE,
                   tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application='APG-web-browsing',
                   service='any', action='allow',
                   tag=group_tags["default-web-browsing"]["name"], group_tag=group_tags["default-web-browsing"]["name"],
                   log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True,
                   description='HTTP(S) traffic for non-managed URL-categories where the port number is NOT 80 or 443'))

    # Rules for denying access to managed APP categories
    #
    # These Deny rules based on Application groups and filters are required to distinguish blocking actions
    # on a per-category basis so that contextualised custom response pages can be produced
    for category in app_categories:
        if category["Action"].lower() == settings.APP_ACTION_MANAGE:
            name = 'not-authorized-for-'+category["SubCategory"].lower()
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source_user='known-user', source=settings.DEFAULT_INSIDE_ADDRESS,
                           fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE,
                           application='APG-'+category["SubCategory"].lower(),
                           service='any', action='deny',
                           tag=group_tags["block-non-authorized"]["name"],
                           group_tag=group_tags["block-non-authorized"]["name"],
                           description='This rule is to catch and block non-authorised '
                                       'access to the managed application category '+category["SubCategory"].upper()+', and to produce '
                                       'a contextualized firewall response page. The rule name is '
                                       'referenced in the JavaScript code of the Application Block response page.',
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))

    # Intelligent default deny rules - catch for apps unaccounted for in the policy (aka "non-sanctioned").

    # All applications originating from authenticated users that did not match
    # any of the application filters defined for managed and non-managed categories would hit one of the rules below.

    for category in app_categories:
        if category["Action"].lower() == settings.APP_ACTION_MANAGE or category["Action"].lower() == settings.APP_ACTION_ALERT:
            name = 'non-sanctioned-'+category["SubCategory"].lower()
            uuid = security_rules_uuids.get(name, None)
            rules.append(R(name=name, uuid=uuid,
                           source_user='known-user', source=settings.DEFAULT_INSIDE_ADDRESS,
                           fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE,
                           application='APF-'+category["SubCategory"].lower()+'-all',
                           service='any', action='deny',
                           tag=group_tags["block-non-sanctioned-apps"]["name"],
                           group_tag=group_tags["block-non-sanctioned-apps"]["name"],
                           description='This rule is to catch and block non-sanctioned applications from the managed '
                                       'application category '+category["SubCategory"].upper()+', and to produce '
                                       'a contextualized firewall response page. The rule name is '
                                       'referenced in the JavaScript code of the Application Block response page.',
                           log_setting=settings.LFP_DEFAULT,
                           log_start=False, log_end=True))

    # All applications from denied categories will hit one of the five rules below

    uuid = security_rules_uuids.get('blocked-category--very-high-risk-apps', None)
    rules.append(R(name='blocked-category-very-high-risk-apps', uuid=uuid, source_user='known-user', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-high-risk', service='any', action='deny', tag=group_tags["block-non-sanctioned-apps"]["name"], group_tag=group_tags["block-non-sanctioned-apps"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block non-sanctioned apps classified as Very High risk'))

    uuid = security_rules_uuids.get('blocked-category-high-risk-apps', None)
    rules.append(R(name='blocked-category-high-risk-apps', uuid=uuid, source_user='known-user', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}high-risk', service='any', action='deny', tag=group_tags["block-non-sanctioned-apps"]["name"], group_tag=group_tags["block-non-sanctioned-apps"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block non-sanctioned apps classified as High risk'))

    uuid = security_rules_uuids.get('blocked-category-medium-risk-apps', None)
    rules.append(R(name='blocked-category-medium-risk-apps', uuid=uuid, source_user='known-user', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}medium-risk', service='any', action='deny', tag=group_tags["block-non-sanctioned-apps"]["name"], group_tag=group_tags["block-non-sanctioned-apps"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block non-sanctioned apps classified as Medium risk'))

    uuid = security_rules_uuids.get('blocked-category-low-risk-apps', None)
    rules.append(R(name='blocked-category-low-risk-apps', uuid=uuid, source_user='known-user', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}low-risk', service='any', action='deny', tag=group_tags["block-non-sanctioned-apps"]["name"], group_tag=group_tags["block-non-sanctioned-apps"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block non-sanctioned apps classified as Low risk'))

    uuid = security_rules_uuids.get('blocked-category-very-low-risk-apps', None)
    rules.append(R(name='blocked-category-very-low-risk-apps', uuid=uuid, source_user='known-user', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application=f'{settings.PREFIX_FOR_APPLICATION_FILTERS}very-low-risk', service='any', action='deny', tag=group_tags["block-non-sanctioned-apps"]["name"], group_tag=group_tags["block-non-sanctioned-apps"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block non-sanctioned apps classified as Very Low risk'))

    # The rule below will only trigger to block non-authenticated users which would then be handled accordingly by the application response page
    uuid = security_rules_uuids.get('non-authenticated-connections', None)
    rules.append(R(name='non-authenticated-connections', uuid=uuid, source_user='unknown', fromzone=settings.ZONE_INSIDE, tozone=settings.ZONE_OUTSIDE, source=settings.DEFAULT_INSIDE_ADDRESS, application='any', service='any', action='deny', tag=group_tags["block-non-compliant-and-anonymous"]["name"], group_tag=group_tags["block-non-compliant-and-anonymous"]["name"], log_setting=settings.LFP_DEFAULT, log_start=False, log_end=True, description='This rule is to catch and block all anonymous connections (without a valid ip-to-user mapping)'))
    # This is the end of the POST rulebase

    # Create a table for displaying rules
    console = Console()
    if settings.VERBOSE_OUTPUT:
        table = Table(title="Security Policy Post-Rules")
        table.add_column("Group Tag", style="cyan")
        table.add_column("Rule Name", style="green")

    # Now we create a deduplicated set of group tags used in the POST section of the policy
    # We also output names and group of all rules
    all_post_group_tags = []
    for rule in rules:
        if settings.VERBOSE_OUTPUT:
            table.add_row(
                rule.group_tag,
                rule.name
            )
        if rule.group_tag not in all_post_group_tags:
            all_post_group_tags.append(rule.group_tag)

    # Display the table if verbose output is enabled
    if settings.VERBOSE_OUTPUT:
        console.print(table)

    all_post_group_tags_deduped = set(all_post_group_tags)

    return rules, all_post_group_tags_deduped
