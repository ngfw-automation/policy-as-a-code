"""
Functions for integrating with ServiceNow for application and URL category management.

This module provides functionality to:
- Generate CSV files with managed application and URL categories for ServiceNow import
- Format category metadata for ServiceNow integration
- Handle approval workflows for different category types
- Process category descriptions and display settings
- Support different approver roles (HR, Compliance, InfoSec)
- Filter categories for service catalog display
"""

import settings
import csv
from rich import print


def generate_categories_for_servicenow1(app_categories, url_categories):
    """
    The function creates a CSV file with a list of managed application and URL categories that need to be managed
    :param app_categories:
    :param url_categories:
    :return:
    """

    print("\nList of groups that need to be managed in ServiceNow:\n\n")

    categories_for_servicenow = list()

    for category in app_categories:
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            categories_for_servicenow.append({
                "category":     category["Category"],
                "group":        category["UserID"],
                "approver":     category["Approver"],
                "description":  category["Description"]
            })

    for category in url_categories:
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            categories_for_servicenow.append({
                "category":     category["Category"],
                "group":        category["UserID"],
                "approver":     category["Approver"],
                "description":  category["Description"]
            })

    # Output all managed categories to the CSV file
    f_servicenow_categories = open(settings.SERVICE_NOW_CATEGORIES_FILENAME, 'w', newline='')
    writer_servicenow_categories = csv.writer(f_servicenow_categories)
    writer_servicenow_categories.writerow(["Category", "Group", "Approver", "Description"])
    # TODO: add a look up for a category description in statically defined dictionary of app categories
    # Write all categories to a file
    for entry in categories_for_servicenow:
        writer_servicenow_categories.writerow([entry["category"], entry["group"], entry["approver"], entry["description"]])
    f_servicenow_categories.flush()

    # Output all managed categories on the screen
    for entry in categories_for_servicenow:
        print(f'{entry["category"]:<39} {entry["group"]:<42}  {entry["approver"]:<22}')

    print('\n\nEnd of the list')
    print(f'This list has been saved in CSV format in "{settings.SERVICE_NOW_CATEGORIES_FILENAME}"')

    return categories_for_servicenow


def generate_categories_for_servicenow(app_categories, url_categories):
    """
    The function creates a CSV file with a list of managed application and URL categories that need to be managed
    :param app_categories:
    :param url_categories:
    :return:
    """

    # Certain categories need to be excluded from the dropdown list when SNow form for access approval
    # is selected from Service Catalog rather than invoked via a link from a firewall
    # We need to exclude categories that seemingly duplicate each other and have the same AD group
    # associated with them. For example "email" effectively duplicates "web based email".
    # We also exclude the restricted categories
    app_categories_to_be_excluded = ["email"]
    url_categories_to_be_excluded = ["games", "grayware", "hacking", "newly-registered-domain", "online-storage-and-backup", "parked"]

    print("\nGenerating categories' metadata for ServiceNow import...", end='')

    categories_for_servicenow = list()

    for category in app_categories:
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            # create base entry
            entry = {"Type": "app", "Name": category["Category"], "Display on form": "Yes", "Managed": "Yes",
                     "AD group": category["UserID"], "HRApproval": "No", "ComplianceApproval": "No",
                     "InfoSecApproval": "No", "Description": category["Description"]}
            # correct the approver field
            if category["Approver"].lower() == "compliance":
                entry.update({"ComplianceApproval": "Yes"})
            elif category["Approver"].lower() == "human capital":
                entry.update({"HRApproval": "Yes"})
            elif category["Approver"].lower() == "information security":
                entry.update({"InfoSecApproval": "Yes"})
            # see if it needs to be excluded from drop down list when accessed via service catalog
            if category["Category"] in app_categories_to_be_excluded:
                entry.update({"Display on form": "No"})
        else:
            entry = {"Type": "app", "Name": category["Category"], "Display on form": "No", "Managed": "No",
                     "AD group": "", "HRApproval": "No", "ComplianceApproval": "No",
                     "InfoSecApproval": "No", "Description": category["Description"]}
        entry.update({"Name": entry["Name"].replace("-", " ")})
        categories_for_servicenow.append(entry)

    for category in url_categories:
        if (category["Action"].lower() == settings.APP_ACTION_MANAGE) and (category["UserID"].lower() not in ["known-user", "pre-logon", "any", "unknown"]):
            # create base entry
            entry = {"Type": "url", "Name": category["Category"], "Display on form": "Yes", "Managed": "Yes",
                     "AD group": category["UserID"], "HRApproval": "No", "ComplianceApproval": "No",
                     "InfoSecApproval": "No", "Description": category["Description"]}
            # correct the approver field
            if category["Approver"].lower() == "compliance":
                entry.update({"ComplianceApproval": "Yes"})
            elif category["Approver"].lower() == "human capital":
                entry.update({"HRApproval": "Yes"})
            elif category["Approver"].lower() == "information security":
                entry.update({"InfoSecApproval": "Yes"})
            # see if needs to be excluded from drop down list when accessed via service catalog
            if category["Category"] in url_categories_to_be_excluded:
                entry.update({"Display on form": "No"})
        else:
            entry = {"Type": "url", "Name": category["Category"], "Display on form": "No", "Managed": "No",
                     "AD group": "", "HRApproval": "No", "ComplianceApproval": "No",
                     "InfoSecApproval": "No", "Description": category["Description"]}
        entry.update({"Name": entry["Name"].replace("-", " ")})
        categories_for_servicenow.append(entry)

    # Output all managed categories to the CSV file
    try:
        f_servicenow_categories = open(settings.SERVICE_NOW_CATEGORIES_FILENAME, 'w', newline='')
    except FileNotFoundError as e:
        print('File not found:',e)
        print('FAILED to export metadata')
    else:
        writer_servicenow_categories = csv.writer(f_servicenow_categories)
        writer_servicenow_categories.writerow(["Type", "Name", "Display on form", "Managed", "AD group", "HRApproval", "ComplianceApproval", "InfoSecApproval", "Description"])
        # Write all categories to a file
        for entry in categories_for_servicenow:
            writer_servicenow_categories.writerow([entry["Type"], entry["Name"], entry["Display on form"], entry["Managed"], entry["AD group"], entry["HRApproval"], entry["ComplianceApproval"], entry["InfoSecApproval"], entry["Description"]])
        f_servicenow_categories.flush()
        print(f'COMPLETED and saved metadata in "{settings.SERVICE_NOW_CATEGORIES_FILENAME}"')

    return categories_for_servicenow
