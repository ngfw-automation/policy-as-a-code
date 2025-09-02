try:
    from .. import settings
except ImportError:
    # Fallback for direct execution - add parent directory to path
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import settings
import csv
from getpass import getpass
from panos.firewall import Firewall
try:
    from ..lib.category_parser import parse_app_categories, parse_url_categories
    from ..lib.rich_output import console
except ImportError:
    # Fallback for direct execution
    from lib.category_parser import parse_app_categories, parse_url_categories
    from lib.rich_output import console
from rich.status import Status
from rich.table import Table
from rich.text import Text
from rich.box import HEAVY_EDGE
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

# For HTML export
import html
import datetime
import json


if settings.RICH_TRACEBACKS:
    from rich.traceback import install
    install(show_locals=settings.RICH_TRACEBACKS_SHOW_VARS)

firewall = input(f'Firewall address  [default: {settings.DEFAULT_FIREWALL}]:') or settings.DEFAULT_FIREWALL
api_user = input(f'Username          [default: {settings.DEFAULT_ADMIN_USERNAME}]:') or settings.DEFAULT_ADMIN_USERNAME
api_pass = getpass('Password:')

# We retrieve APP & URL metadata from the files with requirements
app_categories = parse_app_categories('../' + settings.APP_CATEGORIES_REQUIREMENTS_FILENAME)
url_categories = parse_url_categories('../' + settings.URL_CATEGORIES_REQUIREMENTS_FILENAME)

# Initial connection to the firewall
console.print(f'Connecting to {firewall}...', end='')
fw = Firewall(hostname=firewall, api_username=api_user, api_password=api_pass)
fw.refresh_system_info()
console.print(f'connected (PLATFORM: {fw.platform}, PAN-OS: {fw.version}, CONTENT VERSION: {fw.content_version})')

# Function to convert ElementTree objects to dictionaries
def et_to_dict(element):
    """
    Convert an ElementTree element to a dictionary.

    Args:
        element: ElementTree element

    Returns:
        dict: Dictionary representation of the ElementTree element
    """
    result = {}

    # Add element attributes to the dictionary
    if element.attrib:
        result.update(element.attrib)

    # Process child elements
    for child in element:
        child_dict = et_to_dict(child)

        # If the child has no children and only text, use the text as the value
        if not child_dict and child.text and child.text.strip():
            child_dict = child.text.strip()

        # Special handling for 'member' tags which should always be in a list
        if child.tag == 'member':
            if 'member' not in result:
                result['member'] = []
            result['member'].append(child_dict)
        # Handle multiple children with the same tag
        elif child.tag in result:
            # If this is the first duplicate, convert to a list
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_dict)
        else:
            result[child.tag] = child_dict

    # Add text content if it exists and there are no children
    if element.text and element.text.strip():
        if not result:
            # If there are no attributes or children, use the text as the value
            result = element.text.strip()
        else:
            # If there are attributes or children, add the text under a special key
            result['_text'] = element.text.strip()

    return result

# Custom code to get application list and metadata
# show predefined xpath /predefined/application
with Status(f"Retrieving all applications known to the firewall (this may take a minute)...", console=console) as status:
    built_in_apps_full = fw.op('<show><predefined><xpath>/predefined/application</xpath></predefined></show>', cmd_xml=False, xml=False)
    status.update(f"Retrieving all applications known to the firewall using a custom method (this may take a minute)...[green]COMPLETED[/green]")
    if built_in_apps_full.attrib['status'] == 'success':
        apps_full = built_in_apps_full.findall(".//application/entry")
        # Convert all ElementTree objects to dictionaries
        apps_dict = [et_to_dict(app) for app in apps_full]

        # # Print the first dictionary as an example
        if apps_dict[0] and apps_dict[0].get("name")=="1und1-mail":
            console.print("Example of converted dictionary:")
            # Pretty print the first dictionary with indentation for better readability
            console.print(json.dumps(apps_dict[0], indent=2))

normalized_built_in_apps = dict()
for each_app in apps_dict:
    if each_app.get("subcategory") is not None:
        app_details = {
            "name":                     each_app.get("name"),
            "subcategory":              each_app.get("subcategory"),
            "category":                 each_app.get("category"),
            "risk":                     each_app.get("risk"),
            "tags":                     each_app.get("tags"),
            "description":              each_app.get("description"),
            "references":               each_app.get("references"),
            "icon":                     each_app.get("icon").get("_text") if isinstance(each_app.get("icon"), dict) and each_app.get("icon").get("_text") else each_app.get("icon"),
            "evasive-behavior":         each_app.get("evasive-behavior"),
            "consume-big-bandwidth":    each_app.get("consume-big-bandwidth"),
            "used-by-malware":          each_app.get("used-by-malware"),
            "able-to-transfer-file":    each_app.get("able-to-transfer-file"),
            "has-known-vulnerability":  each_app.get("has-known-vulnerability"),
            "tunnel-other-application": each_app.get("tunnel-other-application"),
            "prone-to-misuse":          each_app.get("prone-to-misuse"),
            "pervasive-use":            each_app.get("pervasive-use")
        }
        normalized_built_in_apps[each_app.get("name")] = app_details


# Now we go through all managed categories of Apps to populate a dictionary with all apps
# that respective application groups contain

app_group_dictionary = dict()

console.print('Generating app group dictionary:')

# We initialize lists for managed, non-managed, and blocked categories (for ease of look up later)
managed_app_categories     = list()
non_managed_app_categories = list()
blocked_app_categories     = list()

# First, categorize all app categories
relevant_categories = []
for category in app_categories:
    # If the category is managed, we add it to the list of managed categories
    if category['Action'] == settings.APP_ACTION_MANAGE:
        managed_app_categories.append(category['SubCategory'])
        relevant_categories.append(category)
    # If the category is not managed, we add it to the list of non-managed categories
    elif category['Action'] == settings.APP_ACTION_ALERT:
        non_managed_app_categories.append(category['SubCategory'])
        relevant_categories.append(category)
    # If the category is blocked, we add it to the list of blocked categories
    elif category['Action'] == settings.APP_ACTION_DENY:
        blocked_app_categories.append(category['SubCategory'])
        relevant_categories.append(category)

# Create a progress bar for application retrieval
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    console=console,
) as progress:
    # Create the main task
    main_task = progress.add_task(f"[cyan]Processing application categories...", total=len(relevant_categories))

    # Process each category
    for category in relevant_categories:
        # Determine the category type
        if category['Action'] == settings.APP_ACTION_MANAGE:
            category_type = "managed"
        elif category['Action'] == settings.APP_ACTION_DENY:
            category_type = "blocked"
        else:
            category_type = "non-managed"

        # we generate a standard application group name that we suppose the firewall already has
        application_group_name = settings.PREFIX_FOR_APPLICATION_GROUPS + category['SubCategory']

        # Update the progress description
        progress.update(main_task, description=f"[cyan]Processing {application_group_name}...")

        # Create selection criteria string
        selection_criteria = []
        if 'Risk' in category and category['Risk']:
            selection_criteria.append(f"RISK: {category['Risk']}")
        if 'Category' in category and category['Category']:
            selection_criteria.append(f"PARENT: {category['Category']}")
        if 'Tags' in category and category['Tags']:
            selection_criteria.append(f"TAG: {category['Tags']}")

        # For blocked categories, get apps by cross-referencing subcategory with blocked category names
        if category_type == "blocked":
            # Find all applications that belong to this subcategory
            member_list = []
            for app_name, app_details in normalized_built_in_apps.items():
                if app_details['subcategory'] == category['SubCategory']:
                    member_list.append(app_name)

            # No non-sanctioned apps for blocked categories since we're getting all apps directly
            non_sanctioned_apps = []

            # Store detailed information in the dictionary
            app_group_dictionary[category['SubCategory']] = {
                'subcategory_name': category['SubCategory'],
                'category': category['Category'],
                'type': category_type,
                'apps': member_list,
                'non_sanctioned_apps': non_sanctioned_apps,
                'selection_criteria': "\n".join(selection_criteria) if selection_criteria else "None"
            }

            # Print a success message with green tick
            console.print(f"[green]✓[/green] Found {len(member_list)} applications for blocked category {category['SubCategory']} by cross-referencing subcategories")
        else:
            # For managed and non-managed categories, use the original approach with application groups
            # Retrieve applications for this group
            applications_in_the_group = fw.op(f'<show><applications><vsys>vsys1</vsys><list><member>{application_group_name}</member></list></applications></show>', cmd_xml=False, xml=False)

            if applications_in_the_group.attrib['status'] == 'success':
                members = applications_in_the_group.findall(".//applications/member")
                member_list = [member.text for member in members]

                # Find non-sanctioned applications for this subcategory
                non_sanctioned_apps = []
                for app_name, app_details in normalized_built_in_apps.items():
                    if app_details['subcategory'] == category['SubCategory'] and app_name not in member_list:
                        non_sanctioned_apps.append(app_name)

                # Store detailed information in the dictionary
                app_group_dictionary[category['SubCategory']] = {
                    'subcategory_name': category['SubCategory'],
                    'category': category['Category'],
                    'type': category_type,
                    'apps': member_list,
                    'non_sanctioned_apps': non_sanctioned_apps,
                    'selection_criteria': "\n".join(selection_criteria) if selection_criteria else "None"
                }

                if len(member_list) != 0:
                    # Print a success message with green tick
                    console.print(f"[green]✓[/green] Retrieved {len(member_list)} applications for {application_group_name}, found {len(non_sanctioned_apps)} non-sanctioned applications")
                else:
                    console.print(f"[yellow]⚠[/yellow] The application group [{application_group_name}] is empty or its name is incorrect, but it will still be displayed in the table.")
            else:
                console.print(f"[red]✗[/red] Request failed for {application_group_name}")

        # Advance the progress
        progress.advance(main_task)

# Create a Rich table to display the information
table = Table(show_header=True, title="Application Categories", header_style="bold magenta", box=HEAVY_EDGE)
table.add_column("Subcategory Name", style="cyan")
table.add_column("Type", style="green")
table.add_column("Selection Criteria", style="yellow")
table.add_column("AD Group", style="magenta")
table.add_column("Sanctioned applications (matching the selection criteria)", style="blue")
table.add_column("Non-sanctioned applications", style="red")

# Add rows to the table
for subcategory, data in app_group_dictionary.items():
    # Format the applications list for display - no truncation
    apps_display = ", ".join(data['apps'])

    # Format the non-sanctioned applications list
    non_sanctioned_apps_display = ", ".join(data['non_sanctioned_apps'])

    # Determine AD group value based on category type
    if data['type'] == "managed":
        ad_group = f"UG-{data['subcategory_name']}"
    elif data['type'] == "blocked":
        ad_group = "N/A"
    else:
        ad_group = "N/A (known-user)"

    # Apply styling based on category type
    if data['type'] == "managed":
        table.add_row(
            Text(data['subcategory_name'], style="bold"),
            Text(data['type'], style="bold green"),
            Text(data['selection_criteria'], style="bold"),
            Text(ad_group, style="bold"),
            Text(apps_display, style="bold"),
            Text(non_sanctioned_apps_display, style="bold")  # Non-sanctioned applications
        )
    elif data['type'] == "blocked":
        table.add_row(
            Text(data['subcategory_name'], style="bold"),
            Text(data['type'], style="bold red"),
            Text(data['selection_criteria'], style="bold"),
            Text(ad_group, style="bold"),
            Text(apps_display, style="bold"),
            Text(non_sanctioned_apps_display, style="bold")  # Non-sanctioned applications
        )
    else:
        table.add_row(
            data['subcategory_name'],
            data['type'],
            data['selection_criteria'],
            ad_group,
            apps_display,
            non_sanctioned_apps_display  # Non-sanctioned applications
        )

# Display the table
console.print(table)

# Export to HTML
console.print("Exporting to HTML...", style="bold green")

# Build HTML content
# Build HTML content with proper variable interpolation
current_date = datetime.datetime.now().strftime('%Y-%m-%d')
html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        @page {{ size: letter landscape; margin: 1cm; }}
        body {{ font-family: Arial, sans-serif; font-size: 11px; }}
        h1 {{ text-align: center; font-size: 18px; margin-bottom: 20px; }}
        p.note {{ text-align: center; font-size: 12px; margin-bottom: 20px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            page-break-inside: avoid;
        }}
        th, td {{
            border: 1px solid #999;
            padding: 6px;
            vertical-align: top;
            word-wrap: break-word;
            word-break: break-word;
        }}
        .nowrap {{
            white-space: nowrap;
        }}
        .managed {{
            background-color: #e6f7ff; /* Light blue background for managed */
        }}
        .non-managed {{
            background-color: #f2f2f2; /* Light gray background for non-managed */
        }}
        .blocked {{
            background-color: #ffe6e6; /* Light red background for blocked */
        }}
        .sanctioned {{
            background-color: #e6ffe6; /* Light green background for sanctioned apps */
        }}
        .non-sanctioned {{
            background-color: #ffe6e6; /* Light red background for non-sanctioned apps */
        }}
        /* Tooltip styling */
        [data-tooltip] {{
            position: relative;
            cursor: help;
        }}
        [data-tooltip] .tooltip-content {{
            display: none;
            position: absolute;
            left: 0;
            bottom: 100%;
            z-index: 100;
            background-color: #fffbe6; /* Light yellowish background */
            color: #333;
            padding: 10px;
            border-radius: 5px;
            font-size: 11px; /* Same size as the table text */
            width: 400px;
            word-wrap: break-word;
            box-shadow: 0 0 5px rgba(0,0,0,0.3);
        }}
        /* Style for flipped tooltip (when displayed below instead of above) */
        [data-tooltip] .tooltip-content.flipped {{
            bottom: auto;
            top: 100%;
        }}
        [data-tooltip]:hover .tooltip-content {{
            display: block;
        }}
        /* Style for tooltip icon */
        .tooltip-icon {{
            vertical-align: middle;
            height: 32px; /* Larger size for tooltip */
            margin-right: 5px;
            margin-bottom: 10px;
        }}
        /* Style for lists in tooltips */
        [data-tooltip] .tooltip-content ul {{
            margin: 0;
            padding-left: 20px;
        }}
        [data-tooltip] .tooltip-content li {{
            margin-bottom: 5px;
        }}
        /* Style for links in tooltips */
        [data-tooltip] .tooltip-content a {{
            color: #0066cc;
            text-decoration: underline;
        }}
        [data-tooltip] .tooltip-content a:hover {{
            text-decoration: none;
        }}
        /* Style for app icons */
        .app-icon {{
            vertical-align: middle;
            height: 11px; /* Same size as the text */
            margin-right: 3px;
        }}
    </style>
    <script>
        // Function to ensure tooltips stay within page boundaries
        document.addEventListener('DOMContentLoaded', function() {{
            // Add mouseover event listener to all tooltip elements
            const tooltipElements = document.querySelectorAll('[data-tooltip]');
            tooltipElements.forEach(function(element) {{
                element.addEventListener('mouseenter', function() {{
                    const tooltip = this.querySelector('.tooltip-content');
                    if (!tooltip) return;

                    // Reset position to default first
                    tooltip.style.left = '0';
                    // Remove the flipped class by default
                    tooltip.classList.remove('flipped');

                    // Get tooltip dimensions and position
                    const tooltipRect = tooltip.getBoundingClientRect();
                    const viewportWidth = window.innerWidth;
                    const viewportHeight = window.innerHeight;

                    // Check if tooltip goes beyond right edge of viewport
                    if (tooltipRect.right > viewportWidth) {{
                        // Adjust position to keep it within viewport
                        tooltip.style.left = (viewportWidth - tooltipRect.right) + 'px';
                    }}

                    // Check if tooltip goes beyond top of viewport
                    if (tooltipRect.top < 0) {{
                        // Display below instead of above by adding the flipped class
                        tooltip.classList.add('flipped');
                    }} else {{
                        // Make sure the flipped class is removed if not needed
                        tooltip.classList.remove('flipped');
                    }}
                }});
            }});
        }});
    </script>
</head>
<body>
    <h1>Application Categories</h1>
    <p class="note">This report is generated on {current_date} for the global web filtering policy. The application list is retrieved from {firewall} running PAN-OS v{fw.version} with content v.{fw.content_version}.</p>
    <table>
        <thead>
            <tr>
                <th style="width:15%;">Subcategory Name</th>
                <th style="width:10%;">Type</th>
                <th style="width:15%;">Selection Criteria</th>
                <th style="width:10%;">AD Group</th>
                <th style="width:25%;">Sanctioned Applications</th>
                <th style="width:25%;">Non-sanctioned Applications</th>
            </tr>
        </thead>
        <tbody>
"""

# List of characteristics to check for
characteristics_to_check = [
    "evasive-behavior",
    "consume-big-bandwidth",
    "used-by-malware",
    "able-to-transfer-file",
    "has-known-vulnerability",
    "tunnel-other-application",
    "prone-to-misuse",
    "pervasive-use"
]

def create_app_html_with_tooltips(app_list):
    """Create HTML for application list with tooltips for each application."""
    app_html_parts = []

    for app in app_list:
        app_name = html.escape(app)
        tooltip_content = []

        # Check if app exists in normalized_built_in_apps
        if app in normalized_built_in_apps:
            app_info = normalized_built_in_apps[app]

            # Add description if available
            if app_info.get("description"):
                tooltip_content.append(f"<li><b>Description:</b> {html.escape(app_info['description'])}</li>")

            # Add parent category if available
            if app_info.get("category"):
                tooltip_content.append(f"<li><b>Parent Category:</b> {html.escape(app_info['category'])}</li>")

            # Add risk information if available
            if app_info.get("risk"):
                tooltip_content.append(f"<li><b>Risk:</b> {html.escape(app_info['risk'])}</li>")

            # Add tags if available
            if app_info.get("tags"):
                if isinstance(app_info["tags"], dict) and "member" in app_info["tags"]:
                    tags = app_info["tags"]["member"]
                    if isinstance(tags, list):
                        tooltip_content.append(f"<li><b>Tags:</b> {html.escape(', '.join(tags))}</li>")
                    else:
                        tooltip_content.append(f"<li><b>Tags:</b> {html.escape(str(tags))}</li>")
                elif isinstance(app_info["tags"], str):
                    tooltip_content.append(f"<li><b>Tags:</b> {html.escape(app_info['tags'])}</li>")

            # Check for characteristics directly in app properties
            found_characteristics = []
            for characteristic in characteristics_to_check:
                if app_info.get(characteristic) == "yes":
                    found_characteristics.append(characteristic)

            # Add characteristics if any found
            if found_characteristics:
                tooltip_content.append("<li><b>Characteristics:</b>")
                tooltip_content.append("<ul>")
                for characteristic in found_characteristics:
                    tooltip_content.append(f"<li>{html.escape(characteristic)}</li>")
                tooltip_content.append("</ul></li>")

            # Add reference link from app dictionary if available
            if app_info.get("references") and isinstance(app_info["references"], dict) and "entry" in app_info["references"]:
                entry = app_info["references"]["entry"]
                if isinstance(entry, dict) and "link" in entry and "name" in entry:
                    link = entry["link"]
                    name = entry["name"]
                    tooltip_content.append(f'<li><b>Reference:</b> <a href="{html.escape(link)}" target="_blank">{html.escape(name)}</a></li>')
        else:
            tooltip_content.append("<li>No information available</li>")

        # Check if app has an icon
        icon_html = ""
        tooltip_icon_html = ""
        if app in normalized_built_in_apps and normalized_built_in_apps[app].get("icon"):
            # Add the icon as an img tag with base64 data
            icon_data = normalized_built_in_apps[app]["icon"]
            icon_html = f'<img src="{icon_data}" class="app-icon" alt="{app_name} icon" />'
            # Add larger icon for tooltip
            tooltip_icon_html = f'<img src="{icon_data}" class="tooltip-icon" alt="{app_name} icon" />'

        # Add the icon to the beginning of the tooltip content if available
        tooltip_header = f"<div style='text-align:center; margin-bottom:10px;'>{tooltip_icon_html}<b>{app_name}</b></div>" if tooltip_icon_html else ""

        # Join all tooltip content with HTML list tags
        tooltip_html = tooltip_header + "<ul>" + "".join(tooltip_content) + "</ul>"

        # Create span with data-tooltip attribute and a child div for the tooltip content
        app_html = f'<span data-tooltip style="cursor:help;">{icon_html}{app_name}<div class="tooltip-content">{tooltip_html}</div></span>'
        app_html_parts.append(app_html)

    # Join with comma and word break opportunity
    return ", <wbr>".join(app_html_parts)

for subcategory, data in app_group_dictionary.items():
    sanctioned = create_app_html_with_tooltips(data['apps'])
    non_sanctioned = create_app_html_with_tooltips(data['non_sanctioned_apps'])
    if data['type'] == "managed":
        ad_group = f"UG-{data['subcategory_name']}"
    elif data['type'] == "blocked":
        ad_group = "N/A"
    else:
        ad_group = "N/A (known-user)"
    if data['type'] == "managed":
        row_class = ' class="managed"'
    elif data['type'] == "blocked":
        row_class = ' class="blocked"'
    else:
        row_class = ' class="non-managed"'

    # Determine cell classes based on content and category type
    # Only apply sanctioned class for managed and non-managed categories, not for blocked
    if data['type'] != "blocked":
        sanctioned_class = ' class="sanctioned"' if sanctioned.strip() else ''
    else:
        sanctioned_class = ''  # For blocked categories, use the row's blocked class
    non_sanctioned_class = ' class="non-sanctioned"' if non_sanctioned.strip() else ''

    html_content += f"""
        <tr{row_class}>
            <td>{html.escape(data['subcategory_name'])}</td>
            <td>{html.escape(data['type'])}</td>
            <td>{html.escape(data['selection_criteria']).replace('\n', '<br>')}</td>
            <td>{html.escape(ad_group)}</td>
            <td{sanctioned_class}>{sanctioned}</td>
            <td{non_sanctioned_class}>{non_sanctioned}</td>
        </tr>
    """

html_content += """
        </tbody>
    </table>
</body>
</html>
"""

# Save HTML to disk for troubleshooting
with open("application_categories.html", "w", encoding="utf-8") as f:
    f.write(html_content)
print("HTML saved to application_categories.html")


# Export to CSV
console.print("Exporting to CSV...", style="bold green")
csv_filename = "application_categories.csv"

with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
    csv_writer = csv.writer(csvfile)

    # Create header with characteristics columns
    characteristics_columns = []
    for characteristic in characteristics_to_check:
        characteristics_columns.append(characteristic)

    # Write header
    csv_writer.writerow([
        'Subcategory', 
        'Managed/Non-managed', 
        'User-ID', 
        'Application', 
        'Status', 
        'Description', 
        'Risk Level', 
        'Tags', 
        'Parent Category'
    ] + characteristics_columns)

    # Write one row per application (both sanctioned and non-sanctioned)
    for subcategory, data in app_group_dictionary.items():
        category_type = data['type']
        if category_type == "managed":
            ad_group = f"UG-{data['subcategory_name']}"
        elif category_type == "blocked":
            ad_group = "N/A"
        else:
            ad_group = "N/A (known-user)"

        # Function to process and write an application row
        def write_app_row(app, status):
            # Initialize basic row data
            row_data = [subcategory, category_type, ad_group, app, status]

            # Add additional columns
            description = ""
            risk_level = ""
            tags = ""
            parent_category = ""
            characteristics_values = ["No"] * len(characteristics_to_check)

            # If app exists in normalized_built_in_apps, get its details
            if app in normalized_built_in_apps:
                app_info = normalized_built_in_apps[app]

                # Get description
                description = app_info.get("description", "")

                # Get risk level
                risk_level = app_info.get("risk", "")

                # Get parent category
                parent_category = app_info.get("category", "")

                # Get tags
                if app_info.get("tags"):
                    if isinstance(app_info["tags"], dict) and "member" in app_info["tags"]:
                        tags_data = app_info["tags"]["member"]
                        if isinstance(tags_data, list):
                            tags = ", ".join(tags_data)
                        else:
                            tags = str(tags_data)
                    elif isinstance(app_info["tags"], str):
                        tags = app_info["tags"]

                # Get characteristics
                for i, characteristic in enumerate(characteristics_to_check):
                    if app_info.get(characteristic) == "yes":
                        characteristics_values[i] = "Yes"

            # Add all data to row
            row_data.extend([description, risk_level, tags, parent_category])
            row_data.extend(characteristics_values)

            # Write the row
            csv_writer.writerow(row_data)

        # Write sanctioned applications
        for app in data['apps']:
            write_app_row(app, "Sanctioned")

        # Write non-sanctioned applications
        for app in data['non_sanctioned_apps']:
            write_app_row(app, "Non-sanctioned")

console.print(f"CSV exported to {csv_filename}", style="bold green")
