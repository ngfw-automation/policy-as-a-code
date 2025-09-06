.. _defaults:

Defaults
========

This document provides an overview of the default policy supplied with the project, including 
URL categories and App-ID subcategories and their associated actions in the firewall policy.

.. warning::

   You **must** review all these defaults and modify them to meet your specific requirements.

Security Policy Sections
------------------------

PRE
~~~

The top part of the firewall security policy (that corresponds to the PRE section of the target Panorama device group)
is generated based on the static rules defined in the subfolders of the ``ngfw/policies/security/PRE`` folder.

Each subfolder represents a logical section of the policy. Each section is characterized by the following
distinctive attributes:

- Purpose (indicated by the Group Tag assigned to all rules in the section)
- Rule defaults

The policy rules in each section are defined in the corresponding rules.py file. It starts with defining default values
for all rule attributes. These defaults are followed by the actual rules that effectively describe the deviation from
the section defaults.

There are 7 sections in the default policy:

- **DNS Security** - Rules that secure DNS name resolution traffic by enforcing the use of approved DNS servers, blocking DNS over HTTPS (DoH) and DNS over TLS (DoT) to prevent DNS tunneling, and ensuring proper DNS security controls are in place.

- **Infrastructure essentials** - Rules that secure the minimal traffic required for proper functioning of firewalls and network infrastructure. This includes time synchronization services, certificate revocation checks (OCSP), endpoint detection and response (EDR) software, operating system connectivity checks, firewall helper applications, network troubleshooting tools, and communication between Palo Alto firewalls and cloud services.

- **Break-glass** - Emergency bypass rules designed to temporarily circumvent security controls during critical situations. These rules use External Dynamic Lists (EDL) to provide source IP-based, destination IP-based, and URL-based bypasses that can be activated only in exceptional circumstances when immediate access is required.

- **Incident response** - Rules designed for security operations teams to respond to active threats and security incidents. This section includes blocking rules for known malicious source and destination IPs, URL-based blocking for malicious websites, and automatic isolation of compromised hosts based on command and control (C&C) traffic detection using Dynamic Address Groups (DAG).

- **Block lists** - Baseline security blocking rules that use threat intelligence feeds to deny connections to and from known malicious entities. This includes blocking traffic to/from Palo Alto Networks threat feeds (bulletproof hosting, high-risk IPs, known malicious IPs, and Tor exit nodes) as well as geo-location based blocking for sanctioned countries and regions.

- **Infrastructure applications** - Rules that allow access to core organizational infrastructure applications necessary for basic business operations. This includes IT service desk systems (ServiceNow), controlled download of restricted file types from approved websites, endpoint software updates, and endpoint management platforms for Windows (Microsoft Intune) and macOS (Jamf).

- **Business applications** - Rules that govern access to business-specific applications and services used by authenticated users. This includes organization-specific trusted web applications, legacy custom applications, pre-approved business tools, comprehensive GitHub access (including AI features and Git operations), Microsoft 365 suite access with various security categories, and content delivery network services.

POST
~~~~

The bottom part of the firewall security policy (that corresponds to the POST section of the target Panorama device group)
is dynamically generated based on the business requirements specified in the following two files:

- ``requirements/categories_app.csv``
- ``requirements/categories_url.csv``

The following two diagrams visualize the relationship between App-ID or URL categories,
their associated User-IDs, approvers, and assigned actions in the firewall policy:


.. raw:: html

   <a href="javascript:void(0);" onclick="window.open('_static/url_categories_sankey.html', '_blank', 'width=1200,height=800');" style="float: right; margin-bottom: 10px;">Open in new window</a>

.. plotly::

   import plotly.graph_objects as go
   import csv
   import os
   from collections import defaultdict

   # Define colors for different actions and entities
   action_colors = {
       "manage": "rgba(31, 119, 180, 0.8)",  # Blue
       "deny": "rgba(214, 39, 40, 0.8)",     # Red
       "do not manage": "rgba(44, 160, 44, 0.8)",  # Green
       "continue": "rgba(255, 127, 14, 0.8)", # Orange
       "approver": "rgba(148, 103, 189, 0.8)",  # Purple for approvers
       "userid": "rgba(23, 190, 207, 0.8)"   # Cyan for UserIDs
   }

   # Path to the CSV file
   # Try different relative paths to find the CSV file
   possible_paths = [
       os.path.join(os.path.abspath('../..'), 'requirements', 'categories_url.csv'),
       os.path.join(os.path.abspath('.'), 'requirements', 'categories_url.csv'),
       os.path.join(os.path.abspath('..'), 'requirements', 'categories_url.csv'),
       'requirements/categories_url.csv',  # Direct relative path
   ]

   csv_file = None
   for path in possible_paths:
       if os.path.exists(path):
           csv_file = path
           break

   if csv_file is None:
       # If file not found, use a hardcoded sample for demonstration
       print("Warning: categories_url.csv file not found. Using sample data.")
       # Sample data structure for demonstration
       sample_data = [
           {"Category": "adult", "Action": "manage", "Approver": "human capital", "UserID": "UG-adult"},
           {"Category": "malware", "Action": "deny", "Approver": "", "UserID": ""},
           {"Category": "news", "Action": "do not manage", "Approver": "", "UserID": ""},
           {"Category": "questionable", "Action": "continue", "Approver": "", "UserID": ""}
       ]

   # Read the data
   categories = []
   unique_categories = set()
   actions = []
   unique_actions = set()
   approvers = []
   unique_approvers = set()
   userids = []
   unique_userids = set()
   action_counts = defaultdict(int)
   approver_counts = defaultdict(int)
   userid_counts = defaultdict(int)
   category_action_pairs = []
   action_approver_pairs = []
   category_userid_pairs = []
   userid_approver_pairs = []

   # For action-specific nodes
   action_specific_userids = []
   unique_action_specific_userids = set()
   action_specific_approvers = []
   unique_action_specific_approvers = set()

   if csv_file is not None:
       # Read from CSV file
       with open(csv_file, 'r') as f:
           reader = csv.DictReader(f)
           for row in reader:
               category = row['Category']
               action = row['Action']
               approver = row.get('Approver', '')  # Get approver if available
               userid = row.get('UserID', '')  # Get UserID if available

               # For non-managed categories (with "do not manage" action), set UserID to "known-user"
               if action == "do not manage" and not userid:
                   userid = "known-user"

               if category not in unique_categories:
                   categories.append(category)
                   unique_categories.add(category)

               if action not in unique_actions:
                   actions.append(action)
                   unique_actions.add(action)

               # Add approver if provided, or add "no approver" for non-deny actions if not already in the list
               if action != "deny":
                   if approver and approver not in unique_approvers:
                       approvers.append(approver)
                       unique_approvers.add(approver)
                   elif "no approver" not in unique_approvers:
                       approvers.append("no approver")
                       unique_approvers.add("no approver")

                   # Create action-specific approver nodes
                   action_specific_approver = f"{approver or 'no approver'}"
                   action_specific_approver_key = f"{approver or 'no approver'}_{action}"
                   if action_specific_approver_key not in unique_action_specific_approvers:
                       action_specific_approvers.append((action_specific_approver, action))
                       unique_action_specific_approvers.add(action_specific_approver_key)

               # Add UserID if not already in the list
               if userid and userid not in unique_userids:
                   userids.append(userid)
                   unique_userids.add(userid)

               # Create action-specific UserID nodes for non-deny actions
               if action != "deny" and userid:
                   action_specific_userid = f"{userid}"
                   action_specific_userid_key = f"{userid}_{action}"
                   if action_specific_userid_key not in unique_action_specific_userids:
                       action_specific_userids.append((action_specific_userid, action))
                       unique_action_specific_userids.add(action_specific_userid_key)

               action_counts[action] += 1
               category_action_pairs.append((category, action))

               # Create category-userid pairs
               if userid:
                   userid_counts[userid] += 1
                   category_userid_pairs.append((category, userid, action))  # Added action to the tuple

               # Create userid-approver pairs for "manage" actions
               if action == "manage" and approver and userid:
                   userid_approver_pairs.append((userid, approver, action))  # Added action to the tuple

               # Create action-approver pairs for "manage" actions
               if action == "manage" and approver:
                   approver_counts[approver] += 1
                   action_approver_pairs.append((action, approver))
   else:
       # Use sample data
       for row in sample_data:
           category = row['Category']
           action = row['Action']
           approver = row.get('Approver', '')  # Get approver if available
           userid = row.get('UserID', '')  # Get UserID if available

           # For non-managed categories (with "do not manage" action), set UserID to "known-user"
           if action == "do not manage" and not userid:
               userid = "known-user"

           if category not in unique_categories:
               categories.append(category)
               unique_categories.add(category)

           if action not in unique_actions:
               actions.append(action)
               unique_actions.add(action)

           # Only add approver if action is "manage" and approver is not empty
           if action == "manage" and approver and approver not in unique_approvers:
               approvers.append(approver)
               unique_approvers.add(approver)

               # Create action-specific approver nodes
               action_specific_approver = f"{approver}"
               action_specific_approver_key = f"{approver}_{action}"
               if action_specific_approver_key not in unique_action_specific_approvers:
                   action_specific_approvers.append((action_specific_approver, action))
                   unique_action_specific_approvers.add(action_specific_approver_key)
           elif action != "deny" and "no approver" not in unique_approvers:
               approvers.append("no approver")
               unique_approvers.add("no approver")

               # Create action-specific approver nodes
               action_specific_approver = f"no approver [{action}]"
               if action_specific_approver not in unique_action_specific_approvers:
                   action_specific_approvers.append(action_specific_approver)
                   unique_action_specific_approvers.add(action_specific_approver)

           # Add UserID if not already in the list
           if userid and userid not in unique_userids:
               userids.append(userid)
               unique_userids.add(userid)

           # Create action-specific UserID nodes for non-deny actions
           if action != "deny" and userid:
               action_specific_userid = f"{userid}"
               action_specific_userid_key = f"{userid}_{action}"
               if action_specific_userid_key not in unique_action_specific_userids:
                   action_specific_userids.append((action_specific_userid, action))
                   unique_action_specific_userids.add(action_specific_userid_key)

           action_counts[action] += 1
           category_action_pairs.append((category, action))

           # Create category-userid pairs
           if userid:
               userid_counts[userid] += 1
               category_userid_pairs.append((category, userid, action))  # Added action to the tuple

           # Create userid-approver pairs for "manage" actions
           if action == "manage" and approver and userid:
               userid_approver_pairs.append((userid, approver, action))  # Added action to the tuple

           # Create action-approver pairs for "manage" actions
           if action == "manage" and approver:
               approver_counts[approver] += 1
               action_approver_pairs.append((action, approver))

   # Create node labels and colors
   # Extract just the userid from the tuples in action_specific_userids
   userid_labels = [userid for userid, _ in action_specific_userids]
   # Extract just the approver from the tuples in action_specific_approvers
   # Handle both tuple and string formats in action_specific_approvers
   approver_labels = []
   for approver_item in action_specific_approvers:
       if isinstance(approver_item, tuple):
           approver, _ = approver_item
           approver_labels.append(approver)
       else:
           # For string format, extract approver without the action part
           if "[" in approver_item:
               approver, _ = approver_item.rsplit(" [", 1)
               approver_labels.append(approver)
           else:
               approver_labels.append(approver_item)
   node_labels = categories + userid_labels + actions + approver_labels
   node_colors = []

   # Assign colors to nodes (categories are gray, userids are cyan, actions have specific colors, approvers are purple)
   for i in range(len(node_labels)):
       if i < len(categories):
           node_colors.append("rgba(128, 128, 128, 0.8)")  # Gray for categories
       elif i < len(categories) + len(action_specific_userids):
           node_colors.append(action_colors.get("userid", "rgba(23, 190, 207, 0.8)"))  # Cyan for UserIDs
       elif i < len(categories) + len(action_specific_userids) + len(actions):
           action = node_labels[i]
           node_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.8)"))
       else:
           node_colors.append("rgba(148, 103, 189, 0.8)")  # Purple for approvers

   # Create source, target, and value arrays for links
   sources = []
   targets = []
   values = []
   link_colors = []

   # Create category-userid-approver-action mappings
   category_userid_map = {}
   userid_approver_map = {}
   category_action_map = {}

   # Map categories to userids and actions
   for category, userid, action in category_userid_pairs:
       category_userid_map[(category, action)] = userid
       category_action_map[category] = action

   # Map userids to approvers for "manage" actions
   for userid, approver, action in userid_approver_pairs:
       userid_approver_map[(userid, action)] = approver

   # Create links from categories to userids or directly to actions for "deny" categories
   for category in categories:
       category_idx = categories.index(category)

       # Find the action for this category
       action = None
       for cat, act in category_action_pairs:
           if cat == category:
               action = act
               break

       if action == "deny":
           # For blocked categories, link directly to action
           action_idx = actions.index(action) + len(categories) + len(action_specific_userids)
           sources.append(category_idx)
           targets.append(action_idx)
           values.append(1)  # Each link has a value of 1
           link_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.5)"))
       else:
           # For other categories, link to action-specific userid
           userid = category_userid_map.get((category, action), "known-user")  # Default to "known-user" if not found
           action_specific_userid_key = f"{userid}_{action}"
           # Find the index of the tuple with this userid and action
           userid_idx = -1
           for i, (uid, act) in enumerate(action_specific_userids):
               if uid == userid and act == action:
                   userid_idx = i
                   break
           if userid_idx == -1:
               print(f"Warning: Could not find action-specific userid for {userid} and {action}")
           userid_idx = userid_idx + len(categories)

           sources.append(category_idx)
           targets.append(userid_idx)
           values.append(1)  # Each link has a value of 1
           link_colors.append(action_colors.get("userid", "rgba(23, 190, 207, 0.5)"))  # Cyan for UserID links

   # Create links from action-specific userids to action-specific approvers
   for i, (userid, action) in enumerate(action_specific_userids):
       userid_idx = i + len(categories)

       # Count categories for this userid and action
       count = 0
       for category, uid, act in category_userid_pairs:
           if uid == userid and act == action:
               count += 1

       # Determine approver for this userid and action
       if action == "manage" and (userid, action) in userid_approver_map:
           approver = userid_approver_map[(userid, action)]
       else:
           approver = "no approver"

       # Find the index of the approver with this action
       approver_idx = -1
       for j, approver_item in enumerate(action_specific_approvers):
           # Handle both tuple and string formats
           if isinstance(approver_item, tuple):
               appr, act = approver_item
               if appr == approver and act == action:
                   approver_idx = j
                   break
           else:
               # For string format, extract approver and action
               if f"{approver} [{action}]" == approver_item or f"no approver [{action}]" == approver_item:
                   approver_idx = j
                   break
       if approver_idx == -1:
           print(f"Warning: Could not find action-specific approver for {approver} and {action}")
       approver_idx = approver_idx + len(categories) + len(action_specific_userids) + len(actions)

       sources.append(userid_idx)
       targets.append(approver_idx)
       values.append(count)  # Value based on count of categories with this action
       link_colors.append("rgba(148, 103, 189, 0.5)")  # Purple for approver links

   # Create links from action-specific approvers to actions
   # Each action-specific approver is already associated with a specific action
   for i, approver_item in enumerate(action_specific_approvers):
       approver_idx = i + len(categories) + len(action_specific_userids) + len(actions)

       # Handle both tuple and string formats
       if isinstance(approver_item, tuple):
           approver, action = approver_item
       else:
           # For string format, extract approver and action
           if "[" in approver_item:
               approver, action_part = approver_item.rsplit(" [", 1)
               action = action_part.rstrip("]")
           else:
               # Default values if format is unexpected
               approver = approver_item
               action = "unknown"

       # Count categories for this approver and action
       count = 0
       for category, uid, act in category_userid_pairs:
           if act == action and act != "deny":  # Skip deny actions
               # Find the approver for this category and action
               if act == "manage" and (uid, act) in userid_approver_map and userid_approver_map[(uid, act)] == approver:
                   count += 1
               elif approver == "no approver" and (act != "manage" or (uid, act) not in userid_approver_map):
                   count += 1

       # Create link to the action
       action_idx = actions.index(action) + len(categories) + len(action_specific_userids)
       sources.append(approver_idx)
       targets.append(action_idx)
       values.append(count)
       link_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.5)"))

   # Create the Sankey diagram
   fig = go.Figure(data=[go.Sankey(
       node=dict(
           pad=20,            # Increase padding for better readability
           thickness=25,      # Increase thickness for wider displays
           line=dict(color="black", width=0.8),
           label=node_labels,
           color=node_colors
       ),
       link=dict(
           source=sources,
           target=targets,
           value=values,
           color=link_colors
       ),
       arrangement="freeform",    # Change from "snap" to "freeform" for consistency
       orientation="h",           # Add horizontal orientation
       # Add domain configuration for better space utilization
       domain=dict(x=[0.0, 1.0], y=[0.0, 1.0])  # Use full available space
   )])

   # Update layout
   fig.update_layout(
       title=dict(
           text="Policy treatment of URL categories",
           x=0.5,  # Center horizontally (0=left, 0.5=center, 1=right)
           xanchor='center'  # Anchor point for the x position
       ),
       font=dict(
           size=14,           # Increase from 8 to 14 for better readability
           family="Arial, sans-serif",
           color="black"
       ),
       height=2000,           # Increase height to accommodate all categories
       # Remove fixed width to allow full page utilization
       margin=dict(l=15, r=15, t=40, b=10),  # Slightly increase margins for larger font
       autosize=True,         # Allow the figure to be responsive
       paper_bgcolor='rgba(0,0,0,0)',  # Transparent background
       plot_bgcolor='rgba(0,0,0,0)',   # Transparent plot area
       showlegend=False,      # Ensure no legend interferes with width
       template="plotly_white"  # Clean template for better appearance
   )

   # Save the figure as an HTML file for the "Open in new window" link
   try:
       import os
       # Save directly to the _static directory that Sphinx will use
       image_dir = '_static'
       if not os.path.exists(image_dir):
           os.makedirs(image_dir)
       fig.write_html(os.path.join(image_dir, 'url_categories_sankey.html'), 
                     include_plotlyjs='cdn',
                     full_html=True,
                     config={
                         'responsive': True,
                         'displayModeBar': True,
                         'displaylogo': False,
                         'toImageButtonOptions': {
                             'format': 'png',
                             'filename': 'url_categories_sankey',
                             'height': 1000,
                             'width': 1400,
                             'scale': 1
                         }
                     })
   except Exception as e:
       print(f"Warning: Could not save HTML: {e}")

   fig



.. raw:: html

   <a href="javascript:void(0);" onclick="window.open('_static/app_categories_sankey.html', '_blank', 'width=1200,height=800');" style="float: right; margin-bottom: 10px;">Open in new window</a>

.. plotly::

   import plotly.graph_objects as go
   import csv
   import os
   from collections import defaultdict

   # Define colors for different actions and entities
   action_colors = {
       "manage": "rgba(31, 119, 180, 0.8)",  # Blue
       "deny": "rgba(214, 39, 40, 0.8)",     # Red
       "do not manage": "rgba(44, 160, 44, 0.8)",  # Green
       "continue": "rgba(255, 127, 14, 0.8)", # Orange
       "approver": "rgba(148, 103, 189, 0.8)",  # Purple for approvers
       "userid": "rgba(23, 190, 207, 0.8)"   # Cyan for UserIDs
   }

   # Path to the CSV file
   # Try different relative paths to find the CSV file
   possible_paths = [
       os.path.join(os.path.abspath('../..'), 'requirements', 'categories_app.csv'),
       os.path.join(os.path.abspath('.'), 'requirements', 'categories_app.csv'),
       os.path.join(os.path.abspath('..'), 'requirements', 'categories_app.csv'),
       'requirements/categories_app.csv',  # Direct relative path
   ]

   csv_file = None
   for path in possible_paths:
       if os.path.exists(path):
           csv_file = path
           break

   if csv_file is None:
       # If file not found, use a hardcoded sample for demonstration
       print("Warning: categories_app.csv file not found. Using sample data.")
       # Sample data structure for demonstration
       sample_data = [
           {"SubCategory": "email", "Action": "manage", "Approver": "compliance", "UserID": "UG-email"},
           {"SubCategory": "database", "Action": "deny", "Approver": "", "UserID": ""},
           {"SubCategory": "analytics", "Action": "do not manage", "Approver": "", "UserID": ""}
       ]

   # Read the data
   subcategories = []
   unique_subcategories = set()
   actions = []
   unique_actions = set()
   approvers = []
   unique_approvers = set()
   userids = []
   unique_userids = set()
   action_counts = defaultdict(int)
   approver_counts = defaultdict(int)
   userid_counts = defaultdict(int)
   subcategory_action_pairs = []
   action_approver_pairs = []
   subcategory_userid_pairs = []
   userid_approver_pairs = []

   # For action-specific nodes
   action_specific_userids = []
   unique_action_specific_userids = set()
   action_specific_approvers = []
   unique_action_specific_approvers = set()

   if csv_file is not None:
       # Read from CSV file
       with open(csv_file, 'r') as f:
           reader = csv.DictReader(f)
           for row in reader:
               subcategory = row['SubCategory']
               action = row['Action']
               approver = row.get('Approver', '')  # Get approver if available
               userid = row.get('UserID', '')  # Get UserID if available

               # For non-managed categories (with "do not manage" action), set UserID to "known-user"
               if action == "do not manage" and not userid:
                   userid = "known-user"

               if subcategory not in unique_subcategories:
                   subcategories.append(subcategory)
                   unique_subcategories.add(subcategory)

               if action not in unique_actions:
                   actions.append(action)
                   unique_actions.add(action)

               # Add approver if provided, or add "no approver" for non-deny actions if not already in the list
               if action != "deny":
                   if approver and approver not in unique_approvers:
                       approvers.append(approver)
                       unique_approvers.add(approver)
                   elif "no approver" not in unique_approvers:
                       approvers.append("no approver")
                       unique_approvers.add("no approver")

                   # Create action-specific approver nodes
                   action_specific_approver = f"{approver or 'no approver'} [{action}]"
                   if action_specific_approver not in unique_action_specific_approvers:
                       action_specific_approvers.append(action_specific_approver)
                       unique_action_specific_approvers.add(action_specific_approver)

               # Add UserID if not already in the list
               if userid and userid not in unique_userids:
                   userids.append(userid)
                   unique_userids.add(userid)

               # Create action-specific UserID nodes for non-deny actions
               if action != "deny" and userid:
                   action_specific_userid = f"{userid}"
                   action_specific_userid_key = f"{userid}_{action}"
                   if action_specific_userid_key not in unique_action_specific_userids:
                       action_specific_userids.append((action_specific_userid, action))
                       unique_action_specific_userids.add(action_specific_userid_key)

               action_counts[action] += 1
               subcategory_action_pairs.append((subcategory, action))

               # Create subcategory-userid pairs
               if userid:
                   userid_counts[userid] += 1
                   subcategory_userid_pairs.append((subcategory, userid, action))  # Added action to the tuple

               # Create userid-approver pairs for "manage" actions
               if action == "manage" and approver and userid:
                   userid_approver_pairs.append((userid, approver, action))  # Added action to the tuple

               # Create action-approver pairs for "manage" actions
               if action == "manage" and approver:
                   approver_counts[approver] += 1
                   action_approver_pairs.append((action, approver))
   else:
       # Use sample data
       for row in sample_data:
           subcategory = row['SubCategory']
           action = row['Action']
           approver = row.get('Approver', '')  # Get approver if available
           userid = row.get('UserID', '')  # Get UserID if available

           # For non-managed categories (with "do not manage" action), set UserID to "known-user"
           if action == "do not manage" and not userid:
               userid = "known-user"

           if subcategory not in unique_subcategories:
               subcategories.append(subcategory)
               unique_subcategories.add(subcategory)

           if action not in unique_actions:
               actions.append(action)
               unique_actions.add(action)

           # Only add approver if action is "manage" and approver is not empty
           if action == "manage" and approver and approver not in unique_approvers:
               approvers.append(approver)
               unique_approvers.add(approver)

               # Create action-specific approver nodes
               action_specific_approver = f"{approver}"
               action_specific_approver_key = f"{approver}_{action}"
               if action_specific_approver_key not in unique_action_specific_approvers:
                   action_specific_approvers.append((action_specific_approver, action))
                   unique_action_specific_approvers.add(action_specific_approver_key)
           elif action != "deny" and "no approver" not in unique_approvers:
               approvers.append("no approver")
               unique_approvers.add("no approver")

               # Create action-specific approver nodes
               action_specific_approver = f"no approver [{action}]"
               if action_specific_approver not in unique_action_specific_approvers:
                   action_specific_approvers.append(action_specific_approver)
                   unique_action_specific_approvers.add(action_specific_approver)

           # Add UserID if not already in the list
           if userid and userid not in unique_userids:
               userids.append(userid)
               unique_userids.add(userid)

           # Create action-specific UserID nodes for non-deny actions
           if action != "deny" and userid:
               action_specific_userid = f"{userid}"
               action_specific_userid_key = f"{userid}_{action}"
               if action_specific_userid_key not in unique_action_specific_userids:
                   action_specific_userids.append((action_specific_userid, action))
                   unique_action_specific_userids.add(action_specific_userid_key)

           action_counts[action] += 1
           subcategory_action_pairs.append((subcategory, action))

           # Create subcategory-userid pairs
           if userid:
               userid_counts[userid] += 1
               subcategory_userid_pairs.append((subcategory, userid, action))  # Added action to the tuple

           # Create userid-approver pairs for "manage" actions
           if action == "manage" and approver and userid:
               userid_approver_pairs.append((userid, approver, action))  # Added action to the tuple

           # Create action-approver pairs for "manage" actions
           if action == "manage" and approver:
               approver_counts[approver] += 1
               action_approver_pairs.append((action, approver))

   # Create node labels and colors
   # Extract just the userid from the tuples in action_specific_userids
   userid_labels = [userid for userid, _ in action_specific_userids]
   # Extract just the approver from the tuples in action_specific_approvers
   # Handle both tuple and string formats in action_specific_approvers
   approver_labels = []
   for approver_item in action_specific_approvers:
       if isinstance(approver_item, tuple):
           approver, _ = approver_item
           approver_labels.append(approver)
       else:
           # For string format, extract approver without the action part
           if "[" in approver_item:
               approver, _ = approver_item.rsplit(" [", 1)
               approver_labels.append(approver)
           else:
               approver_labels.append(approver_item)
   node_labels = subcategories + userid_labels + actions + approver_labels
   node_colors = []

   # Assign colors to nodes (subcategories are gray, userids are cyan, actions have specific colors, approvers are purple)
   for i in range(len(node_labels)):
       if i < len(subcategories):
           node_colors.append("rgba(128, 128, 128, 0.8)")  # Gray for subcategories
       elif i < len(subcategories) + len(action_specific_userids):
           node_colors.append(action_colors.get("userid", "rgba(23, 190, 207, 0.8)"))  # Cyan for UserIDs
       elif i < len(subcategories) + len(action_specific_userids) + len(actions):
           action = node_labels[i]
           node_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.8)"))
       else:
           node_colors.append("rgba(148, 103, 189, 0.8)")  # Purple for approvers

   # Create source, target, and value arrays for links
   sources = []
   targets = []
   values = []
   link_colors = []

   # Create subcategory-userid-approver-action mappings
   subcategory_userid_map = {}
   userid_approver_map = {}
   subcategory_action_map = {}

   # Map subcategories to userids and actions
   for subcategory, userid, action in subcategory_userid_pairs:
       subcategory_userid_map[(subcategory, action)] = userid
       subcategory_action_map[subcategory] = action

   # Map userids to approvers for "manage" actions
   for userid, approver, action in userid_approver_pairs:
       userid_approver_map[(userid, action)] = approver

   # Create links from subcategories to userids or directly to actions for "deny" subcategories
   for subcategory in subcategories:
       subcategory_idx = subcategories.index(subcategory)

       # Find the action for this subcategory
       action = None
       for subcat, act in subcategory_action_pairs:
           if subcat == subcategory:
               action = act
               break

       if action == "deny":
           # For blocked subcategories, link directly to action
           action_idx = actions.index(action) + len(subcategories) + len(action_specific_userids)
           sources.append(subcategory_idx)
           targets.append(action_idx)
           values.append(1)  # Each link has a value of 1
           link_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.5)"))
       else:
           # For other subcategories, link to action-specific userid
           userid = subcategory_userid_map.get((subcategory, action), "known-user")  # Default to "known-user" if not found
           action_specific_userid_key = f"{userid}_{action}"
           # Find the index of the tuple with this userid and action
           userid_idx = -1
           for i, (uid, act) in enumerate(action_specific_userids):
               if uid == userid and act == action:
                   userid_idx = i
                   break
           if userid_idx == -1:
               print(f"Warning: Could not find action-specific userid for {userid} and {action}")
           userid_idx = userid_idx + len(subcategories)

           sources.append(subcategory_idx)
           targets.append(userid_idx)
           values.append(1)  # Each link has a value of 1
           link_colors.append(action_colors.get("userid", "rgba(23, 190, 207, 0.5)"))  # Cyan for UserID links

   # Create links from action-specific userids to action-specific approvers
   for i, (userid, action) in enumerate(action_specific_userids):
       userid_idx = i + len(subcategories)

       # Count subcategories for this userid and action
       count = 0
       for subcategory, uid, act in subcategory_userid_pairs:
           if uid == userid and act == action:
               count += 1

       # Determine approver for this userid and action
       if action == "manage" and (userid, action) in userid_approver_map:
           approver = userid_approver_map[(userid, action)]
       else:
           approver = "no approver"

       # Find the index of the approver with this action
       approver_idx = -1
       for j, approver_item in enumerate(action_specific_approvers):
           # Handle both tuple and string formats
           if isinstance(approver_item, tuple):
               appr, act = approver_item
               if appr == approver and act == action:
                   approver_idx = j
                   break
           else:
               # For string format, extract approver and action
               if f"{approver} [{action}]" == approver_item or f"no approver [{action}]" == approver_item:
                   approver_idx = j
                   break
       if approver_idx == -1:
           print(f"Warning: Could not find action-specific approver for {approver} and {action}")
       approver_idx = approver_idx + len(subcategories) + len(action_specific_userids) + len(actions)

       sources.append(userid_idx)
       targets.append(approver_idx)
       values.append(count)  # Value based on count of subcategories with this action
       link_colors.append("rgba(148, 103, 189, 0.5)")  # Purple for approver links

   # Create links from action-specific approvers to actions
   # Each action-specific approver is already associated with a specific action
   for i, approver_item in enumerate(action_specific_approvers):
       approver_idx = i + len(subcategories) + len(action_specific_userids) + len(actions)

       # Handle both tuple and string formats
       if isinstance(approver_item, tuple):
           approver, action = approver_item
       else:
           # For string format, extract approver and action
           if "[" in approver_item:
               approver, action_part = approver_item.rsplit(" [", 1)
               action = action_part.rstrip("]")
           else:
               # Default values if format is unexpected
               approver = approver_item
               action = "unknown"

       # Count subcategories for this approver and action
       count = 0
       for subcategory, uid, act in subcategory_userid_pairs:
           if act == action and act != "deny":  # Skip deny actions
               # Find the approver for this subcategory and action
               if act == "manage" and (uid, act) in userid_approver_map and userid_approver_map[(uid, act)] == approver:
                   count += 1
               elif approver == "no approver" and (act != "manage" or (uid, act) not in userid_approver_map):
                   count += 1

       # Create link to the action
       action_idx = actions.index(action) + len(subcategories) + len(action_specific_userids)
       sources.append(approver_idx)
       targets.append(action_idx)
       values.append(count)
       link_colors.append(action_colors.get(action, "rgba(128, 128, 128, 0.5)"))

   # Create the Sankey diagram
   fig = go.Figure(data=[go.Sankey(
       node=dict(
           pad=20,            # Increase padding for better readability
           thickness=25,      # Increase thickness for wider displays
           line=dict(color="black", width=0.8),
           label=node_labels,
           color=node_colors
       ),
       link=dict(
           source=sources,
           target=targets,
           value=values,
           color=link_colors
       ),
       arrangement="freeform",  # Allow more flexible arrangement
       orientation="h",         # Horizontal orientation
       # Add domain configuration for better space utilization
       domain=dict(x=[0.0, 1.0], y=[0.0, 1.0])  # Use full available space
   )])

   # Update layout
   fig.update_layout(
       title=dict(
           text="Policy treatment of App-ID subcategories",
           x=0.5,  # Center horizontally (0=left, 0.5=center, 1=right)
           xanchor='center'  # Anchor point for the x position
       ),
       font=dict(
           size=14,           # Increase from 8 to 14 for better readability
           family="Arial, sans-serif",
           color="black"
       ),
       height=1200,           # Increased height to match graph size and eliminate canvas scrollbar
       # Remove fixed width to allow full page utilization
       margin=dict(l=15, r=15, t=40, b=10),  # Slightly increase margins for larger font
       autosize=True,         # Allow the figure to be responsive
       paper_bgcolor='rgba(0,0,0,0)',  # Transparent background
       plot_bgcolor='rgba(0,0,0,0)',   # Transparent plot area
       showlegend=False,      # Ensure no legend interferes with width
       template="plotly_white"  # Clean template for better appearance
       # Remove xaxis and yaxis constraints that may interfere with width responsiveness
   )

   # Save the figure as an HTML file for the "Open in new window" link
   try:
       import os
       # Save directly to the _static directory that Sphinx will use
       image_dir = '_static'
       if not os.path.exists(image_dir):
           os.makedirs(image_dir)
       fig.write_html(os.path.join(image_dir, 'app_categories_sankey.html'), 
                     include_plotlyjs='cdn',
                     full_html=True,
                     config={
                         'responsive': True,
                         'displayModeBar': True,
                         'displaylogo': False,
                         'toImageButtonOptions': {
                             'format': 'png',
                             'filename': 'app_categories_sankey',
                             'height': 1000,
                             'width': 1400,
                             'scale': 1
                         }
                     })
   except Exception as e:
       print(f"Warning: Could not save HTML: {e}")

   fig


Naming Conventions
------------------

This section describes the naming conventions used for all objects referenced by the security or decryption policy:

.. list-table::
   :header-rows: 1

   * - Object Type
     - Prefix
     - Example
   * - Address (network)
     - ``N-``
     - ``N-rfc_1918-10.0.0.0_8``
   * - Address (host)
     - ``H-``
     - ``H-open_dns-208.67.222.222_32``
   * - Address (FQDN)
     - ``FQDN-``
     - ``FQDN-time.apple.com``
   * - Address group
     - ``AG-``
     - ``AG-rfc_1918``
   * - Dynamic address group
     - ``DAG-``
     - ``DAG-domain-controllers``
   * - Service object
     - ``SVC-``
     - ``SVC-udp-53``
   * - Application group
     - ``APG-``
     - ``APG-file-sharing``
   * - Custom application
     - ``APP-``
     - ``APP-windows-conn-check``
   * - External dynamic list
     - ``EDL-``
     - ``EDL-URL-no_decryption_dst``
   * - Custom URL category (list)
     - ``UCL-``
     - ``UCL-acme-generic-app``
   * - Custom URL category (match)
     - ``UCM-``
     - ``UCM-comp-inet-info_low-risk``
   * - Security profile group
     - ``PG-``
     - ``PG-apps-risky``
   * - Antivirus profile
     - ``AVP-``
     - ``AVP-default``
   * - Anti-spyware profile
     - ``ASP-``
     - ``ASP-strict``
   * - Vulnerability profile
     - ``VPP-``
     - ``VPP-default``
   * - File blocking profile
     - ``FBP-``
     - ``FBP-log-only``
   * - URL filtering profile
     - ``UFP-``
     - ``UFP-log-only``
   * - WildFire profile
     - ``WFP-``
     - ``WFP-default``
   * - Data filtering profile
     - ``DFP-``
     - ``DFP-default``
   * - Decryption profile
     - ``DP-``
     - ``DP-no_decryption``
   * - Log forwarding profile
     - ``LFP-``
     - ``LFP-default``
   * - User group
     - ``UG-``
     - ``UG-decryption_break-glass``
