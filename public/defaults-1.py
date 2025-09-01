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
        pad=5,             # Minimal padding to save space
        thickness=10,      # Reduced thickness further
        line=dict(color="black", width=0.5),
        label=node_labels,
        color=node_colors
    ),
    link=dict(
        source=sources,
        target=targets,
        value=values,
        color=link_colors
    ),
    arrangement="snap"     # More compact arrangement
)])

# Update layout
fig.update_layout(
    title_text="URL Categories and Their Actions",
    font_size=8,           # Smaller font size
    height=2000,           # Increase height to accommodate all categories
    width=600,             # Further reduced width to fit the page better
    margin=dict(l=5, r=5, t=30, b=5),  # Minimal margins
    autosize=True,         # Allow the figure to be responsive
    paper_bgcolor='rgba(0,0,0,0)',  # Transparent background
    plot_bgcolor='rgba(0,0,0,0)'    # Transparent plot area
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
                  config={'responsive': True})
except Exception as e:
    print(f"Warning: Could not save HTML: {e}")

fig