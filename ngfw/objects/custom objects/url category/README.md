# Custom URL Categories Configuration

This document explains the format of the `custom-url-categories.csv` file and how to populate it with custom URL category definitions for Palo Alto Networks firewalls.

## File Format

The `custom-url-categories.csv` file defines custom URL categories that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a URL or pattern that belongs to a custom URL category.

### CSV Columns

| Column Name | Description | Required | Example |
|-------------|-------------|----------|---------|
| Name | Name of the custom URL category | Yes | `UCL-acme-generic-app` |
| Type | Type of category (List or Match) | Yes | `List` |
| Description | Optional description for the category | No | `This category covers all URLs in ACME domains and subdomains` |
| Sites | URL, pattern, or predefined category to include | Yes | `example.com/`, `computer-and-internet-info` |

## How to Use

### Basic Custom URL Category

To define a basic URL List category:

```
UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
```

This will create a custom URL category named `UCL-acme-generic-app` that includes the URL `example.com/`.

### Custom URL Category Types

Custom URL categories can be of two types:

1. **URL List** - Contains specific URLs or patterns:
   ```
   UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
   UCL-acme-generic-app,List,,*.example.com/
   ```

2. **Category Match** - References predefined PAN-OS URL categories:
   ```
   UCM-comp-inet-info_low-risk,Match,,computer-and-internet-info
   UCM-comp-inet-info_low-risk,Match,,low-risk
   ```

### Multiple URLs in a Category

You can add multiple URLs to the same category by repeating the category name in multiple rows:

```
UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
UCL-acme-generic-app,List,,*.example.com/
UCL-acme-generic-app,List,,example.net/
UCL-acme-generic-app,List,,*.example.net/
```

This will add all four URLs/patterns to the `UCL-acme-generic-app` category.

### URL Patterns

You can use wildcards and special characters in URL patterns:

1. **Wildcard matching** 
   - Use `*` to match one or more tokens (subdomain names in this example):
      ```
      UCL-palo-alto-dependencies,List,URLs required for firewall-related services,*.paloaltonetworks.com/
      ```

  - Use `^` to match precisely one token (a subdomain in this example):
     ```
     UCL-restricted_file_download,List,,^.vo.msecnd.net/stable/
     ```

### Remote URL Lists

You can reference a remote HTTP/HTTPS source for URL lists:

```
UCL-m365-worldwide-any-optimize,List,This category includes URLs from M365 Worldwide Any Optimize category,https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/any/optimize/url
```

This will fetch the URL list from the specified HTTP/HTTPS source and include all URLs in the category.
This approach allows you to save firewall system capacity for EDLs by configuring them as a regular custom URL category
rather than an EDL (this works if you know that the target file rarely
changes, or you have an automation in place to rerun this policy deployment script when the source file gets updated)

## Naming Conventions

The custom URL categories in the CSV file follow these naming conventions:

1. **URL List categories**:
   - `UCL-` prefix (e.g., `UCL-acme-generic-app`)

2. **Category Match categories**:
   - `UCM-` prefix (e.g., `UCM-comp-inet-info_low-risk`)

## Examples

Here are some examples of custom URL category definitions:

### URL List Examples

```
UCL-acme-generic-app,List,This category covers all URLs in ACME domains and subdomains,example.com/
UCL-acme-generic-app,List,,*.example.com/
UCL-restricted_file_download,List,Websites where all authenticated users are allowed to download files of restricted types,^.vo.msecnd.net/stable/
UCL-palo-alto-dependencies,List,URLs required for firewall-related services,*.paloaltonetworks.com/
```

### Category Match Examples

```
UCM-comp-inet-info_low-risk,Match,,computer-and-internet-info
UCM-comp-inet-info_low-risk,Match,,low-risk
UCM-content-delivery_low-risk,Match,,content-delivery-networks
UCM-content-delivery_low-risk,Match,,low-risk
```

## Implementation Details

The custom URL categories defined in this CSV file are processed by the `create_custom_url_categories` function in the `url_categories.py` module. This function:

1. Parses the CSV file using the `parse_metadata_from_csv` function
2. Builds a deduplicated list of custom categories based on their names and types
3. Processes each category:
   - Extracts the description (using the last non-empty description for each category)
   - Builds a list of URLs or categories for each custom category
   - Handles remote HTTP/HTTPS sources for URL lists
4. Creates custom URL category objects using the Palo Alto Networks SDK:
   - URL List type categories with specific URLs or patterns
   - Category Match type categories referencing predefined PAN-OS URL categories
5. Deploys the custom URL categories to the PAN-OS device using multi-config API calls

Additionally, the module can create dynamic custom URL categories based on business requirements, such as risk-based category matching profiles (medium and high risk).

## Validation Rules

- Custom URL category names should follow the naming conventions described above
- Category types must be one of: List (or URL List), Match (or Category Match)
- For URL List categories, the Sites column should contain valid URLs or patterns
- For Category Match categories, the Sites column should contain valid predefined PAN-OS URL categories
- Remote URL lists must be accessible via HTTP/HTTPS from the firewall

## Notes

- If you modify this file, you need to redeploy the configuration to the firewall for changes to take effect
- Custom URL categories are essential components for security policy rules that need to match specific websites or categories
- URL List categories are useful for matching specific websites or patterns
- Category Match categories are useful for combining predefined PAN-OS URL categories
- Remote URL lists allow you to maintain URL lists outside of the firewall configuration
- The system can automatically create risk-based category matching profiles based on business requirements
