# Response Pages

This directory contains configuration and templates for customizable response pages displayed by the NGFW when blocking content.

## Directory Structure

- **lab/** - Response pages for lab/testing environment
  - **configs/** - YAML configuration files for different response pages
  - **templates/** - Jinja2 templates for rendering response pages
  - **shared.yaml** - Shared configuration values for the lab environment
- **prod/** - Response pages for production environment (similar structure to lab)

## How Response Pages Work

Response pages are generated using a combination of:
1. YAML configuration files that define content and conditional logic
2. Jinja2 templates that define the HTML structure
3. JavaScript that processes conditions and populates dynamic content

### Configuration Files

Each response page has a YAML configuration file in the `configs/` directory. These files define:

- Basic page information (page_id, title)
- Default heading and message
- Conditional blocks that customize the response based on attributes of the blocked content
- Fallback content for when no conditions match
- Service desk form IDs for different scenarios

Example structure:
```yaml
page_id: url_block_page
title: "Web Page Blocked"
default_heading: "Web page blocked (unknown reason)"
default_message: "This website has been blocked according to our security policy."

conditional_blocks:
  - match: category
    operator: includes
    value: web-based-email
    heading: "Compliance warning"
    message: "For your security and data protection, access to personal web-mail sites is prohibited..."

fallback:
  heading: "Approval required"
  message: "This website falls under a category that requires approval before use..."
```

### Templates

Templates are Jinja2 files (`.html.j2`) that define the HTML structure of response pages. The system uses:

- **base.html.j2** - The main template that defines the overall structure
- Page-specific templates that extend the base template to add custom behavior

Most page-specific templates are minimal and simply extend the base template, but they can override blocks to customize behavior.

### Shared Configuration

The `shared.yaml` file contains values used across all response pages in an environment:

- Organization information (name, department labels)
- URLs for service desk and redirects
- Global CSS styling
- Common messages

## Customizing Response Pages

To customize response pages for your organization:

1. **Update shared.yaml**:
   - Set your organization name and labels
   - Update service desk URLs
   - Customize CSS to match your branding

2. **Modify configuration files**:
   - Update messages to reflect your policies
   - Customize conditional logic based on your requirements
   - Update service desk form IDs

3. **Customize templates** (if needed):
   - Modify base.html.j2 to change the overall structure
   - Create or update page-specific templates for special cases

### Example: Customizing URL Block Page

To customize the URL block page:

1. Edit `configs/url-block-page.yaml`:
   ```yaml
   title: "Your Company - Access Restricted"
   default_heading: "Website Access Restricted"
   default_message: "This website has been blocked according to Your Company's security policy..."
   ```

2. Update conditional blocks to match your policies:
   ```yaml
   conditional_blocks:
     - match: category
       operator: includes
       value: social-networking
       heading: "Social Media Access Restricted"
       message: "Access to social media sites is limited during business hours..."
   ```

3. Update service desk form IDs to point to your ticketing system.

For more advanced customization, you can modify the templates or create new ones.