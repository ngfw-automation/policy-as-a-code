# External Dynamic Lists (EDLs) Configuration

This document explains the format of the `edls.csv` file and how to populate it with External Dynamic List (EDL) definitions for Palo Alto Networks firewalls.

## File Format

The `edls.csv` file defines External Dynamic Lists that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single EDL configuration.

### CSV Columns

| Column Name | Description | Required | Example |
|-------------|-------------|----------|---------|
| Name | Name of the EDL | Yes | `EDL-EXT-IP-DST-azure_atp` |
| Old name | Previous name for the EDL (for reference) | No | `External EDL - Azure ATP` |
| Type | Type of EDL (ip, url, domain) | Yes | `ip` |
| Repeat | How often the EDL should be refreshed | Yes | `daily`, `hourly`, `five-minute` |
| Repeat At | Specific time for refresh (if applicable) | No | `2` (for 2:00 AM) |
| Username | Username for authentication (if required) | No | `admin` |
| Password | Password for authentication (if required) | No | `password` |
| Certificate Profile | Certificate profile for authentication (if required) | No | `cert-profile-1` |
| Source | The URL source of the EDL | Yes | `https://example.com/edl.txt` |
| Description | A description of the EDL | No | `External EDL hosted by Example Inc.` |

## How to Use

### Basic EDL Configuration

To define a basic EDL, you need to specify at least the Name, Type, Repeat, and Source:

```
EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,,,,,https://example.com/edl.txt,External EDL hosted by Example Inc.
```

This will create an EDL named `EDL-EXT-IP-DST-example` that fetches IP addresses from `https://example.com/edl.txt` and refreshes daily.

### EDL Types

EDLs can be of different types:

1. **IP EDLs** - Used for lists of IP addresses:
   ```
   EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,,,,,https://example.com/ip-list.txt,External EDL with IP addresses
   ```

2. **URL EDLs** - Used for lists of URLs:
   ```
   EDL-EXT-URL-DST-example,External EDL - Example,url,daily,,,,,https://example.com/url-list.txt,External EDL with URLs
   ```

3. **Domain EDLs** - Used for lists of domains:
   ```
   EDL-EXT-DOM-DST-example,External EDL - Example,domain,daily,,,,,https://example.com/domain-list.txt,External EDL with domains
   ```

### Refresh Schedules

EDLs can be refreshed at different intervals:

1. **Daily** - Refreshed once per day:
   ```
   EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,7,,,,https://example.com/edl.txt,Refreshed daily at 7 AM
   ```

2. **Hourly** - Refreshed once per hour:
   ```
   EDL-EXT-IP-DST-example,External EDL - Example,ip,hourly,,,,,https://example.com/edl.txt,Refreshed hourly
   ```

3. **Five-minute** - Refreshed every five minutes:
   ```
   EDL-EXT-IP-DST-example,External EDL - Example,ip,five-minute,,,,,https://example.com/edl.txt,Refreshed every five minutes
   ```

### Authentication

For EDLs that require authentication:

```
EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,,username,password,,https://example.com/edl.txt,EDL with basic authentication
```

### Certificate Profile

For EDLs that require certificate-based authentication:

```
EDL-EXT-IP-DST-example,External EDL - Example,ip,daily,,,,cert-profile-1,https://example.com/edl.txt,EDL with certificate authentication
```

### Environment-Specific EDLs

For EDLs that need to be environment-specific, use the `<target_environment>` placeholder in the Source URL:

```
EDL-IP-break_glass_dst,Internal EDL - IP DST - break-glass,ip,five-minute,,,,,https://edls.example.local/edl/<target_environment>/ip-dst-break-glass.txt,Internal EDL for break-glass scenarios
```

The `<target_environment>` placeholder will be replaced with the actual target environment name during deployment.

## Examples

Here are some examples of EDL definitions:

### External EDLs (hosted by third parties)

```
EDL-EXT-IP-DST-azure_atp,External EDL - Azure ATP,ip,daily,2,,,,https://saasedl.paloaltonetworks.com/feeds/azure/public/azureadvancedthreatprotection/ipv4,External EDL hosted by Palo Alto Networks. Contains IP addresses that belong to Azure Advanced Threat Prevention.
EDL-URL-m365_worldwide_any_all,External EDL - URL - M365 Worldwide Any ALL,url,daily,7,,,,https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/any/all/url,External EDL hosted by Palo Alto Networks. Contains URLs that belong to Microsoft 365.
EDL-EXT-IP-DST-zoom,External EDL - Zoom,ip,daily,3,,,,https://assets.zoom.us/docs/ipranges/Zoom.txt,External EDL hosted by Zoom. Contains IP addresses that belong to Zoom.
```

### Internal EDLs (hosted within the organization)

```
EDL-IP-break_glass_dst,Internal EDL - IP DST - break-glass,ip,five-minute,,,,,https://edls.example.local/edl/<target_environment>/ip-dst-break-glass.txt,Internal EDL. Contains destination IP addresses that ALL internal hosts are allowed to access.
EDL-URL-no_decryption_dst,Internal EDL - URL - do not decrypt,url,hourly,,,,,https://edls.example.local/edl/<target_environment>/url-no-decrypt.txt,Internal EDL. Contains URLs that will never be decrypted.
```

## Implementation Details

The EDLs defined in this CSV file are processed by the `create_edls` function in the `edls.py` module. This function:

1. Parses the CSV file using the `parse_metadata_from_csv` function
2. Creates a table to display the EDLs being staged
3. Processes each EDL entry from the CSV file:
   - Handles formatting for the "Repeat At" field
   - Sets certificate profile, username, and password if provided
   - Handles environment-specific EDL source URLs by replacing `<target_environment>` placeholders
4. Creates EDL objects using the Palo Alto Networks SDK
5. Deploys the EDLs to the PAN-OS device using multi-config API calls

## Validation Rules

- EDL names should follow a consistent naming convention (e.g., `EDL-EXT-IP-DST-example` for external IP destination lists)
- EDL types must be one of: ip, url, or domain
- Repeat values must be one of: daily, hourly, or five-minute
- If Repeat is set to daily, Repeat At should specify the hour (0-23)
- Source URLs must be valid and accessible from the firewall
- For internal EDLs with environment-specific URLs, use the `<target_environment>` placeholder

## Notes

- If you modify this file, you need to redeploy the configuration to the firewall for changes to take effect
- EDLs are essential components for security policy rules that need to match specific IP addresses, URLs, or domains
- External EDLs are typically hosted by third parties (like Palo Alto Networks or other vendors)
- Internal EDLs are typically hosted within your organization and may be environment-specific
- The `<target_environment>` placeholder in Source URLs will be replaced with the actual target environment name during deployment
- EDLs with five-minute refresh intervals should be used sparingly and only for critical lists that require frequent updates