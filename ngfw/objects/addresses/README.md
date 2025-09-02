# Address Objects Configuration

This document explains the format of the `address_objects.csv` file and how to populate it with address object definitions for Palo Alto Networks firewalls.

## File Format

The `address_objects.csv` file defines address objects that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single address object or an address object that belongs to an address group.

### CSV Columns

| Column Name | Description | Required | Example |
|-------------|-------------|----------|---------|
| Name | Name of the address object | Yes | `N-rfc_1918-10.0.0.0_8` |
| Type | Type of address object (IP Netmask, IP Wildcard, IP Range, FQDN, Static Group) | Yes | `IP Netmask` |
| Address | The actual address value | Yes | `10.0.0.0/8`, `time.apple.com` |
| Tags | Semicolon-separated list of tags to apply to the address object | No | `internal;trusted` |
| Description | Optional description for the address object | No | `RFC 1918 private address space` |
| Group Name | Name of the address group this object belongs to | No | `AG-internal_network` |
| Group Tags | Tags to apply to the address group | No | `internal;network` |
| Group Description | Description for the address group | No | `Internal network address space` |

## How to Use

### Basic Address Object

To define a basic IP Netmask address object:

```
N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,,,
```

This will create an address object named `N-rfc_1918-10.0.0.0_8` for the 10.0.0.0/8 network.

### Address Object Types

Address objects can be of different types:

1. **IP Netmask** - Used for IP addresses with subnet masks:
   ```
   N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,,,
   ```

2. **IP Wildcard** - Used for IP addresses with wildcard masks:
   ```
   WC-example,IP Wildcard,10.0.0.0/0.0.0.255,,,,,
   ```

3. **IP Range** - Used for a range of IP addresses:
   ```
   R-dhcp-pool,IP Range,192.168.1.100-192.168.1.200,,,,,
   ```

4. **FQDN** - Used for fully qualified domain names:
   ```
   FQDN-time.apple.com,FQDN,time.apple.com,,,,,
   ```

### Address Object with Tags

To add tags to an address object:

```
N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,internal;trusted,RFC 1918 private address space,,,,
```

This will create an address object with the tags "internal" and "trusted".

### Address Object in a Group

To add an address object to an address group:

```
N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,AG-internal_network,,This group represents the internal network of your organization
```

This will create an address object and add it to the address group `AG-internal_network`.

### Multiple Address Objects in a Group

You can add multiple address objects to the same group:

```
N-rfc_1918-10.0.0.0_8,IP Netmask,10.0.0.0/8,,,AG-internal_network,,This group represents the internal network of your organization
N-rfc_1918-172.16.0.0_12,IP Netmask,172.16.0.0/12,,,AG-internal_network,,
N-rfc_1918-192.168.0.0_16,IP Netmask,192.168.0.0/16,,,AG-internal_network,,
```

This will add all three RFC 1918 private address spaces to the `AG-internal_network` group.

### Groups of Groups (Nested Groups)

To create a group that contains other groups, use the "Static Group" type:

```
AG-internal_network,Static Group,AG-corporate_network,,,AG-all_internal_networks,,All internal networks including corporate and branch offices
```

This will create a group hierarchy where `AG-internal_network` is a member of `AG-all_internal_networks`.

## Naming Conventions

The address objects in the CSV file follow these naming conventions:

1. **IP Netmask objects**:
   - `N-` prefix for networks (e.g., `N-rfc_1918-10.0.0.0_8`)
   - `H-` prefix for host addresses (e.g., `H-lab_firewall_mng-192.168.50.103_32`)

2. **FQDN objects**:
   - `FQDN-` prefix (e.g., `FQDN-time.apple.com`)

3. **Address Groups**:
   - `AG-` prefix (e.g., `AG-internal_network`)

4. **Dynamic Address Groups**:
   - `DAG-` prefix (e.g., `DAG-compromised_hosts`)

## Examples

Here are some examples of address object definitions:

```
N-all-multicast-addresses_224.0.0.0_4,IP Netmask,224.0.0.0/4,,All IPv4 multicast addresses,,,
H-lab_firewall_mng-192.168.50.103_32,IP Netmask,192.168.50.103/32,,Management interface of the lab firewall,AG-all-palo-alto-devices,,"Management interfaces of firewalls, Panoramas and log collectors"
FQDN-time.apple.com,FQDN,time.apple.com,,Default time source for Apple MacOS/iOS,,,
FQDN-time.windows.com,FQDN,time.windows.com,,Default time source for Microsoft Windows,,,
```

## Implementation Details

The address objects defined in this CSV file are processed by the `stage_address_objects` function in the `address_objects_staging.py` module. This function:

1. Parses the CSV file using the `parse_metadata_from_csv` function
2. Converts human-readable types from the CSV file to exact API keywords
3. Processes tags and descriptions
4. Creates address objects using the Palo Alto Networks SDK
5. Creates static and dynamic address groups
6. Handles nested groups (groups of groups)
7. Deploys the address objects and groups to the PAN-OS device using multi-config API calls

Additionally, the module can retrieve address data from other sources:
- GitHub API for Git-over-SSH addresses
- DNS for Active Directory Domain Controllers (when `UPDATE_AD_DC_LIST` is enabled)

## Validation Rules

- Address object names should follow the naming conventions described above
- Address object types must be one of: IP Netmask, IP Wildcard, IP Range, FQDN, or Static Group
- Address values must be valid according to their type
- Group names should start with "AG-" prefix
- Tags should be separated by semicolons

## Notes

- If you modify this file, you need to redeploy the configuration to the firewall for changes to take effect
- Address objects are essential components for security policy rules that need to match specific IP addresses or domains
- Address groups allow you to logically group related addresses for easier management in security policies
- Dynamic address groups are populated based on tags applied to address objects
- The system can automatically update certain address objects (like GitHub addresses and AD Domain Controllers) from external sources