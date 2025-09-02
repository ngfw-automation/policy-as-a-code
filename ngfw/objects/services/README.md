# Service Objects Configuration

This document explains the format of the `service_objects.csv` file and how to populate it with service object definitions for Palo Alto Networks firewalls.

## File Format

The `service_objects.csv` file defines service objects that will be created on the Palo Alto Networks firewall. Each row in the CSV file represents a single service object or a service object that belongs to a service group.

### CSV Columns

| Column Name | Description | Required | Example |
|-------------|-------------|----------|---------|
| Name | Name of the service object. If left empty, the name will be auto-generated as `SVC-{protocol}-{port}` | No | `web-http` |
| Protocol | Protocol used by the service (tcp or udp) | Yes | `tcp` |
| Destination Port | Port number or port range | Yes | `80`, `3478-3481` |
| Description | Optional description for the service object | No | `HTTP web traffic` |
| Tags | Comma-separated list of tags to apply to the service object | No | `web,standard` |
| Session Timeout Override | Flag to indicate if session timeout should be overridden | No | |
| Override Timeout | Custom timeout value if override is enabled | No | |
| Service Group Name | Comma-separated list of service groups this service belongs to | No | `web-services` |

## How to Use

### Basic Service Object

To define a basic service object, you need to specify at least the Protocol and Destination Port:

```
,tcp,80,HTTP web traffic,,,,
```

This will create a service object named `SVC-tcp-80` for TCP port 80 with the description "HTTP web traffic".

### Named Service Object

To create a service object with a custom name:

```
web-http,tcp,80,HTTP web traffic,,,,
```

This will create a service object named `web-http` for TCP port 80.

### Service Object with Tags

To add tags to a service object:

```
web-http,tcp,80,HTTP web traffic,web,,,
```

This will create a service object named `web-http` with the tag "web".

### Service Object in a Group

To add a service object to a service group:

```
web-http,tcp,80,HTTP web traffic,web,,,web-services
```

This will create a service object named `web-http` and add it to the service group `web-services`.

### Multiple Service Groups

To add a service object to multiple service groups, use a comma-separated list:

```
web-http,tcp,80,HTTP web traffic,web,,,"web-services,internet-services"
```

This will add the service object to both `web-services` and `internet-services` groups.

### Port Ranges

For services that use a range of ports:

```
,udp,3478-3481,STUN port ranges for Skype/Teams,,,,
```

This will create a service object named `SVC-udp-3478-3481` for UDP ports 3478 through 3481.

## Examples

Here are some examples of service object definitions:

```
,udp,3478-3481,STUN port ranges for Skype/Teams,,,,
,tcp,445,SMB file sharing,,,,
dns-udp,udp,53,DNS over UDP,,,,
dns-tcp,tcp,53,DNS over TCP,,,,
,tcp,80,HTTP web traffic,,,,
,tcp,443,HTTPS web traffic,,,,
quic-udp,udp,443,QUIC protocol,,,,
ntp-udp,udp,123,Network Time Protocol,,,,
ssh,tcp,22,Secure Shell,,,,
```

## Implementation Details

The service objects defined in this CSV file are processed by the `create_service_objects` function in the `service_objects.py` module. This function:

1. Parses the CSV file using the `parse_metadata_from_csv` function
2. Creates service objects for each row in the CSV file
3. Auto-generates names for service objects if not provided
4. Creates service groups based on the Service Group Name column
5. Deploys the service objects and groups to the PAN-OS device using multi-config API calls

## Validation Rules

- Only TCP and UDP protocols are supported
- Port values must be valid port numbers (0-65535) or valid port ranges (e.g., 3478-3481)
- Service object names are auto-generated if not provided, following the format `SVC-{protocol}-{port}`
- Service group names must be provided if you want to add a service object to a group

## Notes

- If you modify this file, you need to redeploy the configuration to the firewall for changes to take effect
- Service objects are essential components for security policy rules that need to match specific protocols and ports
- Service groups allow you to logically group related services for easier management in security policies