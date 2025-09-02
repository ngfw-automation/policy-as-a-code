API Structure and Endpoint Differences
--------------------------------------

**Panorama XML & REST APIs:** Panorama offers a traditional XML API (and more recently a REST API in PAN-OS 10.x+) on
the Panorama appliance itself. The **Panorama XML API** uses a request format with a ``type`` parameter and XPath-like
paths to specify config locations. For example, creating a policy via XML API involves sending an XML ``<entry>``
at the proper XPath (including the device group context) and using the admin's API key for authentication. Panorama's
REST API (in 10.2/11.1) similarly requires specifying the scope (e.g. ``location=device-group&device-group=<name>``)
as query parameters or path segments, and still ultimately interacts with Panorama's own IP/hostname.

**SCM's Unified REST API:** Strata Cloud Manager uses an entirely new, unified REST API framework for all
configuration management. Instead of per-Panorama endpoints, you interact with a cloud-hosted endpoint
(``api.strata.paloaltonetworks.com``) that serves all tenants. The API is organized by functional domains
rather than by device: for example, there are base paths like ``/config/security/v1/...`` for security policies,
``/config/objects/v1/...`` for objects, ``/config/network/v1/...`` for network settings, etc., rather than Panorama's
mix of endpoints or XPaths per device group. This functional segmentation is a shift from Panorama's structure that
was tied to device-group hierarchies. The restructured API paths mean that policy and object management in SCM
is not tied to a Panorama XML hierarchy, but presented as REST resources (e.g., ``/config/security/v1/security-rules``
for rules, ``/config/objects/v1/address-objects`` for addresses, etc.).

A significant change is how you specify the target scope for a configuration change. In Panorama's XML API or REST
API, one would include the device group or template in the request (via XPaths or query params like
``device-group=<DGName>``). In SCM, scope is indicated by attributes in the JSON payload (or sometimes by a path
parameter). Specifically, many POST/PUT calls require a ``"folder"`` field (or ``"snippet"`` or ``"device"``,
depending on the config type) in the JSON body to specify where the object or rule resides. For example, to create a
new tag object in a folder called "Datacenter Firewalls", you would call ``POST /config/objects/v1/tags`` with a
JSON body containing the tag details and ``"folder": "Datacenter Firewalls"``. This contrasts with Panorama's approach
of embedding location in the API endpoint or parameters. SCM has eliminated the use of location query parameters for
creating/updating/deleting objects, standardizing on including ``folder``/``snippet`` identifiers in the request body.
(Filtering in GETs still uses query params for convenience, but not for defining config scope in write operations.)

Other structural differences include:

* **Resource Identifiers:** SCM uses globally unique identifiers (UUIDs) for objects and rules. When updating or
  deleting a specific object/rule, the API call is typically ``PUT /.../resource/<UUID>`` or
  ``DELETE /.../resource/<UUID>``. Panorama's XML API used XPath with names, and Panorama's REST often used names
  or sequential IDs within a given device group. With SCM, you may need to first lookup an object by name (or list all)
  to get its UUID if not stored, then act on it. The pan.dev documentation highlights path parameters using UUIDs for
  modify/delete operations.

+ **Versioning and Multi-Tenancy:** The SCM API is versioned (v1, v2, etc.) and explicitly built for multi-tenant
  cloud management. Your API calls include your tenant context via the authentication token (see next section).
  In Panorama, you were interacting with a single Panorama instance's API endpoint directly (no tenant concept,
  since it was single-tenant). In SCM, the **Tenant Service Group (TSG)** concept is effectively your tenant scope
  for all API calls (the cloud will route your calls to the correct config backend for your tenant). The base URL
  ``api.strata.paloaltonetworks.com`` is common, and authorization ensures isolation by tenant.

* **Data Formats:** Both Panorama's REST API and SCM's API use JSON for request/response bodies (Panorama's XML API
  of course used XML). If the existing tooling was using the XML API, moving to SCM will involve switching to JSON
  payloads and understanding the new schemas. Even if using Panorama's REST, note that **some schemas differ**.
  For example, Panorama REST might call for a structure like
  ``{ "security-rule": { "name": ..., "profile-setting": { ... } } }``, whereas SCM might have slightly different
  field names or organization as it evolves its model (consult pan.dev for exact schemas). Generally, SCM's API
  schemas closely resemble PAN-OS concepts but may abstract certain things (e.g. global vs local rules are handled
  by folder inheritance rather than separate "pre-rule/post-rule" lists).

**Summary:** The API structure in SCM is more **RESTful and high-level**, requiring the caller to specify context
(folder/snippet) in JSON and operating on a cloud endpoint. By contrast, Panorama's API is either XML-based with
raw config XPaths or a device-specific REST endpoint with parameters for context. When migrating code, expect to
adjust API endpoints (to the new base and paths) and payload structure (no direct XPaths; use JSON with proper
fields for scope and config).