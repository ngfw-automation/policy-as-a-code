Authentication and Access Control Differences
---------------------------------------------

Authentication and access control differ markedly between on-prem Panorama and Strata Cloud Manager:

* **Panorama API Authentication:** Panorama (and PAN-OS devices) use an **API Key** for 
  authentication. The typical workflow is that an admin generates an API key (one per admin user) 
  by sending their credentials to Panorama (``type=keygen`` call) and then uses that API key for 
  all subsequent API calls. The key can be passed as a query parameter:

  .. code-block::

     &key=<APIKEY>

  or in an HTTP header:

  .. code-block::

     X-PAN-KEY: <APIKEY>

  This key is tied to the permissions of the Panorama admin account. Role-based access in Panorama 
  can restrict what that API user can do (for example, you could have an admin account limited to 
  certain device groups or with read-only API rights), but the model is essentially **user accounts 
  with API keys**. There is no expiration for the key unless the admin password is changed or the 
  key is revoked. In summary, Panorama's API auth is **simple key-based auth** scoped to a 
  Panorama admin user.

* **SCM API Authentication:** Strata Cloud Manager uses a more modern **cloud authentication 
  mechanism (OAuth 2.0)**. You do not use Panorama admin accounts or API keys. Instead, **you create 
  a Service Account in SCM's Identity and Access Management** and assign it appropriate roles 
  (permissions) within your tenant. This service account provides a **Client ID and Client Secret**. 

  To authenticate, your automation must obtain a **JWT access token** by performing an OAuth 2.0 
  Client Credentials flow against Palo Alto Networks' auth server. Specifically, you send the 
  client ID/secret and your tenant scope (the TSG ID) to the token URL:

  .. code-block::

     auth.apps.paloaltonetworks.com/oauth2/access_token

  to get a JWT. The resulting token (typically valid for a short duration, e.g. one hour) must be 
  included in API requests as a Bearer token in the ``Authorization`` header:

  .. code-block::

     Authorization: Bearer <token>

  This is a **stateless token-based auth** – meaning no long-lived key tied to user, but short-lived 
  tokens that your script will need to refresh periodically by repeating the OAuth flow.

  Access control in SCM is governed by **roles and access domains**. Each service account (or user) 
  in SCM can be granted roles that limit what APIs they can call or what resources they can manage. 
  For example, roles might restrict whether an account can **read vs. write configuration, or only 
  access certain folders/devices**. In Panorama, role-based control is a bit coarser (often read 
  vs. write at the device-group or template level, if used at all). 

  **SCM's IAM model is more granular and cloud-centric**, allowing separation of duties through 
  roles and even separate *Tenant Service Groups* (for multi-tenant scenarios or MSPs). An SCM 
  access token implicitly carries the scope of what that service account is allowed to do. (For 
  instance, you might have a token that only allows configuration of certain parts of the policy 
  if the service account's role is limited.) The pan.dev developer docs describe how service 
  accounts and roles are set up for SCM.

**Key takeaway:** The migration will require implementing the OAuth 2.0 token retrieval in your 
tooling (instead of the static API key). Also, you will manage **client credentials securely** 
(likely storing client_id and secret, and automating token requests). The user accounts in 
Panorama with API roles will be replaced by **service accounts with role-based access** in SCM – 
ensure the service account has permissions for "Configuration Management" tasks on NGFWs (the 
appropriate role, such as *NGFW Deployment Admin or similar*, which covers pushing policies). 
This also means revocation or rotation of credentials is different: you can revoke a service 
account or rotate secrets if needed, and tokens expire automatically, adding security.

In short, **Panorama = API key per admin**, **SCM = OAuth client credentials yielding temporary tokens**. 
The code must handle token management and include the bearer token on each request. No direct use 
of ``X-PAN-KEY`` or ``key=`` parameter occurs in SCM.