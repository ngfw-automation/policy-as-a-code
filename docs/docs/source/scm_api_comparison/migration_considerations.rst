Migration Considerations and Code Changes
-----------------------------------------

Migrating from Panorama to Strata Cloud Manager will require changes across authentication, API 
calls, and data handling in your tooling. Here is a summary of key changes and considerations to 
ensure code portability:

* **Authentication Workflow:** Remove any Panorama API key generation usage. Implement an 
  **OAuth 2.0 client credentials flow** to obtain a token for SCM. This means your code needs to 
  securely handle the **client_id**, **client_secret**, and **TSG (tenant) ID**. 

  For example, you might have a config file or environment variables for these, and your code will 
  request a token at startup (and refresh it periodically). The token (JWT) should then be included 
  in all API requests (e.g., set an HTTP header:

  .. code-block::

     Authorization: Bearer <token>

  on your REST calls). 

  *Access control:* ensure the service account used has the necessary roles to create policies and 
  push configs. If multiple environments (TSGs) exist, you might need to handle multiple credentials.

* **Endpoint and URL Changes:** Update base URLs from your Panorama's hostname to the 
  **SCM API endpoint** (``https://api.strata.paloaltonetworks.com``). All API paths must be 
  changed to the new format. For example: a Panorama XML API call like:

  .. code-block::

     https://panorama/api/?type=config&action=set&xpath=/config/devices/entry/device-group/DMZ/pre-rulebase/security/rules&element=<entry name="Rule1">...</entry>

  would become a REST call to:

  .. code-block::

     https://api.strata.paloaltonetworks.com/config/security/v1/security-rules

  with a JSON body defining the rule (including which folder it belongs to). The structure of 
  endpoints is completely different (no ``type=set`` or XPath). You will likely use **HTTP methods** 
  (POST for create, PUT for update, GET for retrieve, DELETE for delete) on the appropriate URLs 
  rather than Panorama's single ``/api/`` endpoint with query params. Refer to the SCM API 
  documentation for the exact endpoints for each feature (security rules, decryption rules, 
  objects, etc.).

* **Specifying Scope (Device Group vs Folder):** Audit all places where your code references a **device group or template name**. In SCM, these need to be translated to **folder and snippet constructs**. For example:

  * When creating or moving a security rule, instead of providing a device group, you will include ``"folder": "<FolderName>"`` in the JSON payload. Ensure your code knows the correct folder names/IDs corresponding to what was previously a device group. You might need to create those folders in SCM (via API or UI) before placing rules into them. The hierarchy can be up to four levels deep under "All Firewalls", so plan a folder structure analogous to your Panorama device group hierarchy for consistency.

  * Template configurations (like interface settings, zone definitions, etc.) in Panorama were often handled via *templates/template stacks*. In SCM, those are handled via **snippets** and **variables**. If your automation touched template settings (for example, if it created a Decryption Profile object or a certificate in a template), you will need to use the **"Setup" APIs** in SCM to create those as snippets or device-specific settings. Snippets can be created and then associated to folders/devices as needed. This is likely outside pure "policy rules" creation, but important if your code was doing things like uploading certificates or defining interfaces for decryption mirroring, etc.

* **Policy Rule Structure Changes:** Adapt how rules and profiles are defined in the payload. Some specific changes:

  * **Security rule schema:** The JSON fields for a rule in SCM may not exactly match the XML elements from Panorama. Check the API reference for required fields. Common fields (source, dest, service, application, action, etc.) remain, but the representation of security profiles is different (you likely must reference a Profile Group by name or ID, since individual profiles aren't applied directly). Also, if you used tags or comments on rules, those exist in SCM as well (tags should be created via objects API and then referenced).

  * **Decryption rule schema:** Similarly, ensure your decryption rule logic (which likely sets match criteria and an action like "decrypt" or "no-decrypt") is aligned with SCM's API. The concept remains the same and SCM has endpoints for decryption rules, but verify field naming (e.g. Panorama XML might call it ``<from>`` for source zones, SCM JSON may use ``"from": [...]`` etc., which is intuitive).

  * **Object management:** If your code creates addresses, services, etc., use the ``/config/objects/v1/...`` endpoints. One crucial change: in Panorama API, if you didn't specify a device-group in the call, it might default to Panorama's Shared location. In SCM, every object must live in a folder (or Global). Decide whether some objects should reside in the Global folder (making them effectively shared everywhere) or within specific local folders. You will include ``"folder": "<name>"`` when creating objects. For truly global objects, the folder might be "Global" or "All Firewalls" depending on context – consult SCM docs on whether Global is allowed for that object type.

* **Handling Inheritance:** Panorama's pre/post rulebases and shared objects were ways to handle inheritance. SCM uses folder hierarchy for inheritance (with overrides). Your code logic might not need to explicitly handle inheritance (SCM does it automatically: a rule placed in a higher-level folder applies to all sub-folders unless overridden). But if your Panorama automation was, say, creating certain rules in shared and certain in device-group, you'll mimic that by choosing the correct folder level in SCM (e.g., a rule that was in Panorama's "Shared" could be placed in SCM's "Global" folder for equivalent effect). Keep these design differences in mind to maintain equivalent policy behavior.

* **Commit/Push Process:** Replace any code that calls Panorama's commit APIs with calls to 
  SCM's push. If the current tool waited for commit jobs to finish (by polling job IDs from 
  Panorama), implement similar polling for SCM push jobs. The SCM **"Jobs" API** can list 
  operations and their status. For example, after triggering a push, you could call something like:

  .. code-block::

     GET /config/operations/v1/jobs?filter=push

  (exact syntax TBD by docs) to get the job status, or the API may return a job ID on push 
  initiation which you then GET on:

  .. code-block::

     GET /jobs/{id}

  Make sure to handle success/failure responses (SCM will report detailed errors if a push fails, 
  similar to Panorama's commit-all output). Also note that SCM can queue pushes; if one is in 
  progress, another can be submitted and will execute after – your code might need to handle this 
  scenario (perhaps by checking for no active job before pushing, or just being aware of the 
  potential concurrency).

* **SDK Migration or Direct Calls:** Decide if you will refactor to use a new SDK (like ``pan-scm-sdk``). If yes, update the library usage and adjust object names and methods. If not and you proceed with direct calls, ensure you build a small abstraction in your code for common tasks (e.g., a function to create a rule given parameters, which calls the appropriate URL and handles the folder, etc.). This will make maintenance easier as the new API evolves. Palo Alto may update the SCM API versions (v2, etc.), so having a clear abstraction layer means you can update endpoints in one place.

* **Testing and Validation:** Because this is a significant change, test your migrated code in a non-production tenant first. Verify that rules created via API appear correctly in the SCM web interface and on firewalls, and that a push is required (and works) to activate them. Pay attention to differences like *ordering of rules* – Panorama's API had you specify rule order with ``<insert>`` or ``<position>`` parameters. SCM's API uses a dedicated "move rule" endpoint to re-order rules. If your tool was positioning rules, you will need to call the **"Move a security rule"** API to place it above or below another rule (unless you built the rules in correct order initially). Incorporate those calls as needed, since rule ordering is critical in firewall policy.

* **Logging and Feedback:** Update any logging or error-handling in your code. For example, Panorama XML API errors come in an XML structure with a ``<msg>``. SCM errors will come as HTTP errors with a JSON message or code. It might be useful to log the response body on failures to troubleshoot during development. Also, ensure you handle token expiration (the API will return 401 Unauthorized if the token is expired – your code should then fetch a new token and retry).

* **Migration of Existing Config:** This is slightly outside pure API coding, but note that **migrating existing Panorama config to SCM** is non-trivial. Palo Alto provides migration tools (as seen in the ``panos-to-scm`` script) to help export a Panorama configuration and import into SCM. If the user's question is more about code migration than data migration, you might not need to carry over existing rules via API (maybe the environment is new). But if you do need to import existing Panorama rules to SCM, you could either use the migration tool or have your code pull from Panorama (via XML API) and then push into SCM via the new API. Given the complexity, using Palo Alto's provided migration script or professional services might be wiser for a one-time bulk migration, then use your adapted automation for ongoing config management in SCM.

In summary, **plan for significant adjustments to your codebase** when moving to Strata Cloud Manager. The key domains of change are authentication (API key vs OAuth), API endpoint structure (device-group XPath vs folder-based REST), and commit handling. Many of the logical constructs (security rule fields, objects, etc.) remain conceptually the same, but you will interact with them differently. By leveraging Palo Alto's documentation and possibly their new SDKs, you can update your tooling to manage policies on SCM with minimal disruption, while taking advantage of SCM's unified management capabilities.