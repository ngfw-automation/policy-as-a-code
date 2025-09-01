Key Differences to Address
--------------------------

-  **API Protocol:** Panorama uses the PAN-OS XML API via the pan-os
   Python SDK (imperative, stateful API calls) while SCM uses a **modern
   REST API** (JSON over HTTP) with a **unified endpoint** for
   cloud-managed config. The code must shift from building XML config
   snippets to sending JSON payloads. Many API endpoints in SCM
   correspond to familiar Panorama config elements (security rules,
   addresses, etc.), but the interactions are stateless HTTP calls
   rather than a persistent session to a device.

-  **Authentication Flow:** Instead of device-local login credentials,
   SCM requires **OAuth2** authentication. The integration must handle
   token management (requesting the token, refreshing it when expired).
   The pan-scm-sdk simplifies this via its ``ScmClient`` (you provide
   client ID/secret and it obtains tokens for you). The code should be
   prepared to manage failures like expired/invalid tokens (e.g. re-auth
   if needed), which was not a concern with Panorama's one-time API key
   approach.

-  **Context and Hierarchy:** The notion of **Device Group & Template**
   in Panorama does not map 1:1 to SCM, but the concept of a **folder**
   in SCM is analogous to a container for policy (e.g. representing a
   group of firewalls or a location). The tool will need to know or
   decide which folder to use for deployment. This might be provided
   explicitly in the target config. For example, if previously
   ``panorama_device_group = "BranchOffices"``, in SCM the equivalent
   might be ``folder = "BranchOffices"`` (assuming those device groups
   were migrated as folders). Also, **"snippet"** might correspond to
   sections of device configuration (like template stacks); if the
   policy is purely security rules, snippet may not be heavily used, but
   for network or device settings it could matter. In any case, the code
   should include the folder (and snippet if required) in API calls –
   many SCM API calls demand a ``folder`` identifier in the query or
   body to know where to put the object.

-  **Policy Deployment Method:** On Panorama, all changes are delivered
   in one large chunk (multi-config XML) and then require a commit. In
   SCM, the deployment could be a series of **POST/PUT calls for each
   object/rule**, or constructing a batch. There may not be an exact
   equivalent to Panorama's single API call containing everything, but
   using multiple calls or a candidate push yields the same result. The
   code should be structured to handle partial failures – e.g., if one
   rule creation fails, how do we handle continuing or rolling back? In
   Panorama, the multi-config call is transactional (all-or-nothing if
   ``strict_transactional=True``). In SCM, each REST call is its own
   transaction unless using a candidate config mechanism. One strategy
   is to apply all changes to a **candidate** and only commit if all
   calls succeeded, otherwise do not commit (or use the SDK's built-in
   transaction support if available).

-  **Feature Gaps or Differences:** The team should verify if all needed
   object types and configurations are supported via the SCM API. Strata
   Cloud Manager is continually improving, but it might not expose 100%
   of the low-level settings that Panorama's XML API does. For example,
   if the tool uses any exotic features (like custom threat signatures,
   or certain legacy objects), ensure those exist in SCM's API. The
   question specifically says "ignore simulation/validation," meaning we
   don't worry about the offline checks, but focus on deployment – which
   SCM definitely supports for security policy. **Logically, the unified
   policy model in SCM should handle security and decryption rules**
   (these are core to cloud-managed NGFW). Just be prepared to adjust
   some details (for instance, the **"target" field** on Panorama rules
   – used to target specific devices – might not be needed in SCM if the
   folder inherently selects devices, or it might be handled via
   **Labels**/**Device tags** in the cloud). The code that currently
   preserves or sets the Panorama rule ``target`` should be revisited;
   SCM's shared policy might not use per-firewall targeting in the same
   way, or it might use a different mechanism (like create separate
   folders/policies for different device groups).