Changes Needed to Support SCM
-----------------------------

Strata Cloud Manager introduces a different interface for managing policies, so several parts of the above
workflow will need adaptation or extension:

-  **Target Definition and CLI:** A new **deployment type**
   (e.g. ``"scm"``) should be introduced for SCM targets in the
   ``policy_targets.json``. Instead of Panorama IP, device group, and
   template, an SCM target entry would likely include information like
   the cloud **tenant/TSG identifier** and perhaps a target **folder**
   or context. The CLI in ``main.py`` would need to recognize an SCM
   target and gather appropriate credentials. Unlike Panorama's admin
   username/password, SCM uses an **OAuth2 authentication flow** –
   e.g. client ID and client secret for a service account, which yield
   an access token. The tool may prompt for these or (more securely)
   read them from environment variables or a config file (since client
   secret is not something to type every run). Once credentials are
   obtained, the code would not instantiate a ``Panorama`` object, but
   rather initialize an **SCM API client**. For example, Palo Alto
   provides a Python SDK (``pan-scm-sdk``) where you create an
   ``ScmClient`` or ``Scm`` instance with the client ID/secret and TSG
   (tenant service group) ID. The menu and ``deploy_policy()`` logic
   should be extended to handle this path
   (e.g. ``if deployment_type == "scm": ...``).

-  **Authentication & Session Management:** The current code uses the
   PAN-OS XML API (via pan-os-python), logging in with username/password
   to the Panorama device (which the SDK internally exchanges for an API
   key). In SCM, authentication is entirely different: the code must
   obtain a **Bearer token** via OAuth2. This likely means adding a step
   to request an OAuth token from the **SCM Authentication Service**
   using client credentials, or leveraging the SCM SDK which handles
   token retrieval internally. The token then needs to be used in all
   subsequent API calls to SCM. This is a significant change – the code
   can no longer use ``panos_device = Panorama(host, user, pass)``;
   instead, it might do something like
   ``scm_client = Scm(client_id, client_secret, tsg_id)`` (using the
   SDK) or manually call the OAuth endpoint and store the token. The
   **credential flow** thus shifts from interactive user login to
   non-interactive service auth. (If interactive login to the cloud UI
   were required, that would be complex – but typically we'd use a
   service account for automation in SCM.)

-  **API Interface:** The tool's core operations must be reworked to use
   **SCM's REST APIs** in place of the Panorama XML API. Panorama's
   ``Panorama`` object and associated classes won't directly work
   against SCM, because SCM is not just "Panorama in the cloud" – it's a
   new SaaS with a **unified API framework**. Concretely, instead of
   constructing XML and calling ``xapi.multi_config``, the code should
   invoke REST endpoints (likely HTTPS calls to
   ``api.strata.paloaltonetworks.com``). For example, to create security
   rules on SCM, one would call the **"security rules"** endpoint
   (e.g. ``POST /config/security/v1/security-rules``) with a JSON
   payload. If using the **SCM Python SDK**, many of these are available
   as high-level methods. For instance, you could call
   ``client.security_rule.create({...})`` or use model objects provided
   by the SDK (e.g. ``SecurityRuleModel``) and then call an ``update()``
   or ``push()`` method. Each rule or object type (addresses, tags,
   profiles, etc.) has a corresponding REST API in SCM, so the code
   needs to translate the configuration data into the appropriate JSON
   format and send it via the token-authenticated HTTPS calls.

-  **Policy Scope (Device Group vs. Folder/Snippet):** In Panorama, the
   script targets a specific device-group and template (passed in as
   ``policy_container`` and ``policy_template``) to know where to place
   the config. In Strata Cloud Manager, the analogous concept is the
   **Tenant and Folder** hierarchy. The SCM config is organized by
   *Folders* (and possibly *Snippets* for templates/config context). The
   code will need to specify the target folder (akin to a device group)
   when creating objects or rules. For example, using the SCM SDK,
   operations often require a ``folder="XYZ"`` parameter to indicate
   where the object lives. The *folder* might represent a group of
   firewalls or a section of the config (e.g. "Texas" or "Datacenter" in
   the SDK examples). The tool must be adjusted to either take a folder
   name in the target config or derive it (perhaps the Panorama device
   group name corresponds to a folder in SCM after migration).
   Additionally, rules in SCM likely require specifying whether they are
   **pre-rule or post-rule** (global vs. local precedence) via a field
   or URL parameter (Panorama had separate Pre vs Post rulebases) – the
   SCM API uses a query parameter or field ``position: "pre" | "post"``
   for rule creation. The code that currently splits rules into pre/post
   lists can be reused, but when calling the SCM API we must include the
   correct position indicator instead of adding to separate containers.
   There may not be a concept of a "Template" in the same way; network
   settings might be handled via *Snippets*, but for pure policy
   (security and decryption rules) the main concern is the folder
   (device group equivalent) and rule order.

-  **Building and Pushing Config:** The existing architecture constructs
   all rules and objects in-memory using pan-os SDK objects, then pushes
   them in one giant transaction (multi-config XML). With SCM, there are
   two possible approaches:

   1. **Incremental API Calls:** After connecting to SCM, the script
      could individually create/delete objects and rules using a
      sequence of REST calls. For example: call ``DELETE /addresses``
      for each stale address, then ``POST /addresses`` to create each
      new address, etc., and similarly for rules. This would mirror what
      the current code does but via REST. The SCM SDK can simplify this
      by allowing Pythonic creation of objects
      (e.g. ``client.address.create({...})`` returns an Address object)
      rather than manual HTTP requests. One challenge is performance –
      dozens or hundreds of sequential API calls might be slow. However,
      the SCM API is designed for automation, so this is a viable
      approach (perhaps using bulk endpoints if available).

   2. **Candidate Config and Commit:** SCM also supports the concept of
      a **candidate configuration push** and commit jobs. We could
      prepare a batch of changes and then invoke a commit operation. For
      instance, the SDK provides a ``candidate_push`` or similar
      mechanism (as hinted by "Candidate Push Models" in the docs). A
      potential strategy is to use the SDK to stage all changes to the
      candidate config (similar to how we build a multi-config XML) and
      then execute a single "push" job to apply them. This would achieve
      a transaction-like update, akin to Panorama's multi-config. The
      existing code's logic of generating the entire policy first (rules
      list, objects list) could be repurposed to stage multiple SDK
      calls and then one commit at end.

   Regardless of approach, the **commit and locking model** differs: On
   Panorama, we explicitly took locks on the device group/template,
   pushed config, and then required a manual Commit in the Panorama UI.
   In SCM, when using the API, one would typically call a **commit job**
   via API to activate the changes (or the SDK's equivalent). There is
   no concept of per-device "config lock" that the script manages – the
   cloud service likely handles concurrency globally with its own
   transaction system. So the sections of code dealing with
   ``panos_device.op("...")`` for setting
   targets and locks can be dropped or replaced. Instead, after pushing
   config via the SCM API, the script might call an endpoint to
   **commit** the changes (or the SDK might auto-commit, depending on
   design). This commit would publish the policy to the cloud-managed
   firewalls. The tool could poll a **Job** API to wait for commit
   completion, analogous to how one might wait for a Panorama commit
   job.

-  **Reusing vs. Refactoring Architecture:** A lot of the existing
   policy generation logic can be **reused** – the code that reads
   requirement CSVs and JSON, computes which rules and objects to
   create, etc., remains valid. The main refactor is needed at the
   **point of deployment** (i.e., the interface between the computed
   policy and the API calls). To minimize disruption, one approach is to
   **abstract the deployment backend**: for example, define a generic
   interface or set of functions for "create address object", "create
   tag", "create security rule", etc., with one implementation for
   Panorama (current) and one for SCM. Initially, it could be done with
   simple ``if deployment_type == "scm"`` conditionals around the
   existing code paths. For instance, in ``build_policy()``, instead of
   calling Panorama-specific routines directly, have it call a wrapper
   that checks the target type and either (a) uses pan-os SDK + XAPI
   (current flow) or (b) calls the new SCM methods. Over time, it would
   be cleaner to encapsulate these into separate classes (e.g. a
   ``PanoramaDeployer`` vs an ``ScmDeployer``) so that the main flow
   chooses the appropriate deployment handler. This abstraction will
   prevent cluttering the code with many ``if scm vs panorama``
   branches. It also allows extending to other deployment targets in the
   future if needed (cloud NGFW services, etc.).

-  **SDKs and Libraries:** As noted, the **Panorama XML API** is handled
   by the ``pan-os-python`` SDK today. For SCM, Palo Alto has introduced
   new SDKs/tools (the ``pan-scm-sdk`` for Python is one option)
   designed to interact with the Strata Cloud Manager API. Adopting this
   SDK would expedite development: it provides Python classes for things
   like addresses, rules, profiles, with data validation, and handles
   the low-level REST calls internally. This avoids manually crafting
   HTTP requests and parsing responses. The team would need to include
   this SDK in the project's requirements (e.g.,
   ``pip install pan-scm-sdk``) and adjust the code to use its
   ``ScmClient``. If not using the SDK, the alternative is to use
   Python's ``requests`` to call the REST API endpoints directly, manage
   tokens, construct JSON payloads, etc. That is doable but would result
   in more custom code. Given the complexity of full policy push (lots
   of object types), leveraging the official SDK is recommended. It also
   will handle **exceptions and error messages** in a structured way
   (similar to how ``PanDeviceXapiError`` is used now).