Integration Strategy (Panorama + SCM)
-------------------------------------

To support SCM **alongside** Panorama, a phased approach is advisable:

-  **1. Add SCM as a New Target Option:** Begin by extending the
   configuration and menus to allow an SCM target. This involves
   updating ``policy_targets.json`` with a new entry (including fields
   like ``deployment_type: "scm"``, plus any needed info such as
   ``tsg_id``, ``folder``, etc.), and updating ``load_menu_options()``
   if necessary (likely minimal change since it reads the JSON into the
   menu). Ensure the CLI can accept a selection for SCM and pass it into
   ``deploy_policy()``.

-  **2. Implement Basic Connectivity:** Develop a new code path in
   ``deploy_policy()`` (or a new function) to handle SCM. This should
   initialize the connection (e.g., create the ``ScmClient`` with
   credentials). You might integrate an **OAuth token fetch** here if
   not using the SDK. At this stage, also parse and store any context
   info (folder names, etc.) from the target definition. For now, you
   can skip fine-grained operations – just verify that the script can
   obtain a token and perhaps query something trivial (like list
   existing folders or rules) to confirm connectivity.

-  **3. Map Object and Rule Creation to API Calls:** One by one, modify
   the policy deployment steps to use the SCM API. For example:

   -  Replace calls that **delete existing policy** on Panorama with
      calls to retrieve and delete existing rules via SCM (if the
      strategy is to wipe and replace, similar to Panorama). SCM's API
      allows listing and deleting rules/objects; those should be invoked
      for cleanup of old config (or the tool might rely on SCM's ability
      to have distinct folders per version – but likely we'll do a
      cleanup for consistency).

   -  Update object creation routines: e.g., where ``create_tags()``
      currently constructs ``Tag`` objects and adds them to Panorama,
      instead call ``client.tag.create()`` for each tag (or batch create
      if available). Ensure to include required fields that Panorama may
      infer differently (for instance, Panorama auto-names objects in
      XML – in REST you must provide all fields explicitly).

   -  Update security rule creation: rather than building a
      ``SecurityRule`` object and relying on ``element_str()``, gather
      the rule properties into a dict and call the SCM API. The code
      already has the raw rule data (from the CSV or JSON inputs) which
      can be repurposed. One must translate field names to the SCM API
      format (e.g., PanOS XML uses ``<source>`` and ``<destination>``
      for addresses, whereas the SCM JSON might expect keys like
      ``"sourceAddresses"`` etc. The SDK documentation can guide these
      mappings, or the SDK models can be used directly). Don't forget to
      specify ``folder`` and ``position`` for each rule creation call as
      required by SCM. Using the SDK's **model classes** could help
      ensure the JSON is correct – e.g., fill a ``SecurityRuleModel``
      and then call ``client.security_rule.create(model_instance)``.

-  **4. Handle Commit/Push:** After creating all objects and rules on
   SCM (which likely go into a *candidate* configuration state for that
   tenant), invoke the commit. With the SDK, this might be something
   like ``client.commit_all()`` or creating a **Job** to push config
   (the SDK's "Candidate Push Models" and "Jobs Models" suggest that
   you'd do something akin to ``client.candidate_push.push()``, then
   maybe ``client.jobs.status(job_id)`` to poll). The integration should
   wait for the commit job to succeed and inform the user. This is
   analogous to Panorama where the user would manually commit; in SCM we
   can automate it. If the design is to not auto-commit (for safety),
   the tool could alternatively output a notice that "Changes have been
   staged to the cloud tenant, please commit via Strata Cloud Manager
   UI" – but since the question focuses on deployment, it's likely
   intended to push live.

-  **5. Testing and Gradual Refactor:** It's wise to test the SCM path
   with a smaller scope first (e.g., deploy just a couple of rules or
   objects to a test folder) and ensure the API interactions work. Once
   stable, you can refactor common code. For example, the **policy
   generation logic** (parsing files, etc.) can remain unified, but you
   might refactor the parts that apply the config. Perhaps introduce a
   flag or class that encapsulates differences: e.g., a
   ``DeploymentBackend`` with methods like ``delete_rule(name)``,
   ``create_address(name, value)``, ``create_rule(rule_dict)`` –
   implement this for Panorama (calls pan-os SDK) and for SCM (calls
   REST). Then ``build_policy()`` would simply loop through rules
   calling ``backend.create_rule()`` without worrying if it's XML or
   REST underneath. This abstraction will make the code cleaner and
   easier to maintain both deployment modes in parallel.