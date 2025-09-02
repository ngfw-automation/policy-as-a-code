Deployment Model: Commit vs Push Changes
----------------------------------------

One major operational difference is how configuration changes are **committed/applied to devices** 
in Panorama vs in Strata Cloud Manager:

* **Panorama Commit and Push:** In the Panorama model, configuration changes (via API or GUI) 
  are made to Panorama's candidate configuration. An administrator then **commits** those changes 
  on Panorama (which saves them to Panorama's running config database), and subsequently **pushes** 
  the changes to managed firewalls (device groups and templates) as needed. 

  The Panorama API exposes these steps via "commit" and "commit-all" operations. For example, an 
  API script after adding rules would typically call Panorama's ``commit`` API to commit on 
  Panorama itself, and then call ``commit-all`` with parameters to push to a certain device group 
  or template stack. The commit-all API allows specifying scope such as "push only to Device Group X" 
  or "include/exclude templates", or even push to specific devices within a group. 

  This is a somewhat complex procedure but offers granular control (e.g., commit device group A 
  without affecting others, push template changes separately if needed). In Panorama's XML API, 
  these are done by crafting an XML ``<commit>`` or ``<commit-all>`` command with the appropriate 
  elements (device-group name, etc.). Panorama's commit operations can be synchronous or 
  asynchronous (you receive a job ID and poll). 

  In summary, **Panorama requires an explicit push (commit-all) to deliver policies to firewalls**, 
  and your automation likely already handles this by calling these commit APIs after building the 
  policies.

* **Strata Cloud Manager Push Config:** In SCM, there is no separate Panorama server that holds 
  candidate config – the cloud is effectively the manager. When you use SCM APIs to create or 
  modify policies, you are editing the **central config store** (in your tenant's cloud). These 
  changes are staged in SCM and are not immediately active on firewalls until you perform a 
  **"Push Config"** to devices. 

  The concept is analogous to Panorama's push, but implemented in the cloud context. **You must 
  push the changes from SCM to the firewalls (or Prisma Access) for them to take effect**. The 
  SCM web interface has a "Push Config" button, and correspondingly the API has an operation to 
  trigger a push job (though it's not a simple REST endpoint like ``/push`` – it's handled via 
  the operations/jobs API).

  When pushing in SCM, you can choose the scope of deployment: push to **all devices or a subset 
  of devices/folders**. In the UI, you can select specific folders or even individual firewalls 
  as the push targets. For example, you might push only to the "Branch Offices" folder (and 
  thereby all firewalls in that folder hierarchy) while not affecting datacenter firewalls. 

  Under the hood, pushing to a folder in SCM is analogous to Panorama's commit-all to a device 
  group. **If your code was targeting specific device groups to push**, in SCM you will specify 
  the target folder(s) or devices for the push operation. The first ever push in an SCM tenant 
  must include all changes (all admins' changes) and all devices, but subsequently you have 
  flexibility to push only certain pending changes by specific administrators or to certain 
  subsets of firewalls. (The concept of "Admin Scope" allows filtering changes by who made them, 
  which is a new feature in SCM that Panorama did not have. This likely won't affect most API 
  use cases, since an automation usually runs under one account, but it's worth noting.)

  Technically, the SCM API exposes **"configuration operations"** endpoints to manage these pushes 
  and commits. You can list configuration **versions** (snapshots of candidate config) and **jobs** 
  for pushes. A push in SCM triggers a **job** that can be monitored via the API (to see if it 
  succeeded, similar to checking Panorama job IDs). 

  For example, there are endpoints to list config versions and to load a version or revert to a 
  previous version. The details of triggering a push via API are not as straightforward as 
  Panorama's single commit-all call with parameters; instead, you will likely use a specific API 
  call (or sequence) to initiate a push job. (In Palo Alto's pan.dev and Terraform provider, this 
  might be abstracted. The **Terraform provider for SCM** and other tools indicate that pushing 
  config is supported, likely via a resource that triggers a push operation after config changes.)

**Commit Differences:** Notably, **Panorama had a two-phase commit (commit to Panorama, then push 
to devices)**, whereas **SCM essentially always has a one-phase commit from the user perspective 
(just "push" to devices)** because the cloud is always the source of truth for config. There isn't 
a need to "commit locally" – when you do a push in SCM, it takes whatever is in the cloud config 
(your recent API changes) and applies to devices. 

That said, SCM does maintain version snapshots of configuration (like candidate vs running config 
snapshots). It's good practice to **use the "config version" APIs** to perhaps label or snapshot 
a version before a major change, and you can use the **revert** feature if a push goes wrong. 
This is somewhat analogous to Panorama's ability to revert a commit, but SCM's cloud nature allows 
easily rolling back to the last good config across your tenant.

**In terms of code**: after making policy changes via SCM's API, your script will need to **trigger 
a push job**. While Panorama's ``commit-all`` API call was an atomic action you invoked, in SCM 
you might call a dedicated endpoint (or possibly use the Jobs API). Ensure to consult SCM's API 
docs for the exact call – as of the latest documentation, pushing configuration might be done by 
creating a **job resource** via:

.. code-block::

   POST /config/operations/v1/push

(for example) or something similar (the documentation mentions "Push Config to Devices" in the 
context of UI and likely an underlying API). You would then poll the job status via:

.. code-block::

   GET /config/operations/v1/jobs/{job-id}

to know when it completes, much like checking Panorama commit status.

In summary, **the deployment workflow is conceptually similar** – you still must explicitly 
propagate staged changes to firewalls – but the mechanics differ (cloud-managed, job-based). 
The **code will change** by replacing Panorama's commit/commit-all API calls with **SCM's push 
mechanism**. 

Also, because SCM can manage both Prisma Access and NGFW, make sure to push to the correct target 
(the API might require specifying whether it's Prisma Access vs NGFW, or it may infer based on 
folder). The official SCM docs emphasize that pushing will deliver all pending config changes to 
the chosen devices, and partial pushes are limited in certain scenarios (e.g., after onboarding 
a new device, all changes must be pushed together).

**Note:** There is no "context switching" to a device like you might do by logging into a firewall 
or switching vsys. All operations are done in the context of SCM's config tree (Global > All 
Firewalls > folders > etc.). This simplifies the API usage – you never send API calls *to the 
firewall directly* when using SCM; always to the cloud endpoint. 

Panorama sometimes required talking to the firewall for certain local settings or operational 
commands; with SCM, even things like software upgrades or checking HA status are intended to be 
done via cloud (though some features like plugin installation were noted as missing in early 
versions). For policy pushes, just remember everything is initiated from the cloud side.