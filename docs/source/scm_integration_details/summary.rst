Summary
-------

**Supporting Strata Cloud Manager will require introducing a
new deployment backend alongside the Panorama/XML path**. The policy
**definition** (what rules and objects to create) can remain largely the
same, but the **deployment process** (authentication, API calls, and
context handling) will be quite different. We recommend:

-  Adding SCM as a new option in configuration, with necessary fields
   (TSG, folder, etc.),

-  Utilizing the official SCM SDK for Python to simplify API integration
   and adhere to Palo Alto's data models,

-  Refactoring the code to route Panorama vs. SCM deployments through
   different code paths (while reusing common logic like rule
   generation), and

-  Thoroughly testing the SCM path on a sample tenant.

This approach will allow the tool to support **both Panorama and SCM in
parallel**, enabling a smooth transition. As Palo Alto's documentation
emphasizes, the cloud-managed approach offers "simple and secure
management APIs" without the need to maintain Panorama appliances – by
updating the tool accordingly, the same high-level policy-as-code
workflow can drive either a Panorama **device group** or an
**SCM-managed tenant** with minimal difference to the end user, aside
from how credentials are provided and the commit performed.