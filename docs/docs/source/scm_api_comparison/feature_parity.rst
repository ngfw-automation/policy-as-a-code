Feature Parity in Policy Management
-----------------------------------

**General Capability:** Strata Cloud Manager is designed to eventually replicate and extend Panorama's management
functions for Next-Generation Firewalls (NGFW) and cloud-managed firewalls. As of July 2025, SCM can perform all core
tasks for security and decryption policy management via API – including creating, updating, deleting, and moving
security policy rules and decryption rules – for firewalls managed by SCM. The SCM API provides endpoints for full
CRUD operations on security rules and decryption rules (list, create, update, delete, move) similar to Panorama's
APIs. This covers tasks like defining security rules (with sources, destinations, applications, actions, etc.),
defining SSL decryption policies, and applying security profiles. In this sense, the fundamental *abilities*
(creating rules, attaching profiles, etc.) are present in SCM's API.

**Remaining Gaps:** However, SCM is a newer platform and not yet at 100% feature parity with Panorama
in all details of policy management. A few nuanced differences exist:

+ *Security Profile Attachment:* Panorama allows attaching individual security profiles (Anti-Virus, Anti-Spyware,
  URL filtering, etc.) directly to a policy rule, or using a Profile Group. In SCM, policies must use Security
  Profile Groups. SCM's design emphasizes profile groups rather than individual profiles, so the automation must
  ensure that any required profiles are part of a group. (In fact, the official migration tool notes that
  SCM supports security profile groups and not individual profiles, advising to adjust policies accordingly.)

* *Scheduled Rules:* Panorama supports applying a schedule to security rules (enabling a rule only at certain times).
  SCM's API currently does not support adding a schedule to a security rule (this appears to be a limitation as of
  recent releases). If the existing Panorama-based code relies on scheduled rules, this capability is not yet exposed
  via SCM APIs and would require manual configuration or a future update to SCM.

+ *Certain Object Types:* There have been minor differences in how some objects are handled. For example, Antivirus
  and WildFire profiles are treated as one unified profile in SCM. The SCM API doesn't provide separate manipulation
  of an "Antivirus" profile vs. a "WildFire" profile as Panorama does – it expects a combined profile (as part of
  a profile group). Automation scripts would need to account for these differences (e.g. ensure an equivalent profile
  group with AV/WildFire exists).

* *Evolving Features:* SCM is continuously improving, and new policy types are being integrated.
  For instance, a new "Internet" security rule type (for cloud-delivered web security) has been 
  introduced alongside traditional L3 security rules. The SCM API includes a ``type`` field to 
  distinguish "internet" vs. "security" rules, but editing cloud web security rules via API is initially
  read-only until the unified rulebase is fully rolled out. This indicates that SCM is in transition to
  unify policy management across platforms, which may temporarily limit some new rule types from full
  API manipulation. Traditional security policy rules (type ``security``) are fully supported.

Overall, for standard security and decryption policy management, SCM's API can achieve everything Panorama's
API can, albeit with some differences in *how* you do it and a few corner-case limitations (like rule schedules)
to be mindful of. It is advisable to review SCM's latest API documentation for any specific features that might
still be catching up to Panorama's capabilities.