SDK Support and Tooling Compatibility
-------------------------------------

Your existing tooling uses the **PAN-OS SDK for Python (``pan-os-python``)** and possibly some 
direct XML API calls. It's important to evaluate whether these can be reused or need replacement:

* **Pan-os-python Library:** The ``pan-os-python`` SDK is tailored for direct interaction with 
  PAN-OS devices and Panorama. It mimics the device's native object hierarchy and under the hood 
  it communicates with the device's API (XML or REST). **This SDK does not natively support 
  Strata Cloud Manager's new API**. 

  For example, ``pan-os-python`` expects to manage objects on a firewall or Panorama via their 
  IP address/hostname and an API key, none of which applies to SCM's cloud API (which uses a 
  different auth and endpoint). The official docs describe ``pan-os-python`` as targeting 
  "PAN-OS devices" (firewalls and Panorama), which implies **SCM is out of scope for that SDK**. 

  Therefore, attempting to point ``pan-os-python`` to ``api.strata.paloaltonetworks.com`` will 
  not work without significant modification – the endpoints and authentication are entirely 
  different.

* **New SDKs for SCM:** Palo Alto Networks has provided new ways to interact with SCM. The 
  developer community and PAN have released **cloud-specific SDKs** and tools. For instance, 
  there is a **Python SDK for Strata Cloud Manager (sometimes called ``pan-scm-sdk``)**. This 
  SDK is designed to handle the OAuth authentication and wrap the new REST endpoints of SCM into 
  Python classes and methods. 

  Using such an SDK can greatly ease the transition, as it abstracts raw API calls into Python 
  objects (similar to pan-os-python's style). For example, the ``pan-scm-sdk`` provides objects 
  for ``security_rule``, ``address``, ``device``, ``folder``, etc., and methods to list or create 
  them in a given folder. 

  If maintaining Python is preferred, adopting this SDK (or another official one if available) 
  would save time. Palo Alto's developer site (pan.dev) and GitHub have references to this SDK 
  and others (there is also a Go SDK ``scm-go`` and a Terraform provider for SCM).

* **pan-python Library:** If your tooling also uses ``pan-python`` (a low-level Python API wrapper) 
  or direct HTTP calls, those would still need changes. ``pan-python`` could technically be used 
  to make raw REST calls to the new API, but you'd have to manually handle the token auth and 
  craft all the URLs/JSON. It might be simpler to use the specialized SCM SDK or call the REST 
  API directly via Python's ``requests`` library with your own wrapper functions.

* **API Script Changes:** Any direct calls to Panorama's XML API in your code (e.g., using 
  ``requests`` to POST an XML ``<entry>`` or to retrieve an API key) will need to be removed or 
  replaced. Instead of ``type=keygen`` to get an API key, you'll be using a small OAuth routine 
  (for which you can use an HTTP POST to the token URL). 

  Instead of posting to:

  .. code-block::

     https://panorama.yourdomain/api/...

  you'll call:

  .. code-block::

     https://api.strata.paloaltonetworks.com/...

  with appropriate endpoints. The **pan-os-python methods for adding rules/objects** (if you used 
  them) will not directly translate; you'll have to either use the new SDK's methods or invoke 
  the REST endpoints yourself.

* **Testing and Compatibility:** Plan to test the new code thoroughly. The SDK for SCM may have 
  differences in method signatures and return values compared to pan-os-python. Also, error 
  handling might differ (e.g., HTTP error codes vs Panorama's XML ``<response status="error">`` 
  messages). Update any logic that parses API responses accordingly. 

  On the positive side, the SCM API tends to return JSON with clear error messages and standard 
  HTTP codes (400 for bad request, 401 unauthorized, etc.), which can simplify error handling 
  compared to parsing XML.

In summary, **pan-os-python is not plug-and-play with Strata Cloud Manager**. Expect to refactor 
the automation to either use a new SDK (designed for SCM) or directly call the REST API. Palo Alto 
Networks' developer resources (pan.dev) provide documentation and examples for using the new APIs, 
and third-party libraries are emerging to assist with this new platform.