Decryption Profiles
===================

Decryption profiles define settings for SSL decryption, such as which SSL/TLS versions and cipher suites to support.

File Location
~~~~~~~~~~~~~

Decryption profiles are defined in JSON or YAML files located in:

.. code-block:: text

   ngfw/objects/decryption/decryption profile/

This path is defined in the Settings module as ``DECRYPTION_PROFILES_FOLDER``.

File Format
~~~~~~~~~~~

Decryption profiles can be defined in either JSON or YAML format. Each file represents a single decryption profile with settings for SSL/TLS protocols, cipher suites, and proxy behavior.

JSON Example
~~~~~~~~~~~~

.. code-block:: json

    {
        "entry": {
            "@name": "DP-default",
            "ssl-forward-proxy": {
                "block-expired-certificate": "yes",
                "block-untrusted-issuer": "yes",
                "block-unknown-cert": "no",
                "block-timeout-cert": "no",
                "restrict-cert-exts": "no",
                "auto-include-altname": "no",
                "block-unsupported-version": "no",
                "block-unsupported-cipher": "no",
                "block-client-cert": "no",
                "block-if-no-resource": "no",
                "block-tls13-downgrade-no-resource": "no",
                "strip-alpn": "no"
            },
            "ssl-inbound-proxy": {
                "block-unsupported-version": "no",
                "block-unsupported-cipher": "no",
                "block-if-no-resource": "no",
                "block-tls13-downgrade-no-resource": "no"
            },
            "ssl-protocol-settings": {
                "enc-algo-chacha20-poly1305": "yes",
                "auth-algo-md5": "no",
                "min-version": "tls1-0",
                "max-version": "max",
                "keyxchg-algo-rsa": "yes",
                "keyxchg-algo-dhe": "yes",
                "keyxchg-algo-ecdhe": "yes",
                "enc-algo-3des": "yes",
                "enc-algo-rc4": "yes",
                "enc-algo-aes-128-cbc": "yes",
                "enc-algo-aes-256-cbc": "yes",
                "enc-algo-aes-128-gcm": "yes",
                "enc-algo-aes-256-gcm": "yes",
                "auth-algo-sha1": "yes",
                "auth-algo-sha256": "yes",
                "auth-algo-sha384": "yes"
            },
            "ssl-no-proxy": {
                "block-expired-certificate": "no",
                "block-untrusted-issuer": "no"
            },
            "ssh-proxy": {
                "block-unsupported-version": "no",
                "block-unsupported-alg": "no",
                "block-ssh-errors": "no",
                "block-if-no-resource": "no"
            }
        }
    }

YAML Example
~~~~~~~~~~~~

.. code-block:: yaml

    entry:
      "@name": "DP-default"
      ssl-forward-proxy:
        block-expired-certificate: "yes"
        block-untrusted-issuer: "yes"
        block-unknown-cert: "no"
        block-timeout-cert: "no"
        restrict-cert-exts: "no"
        auto-include-altname: "no"
        block-unsupported-version: "no"
        block-unsupported-cipher: "no"
        block-client-cert: "no"
        block-if-no-resource: "no"
        block-tls13-downgrade-no-resource: "no"
        strip-alpn: "no"
      ssl-inbound-proxy:
        block-unsupported-version: "no"
        block-unsupported-cipher: "no"
        block-if-no-resource: "no"
        block-tls13-downgrade-no-resource: "no"
      ssl-protocol-settings:
        enc-algo-chacha20-poly1305: "yes"
        auth-algo-md5: "no"
        min-version: "tls1-0"
        max-version: "max"
        keyxchg-algo-rsa: "yes"
        keyxchg-algo-dhe: "yes"
        keyxchg-algo-ecdhe: "yes"
        enc-algo-3des: "yes"
        enc-algo-rc4: "yes"
        enc-algo-aes-128-cbc: "yes"
        enc-algo-aes-256-cbc: "yes"
        enc-algo-aes-128-gcm: "yes"
        enc-algo-aes-256-gcm: "yes"
        auth-algo-sha1: "yes"
        auth-algo-sha256: "yes"
        auth-algo-sha384: "yes"
      ssl-no-proxy:
        block-expired-certificate: "no"
        block-untrusted-issuer: "no"
      ssh-proxy:
        block-unsupported-version: "no"
        block-unsupported-alg: "no"
        block-ssh-errors: "no"
        block-if-no-resource: "no"

Configuration Options
~~~~~~~~~~~~~~~~~~~~~

Decryption profiles support the following configuration options:

SSL Forward Proxy Settings
^^^^^^^^^^^^^^^^^^^^^^^^^

Settings for SSL forward proxy (client to server) decryption:

- **block-expired-certificate**: Block connections with expired certificates
- **block-untrusted-issuer**: Block connections with untrusted issuers
- **block-unknown-cert**: Block connections with unknown certificates
- **block-timeout-cert**: Block connections with timed-out certificates
- **restrict-cert-exts**: Restrict certificate extensions
- **auto-include-altname**: Automatically include alternative names
- **block-unsupported-version**: Block unsupported SSL/TLS versions
- **block-unsupported-cipher**: Block unsupported cipher suites
- **block-client-cert**: Block client certificates
- **block-if-no-resource**: Block if no resources are available
- **block-tls13-downgrade-no-resource**: Block TLS 1.3 downgrade if no resources are available
- **strip-alpn**: Strip Application-Layer Protocol Negotiation (ALPN) extension

SSL Inbound Proxy Settings
^^^^^^^^^^^^^^^^^^^^^^^^^^

Settings for SSL inbound proxy (server to client) decryption:

- **block-unsupported-version**: Block unsupported SSL/TLS versions
- **block-unsupported-cipher**: Block unsupported cipher suites
- **block-if-no-resource**: Block if no resources are available
- **block-tls13-downgrade-no-resource**: Block TLS 1.3 downgrade if no resources are available

SSL Protocol Settings
^^^^^^^^^^^^^^^^^^^^^

Settings for SSL/TLS protocol versions and algorithms:

- **min-version**: Minimum SSL/TLS version (ssl-3-0, tls1-0, tls1-1, tls1-2, tls1-3)
- **max-version**: Maximum SSL/TLS version (ssl-3-0, tls1-0, tls1-1, tls1-2, tls1-3, max)
- **enc-algo-***: Encryption algorithms (3des, rc4, aes-128-cbc, aes-256-cbc, aes-128-gcm, aes-256-gcm, chacha20-poly1305)
- **auth-algo-***: Authentication algorithms (md5, sha1, sha256, sha384)
- **keyxchg-algo-***: Key exchange algorithms (rsa, dhe, ecdhe)

SSL No Proxy Settings
^^^^^^^^^^^^^^^^^^^^^

Settings for SSL traffic that is not decrypted:

- **block-expired-certificate**: Block connections with expired certificates
- **block-untrusted-issuer**: Block connections with untrusted issuers

SSH Proxy Settings
^^^^^^^^^^^^^^^^^^^

Settings for SSH proxy:

- **block-unsupported-version**: Block unsupported SSH versions
- **block-unsupported-alg**: Block unsupported algorithms
- **block-ssh-errors**: Block SSH errors
- **block-if-no-resource**: Block if no resources are available

Implementation Details
~~~~~~~~~~~~~~~~~~~~~

Decryption profiles are processed by the ``create_non_sdk_objects`` function in the ``auxiliary_functions.py`` module. This function:

1. Parses the JSON or YAML files for decryption profiles using ``parse_metadata_from_json`` or ``parse_metadata_from_yaml``
2. Constructs XML elements for each profile definition
3. Deploys the decryption profiles to the PAN-OS device using multi-config API calls

The same algorithm is used for all security profile types, providing a consistent approach to profile management across the system.
