Custom Spyware Signatures
=========================

Custom spyware signatures allow you to define your own spyware signatures.

File Location
~~~~~~~~~~~~~

Custom spyware signatures are defined in files located in:

.. code-block:: text

   ngfw/objects/custom objects/spyware

This path is defined in the ``settings.py`` module as ``CUSTOM_SPYWARE_SIGNATURES_FOLDER``.

File format
~~~~~~~~~~~

Spyware signatures must be defined in idividual XML files.
Create a signature in PAN-OS web-interface, export and save it to the
``ngfw/objects/custom objects/spyware`` folder.

.. code-block:: xml

    <spyware-threat version="10.2.0">
      <entry name="15001">
        <signature>
          <standard>
            <entry name="test-command-and-control">
              <and-condition>
                <entry name="And Condition 1">
                  <or-condition>
                    <entry name="Or Condition 1">
                      <operator>
                        <pattern-match>
                          <pattern>www\.paloaltonetworks\.com</pattern>
                          <context>http-req-host-header</context>
                          <negate>no</negate>
                        </pattern-match>
                      </operator>
                    </entry>
                  </or-condition>
                </entry>
                <entry name="And Condition 2">
                  <or-condition>
                    <entry name="Or Condition 1">
                      <operator>
                        <pattern-match>
                          <pattern>/test-command-and-control</pattern>
                          <context>http-req-uri</context>
                          <negate>no</negate>
                        </pattern-match>
                      </operator>
                    </entry>
                  </or-condition>
                </entry>
              </and-condition>
              <order-free>yes</order-free>
              <scope>protocol-data-unit</scope>
            </entry>
          </standard>
        </signature>
        <default-action>
          <reset-client/>
        </default-action>
        <threatname>test command and control</threatname>
        <severity>high</severity>
        <direction>client2server</direction>
        <comment>test spyware signature for command and control traffic detection</comment>
        <reference>
          <member>https://en.wikipedia.org/wiki/Command_and_control</member>
        </reference>
      </entry>
    </spyware-threat>