Custom Applications
===================

Custom applications allow you to define your own applications for use in security policy rules.

File Location
~~~~~~~~~~~~~

Custom applications are defined in files located in:

.. code-block:: text

   ngfw/objects/applications

This path is defined in the ``settings.py`` module as ``CUSTOM_APPLICATION_SIGNATURES_FOLDER``.

File format
~~~~~~~~~~~

Applications must be defined in idividual XML files.
Create a signature in PAN-OS web-interface, export and save it to the
``ngfw/objects/applications`` folder.

.. code-block:: xml

    <application version="10.2.0">
      <entry name="APP-windows-conn-check">
        <subcategory>general-business</subcategory>
        <category>business-systems</category>
        <technology>client-server</technology>
        <description>This signature covers connectivity checks performed by Windows OS</description>
        <risk>1</risk>
        <signature>
          <entry name="windows-connectivity-check">
            <and-condition>
              <entry name="And Condition 1">
                <or-condition>
                  <entry name="Or Condition 1">
                    <operator>
                      <pattern-match>
                        <qualifier>
                          <entry name="http-method">
                            <value>GET</value>
                          </entry>
                        </qualifier>
                        <pattern>www\.msftconnecttest\.com</pattern>
                        <context>http-req-host-header</context>
                      </pattern-match>
                    </operator>
                  </entry>
                  <entry name="Or Condition 2">
                    <operator>
                      <pattern-match>
                        <qualifier>
                          <entry name="http-method">
                            <value>HEAD</value>
                          </entry>
                        </qualifier>
                        <pattern>www\.msftconnecttest\.com</pattern>
                        <context>http-req-host-header</context>
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
                        <pattern>\/connecttest\.txt</pattern>
                        <context>http-req-uri-path</context>
                      </pattern-match>
                    </operator>
                  </entry>
                </or-condition>
              </entry>
            </and-condition>
            <scope>protocol-data-unit</scope>
            <order-free>yes</order-free>
          </entry>
        </signature>
        <default>
          <port>
            <member>tcp/80</member>
          </port>
        </default>
        <able-to-transfer-file>yes</able-to-transfer-file>
        <file-type-ident>yes</file-type-ident>
        <parent-app>web-browsing</parent-app>
      </entry>
    </application>
