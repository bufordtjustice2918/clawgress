<!-- include start from vpp_host_resources.xml.i -->
<node name="host-resources">
    <properties>
        <help>Host resources control</help>
    </properties>
    <children>
        <leafNode name="max-map-count">
            <properties>
                <help>Maximum number of memory map areas a process may have</help>
                <valueHelp>
                    <format>u32:65535-2147483647</format>
                    <description>Areas count</description>
                </valueHelp>
                <constraint>
                    <validator name="numeric" argument="--range 65535-2147483647"/>
                </constraint>
            </properties>
            <defaultValue>65535</defaultValue>
        </leafNode>
        <leafNode name="shmmax">
            <properties>
                <help>Maximum shared memory segment size that can be created</help>
                <valueHelp>
                    <format>u32:0-18446744073709551612</format>
                    <description>Size in bytes</description>
                </valueHelp>
                <constraint>
                    <validator name="numeric" argument="--range 0-18446744073709551612"/>
                </constraint>
            </properties>
            <defaultValue>2147483648</defaultValue>
        </leafNode>
    </children>
</node>
<!-- include end -->
