<!-- include start from vpp_host_resources.xml.i -->
<node name="host-resources">
    <properties>
        <help>Host resources control</help>
    </properties>
    <children>
        <leafNode name="nr-hugepages">
            <properties>
                <help>Number of pre-allocated huge pages of the default size</help>
                <valueHelp>
                    <format>u32:0-4294967295</format>
                    <description>Pages count</description>
                </valueHelp>
                <constraint>
                    <validator name="numeric" argument="--range 0-4294967295"/>
                </constraint>
            </properties>
            <defaultValue>2048</defaultValue>
        </leafNode>
        <leafNode name="max-map-count">
            <properties>
                <help>Maximum number of memory map areas a process may have</help>
                <valueHelp>
                    <format>u32:0-65535</format>
                    <description>Areas count</description>
                </valueHelp>
                <constraint>
                    <validator name="numeric" argument="--range 0-65535"/>
                </constraint>
            </properties>
            <defaultValue>4096</defaultValue>
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
