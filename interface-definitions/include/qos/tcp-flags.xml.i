<!-- include start from qos/tcp-flags.xml.i -->
<leafNode name="tcp">
  <properties>
    <help>TCP Flags matching</help>
    <completionHelp>
      <list>ack syn</list>
    </completionHelp>
    <valueHelp>
      <format>ack</format>
      <description>Match TCP ACK</description>
    </valueHelp>
    <valueHelp>
      <format>syn</format>
      <description>Match TCP SYN</description>
    </valueHelp>
    <constraint>
      <regex>(ack|syn)</regex>
    </constraint>
  </properties>
</leafNode>
<!-- include end -->
