<!-- include start from unformat_log2_page_size.xml.i -->
<completionHelp>
  <list>default default-hugepage</list>
</completionHelp>
<valueHelp>
  <format>default</format>
  <description>Default</description>
</valueHelp>
<valueHelp>
  <format>default-hugepage</format>
  <description>Default huge-page</description>
</valueHelp>
<valueHelp>
  <format>&lt;number&gt;K</format>
  <description>Kilobyte</description>
</valueHelp>
<valueHelp>
  <format>&lt;number&gt;M</format>
  <description>Megabyte</description>
</valueHelp>
<valueHelp>
  <format>&lt;number&gt;G</format>
  <description>Gigabyte</description>
</valueHelp>
<constraint>
  <validator name="numeric" argument="--range 0-4294967295"/>
  <regex>(default|default-hugepage|\d+K|\d+M|\d+G)</regex>
</constraint>
<!-- include end -->
