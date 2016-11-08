# NOTE and PLEASE READ
# changes to resources need to be reflected in the ../config.yaml AUDIT_AWS_EC2_ALERT_LIST property
#
coreo_aws_advisor_alert "ec2-ip-address-whitelisted" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-ip-address-whitelisted.html"
  display_name "Security Group contains IP address"
  description "Security Group contains IP address"
  category "Security"
  suggested_action "Review Security Group to ensure that the host ip address added is to allowed access."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=~"]
  alert_when [/\/32/]
end

coreo_aws_advisor_alert "ec2-unrestricted-traffic" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-unrestricted-traffic.html"
  display_name "Security group allows unrestricted traffic"
  description "All IP addresses are allowed to access resources in a specific security group."
  category "Security"
  suggested_action "Restrict access to the minimum specific set of IP address or ports necessary."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=="]
  alert_when ["0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-1521-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 1521"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 1521, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-3306-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 3306"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 3306, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-5432-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 5432"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 5432, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-27017-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 27017"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 27017, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-1433-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 1433"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 1433, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-3389-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 3389"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 3389, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-22-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 22"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 22, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-5439-0.0.0.0/0" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 5439"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port", "security_group_info.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  alert_when ["tcp", 5439, "0.0.0.0/0"]
end

coreo_aws_advisor_alert "ec2-TCP-23" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 23"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  alert_when ["tcp", 23]
end

coreo_aws_advisor_alert "ec2-TCP-21" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 21"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  alert_when ["tcp", 21]
end

coreo_aws_advisor_alert "ec2-TCP-20" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-tcpportopen.html"
  display_name "TCP port is open - 20"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Warning"
  objectives ["","security_groups"]
  audit_objects ["security_group_info.ip_permissions.ip_protocol", "security_group_info.ip_permissions.from_port"]
  operators ["==","=="]
  alert_when ["tcp", 20]
end

coreo_aws_advisor_alert "ec2-ports-range" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-ports-range.html"
  display_name "Security group contains a port range"
  description "Security group contains a port range rather than individual ports."
  category "Security"
  suggested_action "Only add rules to your Security group that specify individual ports and don't use port ranges unless they are required."
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info.ip_permissions.from_port"]
  operators ["!="]
  alert_when ["object[:to_port]"]
end

coreo_aws_advisor_ec2 "advise-ec2" do
  action :advise
  alerts ${AUDIT_AWS_EC2_ALERT_LIST}
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_uni_util_notify "advise-ec2" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_EC2_SEND_ON}"
  payload '{"stack name":"PLAN::stack_name",
  "instance name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_ec2.advise-ec2.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
