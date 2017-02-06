
coreo_aws_rule "ec2-inventory-instances" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
  include_violations_in_count false
  display_name "EC2 Instance Inventory"
  description "This rule performs an inventory on all EC2 instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

coreo_aws_rule "ec2-inventory-security-groups" do
  action :define
  service :ec2
  # link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
  include_violations_in_count false
  display_name "EC2 Security Group Inventory"
  description "This rule performs an inventory on all EC2 Security Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["security_groups"]
  audit_objects ["object.security_group_info.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-ip-address-whitelisted" do
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
  raise_when [/\/32/]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-unrestricted-traffic" do
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
  raise_when ["0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-1521-0.0.0.0/0" do
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
  raise_when ["tcp", 1521, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-3306-0.0.0.0/0" do
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
  raise_when ["tcp", 3306, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-5432-0.0.0.0/0" do
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
  raise_when ["tcp", 5432, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-27017-0.0.0.0/0" do
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
  raise_when ["tcp", 27017, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-1433-0.0.0.0/0" do
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
  raise_when ["tcp", 1433, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-3389-0.0.0.0/0" do
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
  raise_when ["tcp", 3389, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-22-0.0.0.0/0" do
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
  raise_when ["tcp", 22, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-5439-0.0.0.0/0" do
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
  raise_when ["tcp", 5439, "0.0.0.0/0"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-23" do
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
  raise_when ["tcp", 23]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-21" do
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
  raise_when ["tcp", 21]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-TCP-20" do
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
  raise_when ["tcp", 20]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-ports-range" do
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
  raise_when ["object[:to_port]"]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-not-used-security-groups" do
  action :define
  service :ec2
  display_name "EC2 security group is not used"
  description "Security group is not used anywhere"
  category "Audit"
  suggested_action "Remove this security group"
  level "Warning"
  objectives ["security_groups"]
  audit_objects ["security_group_info"]
  operators ["=="]
  raise_when [false]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["security_groups"]
  audit_objects ["security_group_info.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_group_info.group_id"
end

coreo_aws_rule "ec2-instances-active-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["instances"]
  audit_objects ["reservation_set.instances_set.group_set.group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservation_set.instances_set.instance_id"
end

coreo_aws_rule "elb-load-balancers-active-security-groups-list" do
  action :define
  service :elb
  include_violations_in_count false
  link "http://kb.cloudcoreo.com/mydoc_unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.security_groups"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule_runner_ec2 "advise-ec2" do
  action :run
  rules ${AUDIT_AWS_EC2_ALERT_LIST}
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_aws_rule_runner_ec2 "advise-unused-security-groups-ec2" do
  action :run
  rules ["ec2-security-groups-list", "ec2-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
end

coreo_aws_rule_runner_elb "advise-elb-ec2" do
  action :run
  rules ['elb-load-balancers-active-security-groups-list']
  regions ${AUDIT_AWS_EC2_REGIONS}
end

=begin
  START EC2 methods
  JSON send method
  HTML send method
=end
coreo_uni_util_notify "advise-ec2-json" do
  action :nothing
  type 'email'
  allow_empty ${AUDIT_AWS_EC2_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_EC2_SEND_ON}'
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "violations": COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "security-groups-ec2" do
  action :run
  json_input '{
      "main_report":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report,
      "ec2_report":COMPOSITE::coreo_aws_rule_runner_ec2.advise-unused-security-groups-ec2.report,
      "elb_report":COMPOSITE::coreo_aws_rule_runner_elb.advise-elb-ec2.report
  }'
  function <<-EOH

const ec2_alerts_list = ${AUDIT_AWS_EC2_ALERT_LIST};
if(!ec2_alerts_list.includes('ec2-not-used-security-groups')) {
  callback(json_input.main_report);
  return;
}

const activeSecurityGroups = [];

const groupIsActive = (groupId) => {
    for (let activeGroupId of activeSecurityGroups) {
        if (activeGroupId === groupId) return true;
    }
    return false;
};

Object.keys(json_input.elb_report).forEach((region) => {
  Object.keys(json_input.elb_report[region]).forEach(key => {
      const violation = json_input.elb_report[region][key].violations['elb-load-balancers-active-security-groups-list'];
      if (!violation) return;
      violation.result_info.forEach((obj) => {
          obj.object.forEach((secGroup) => {
              activeSecurityGroups.push(secGroup);
          })
      });
  });
});
Object.keys(json_input.ec2_report).forEach((region) => {

  Object.keys(json_input.ec2_report[region]).forEach(key => {
      const violation = json_input.ec2_report[region][key].violations['ec2-instances-active-security-groups-list'];
      if (!violation) return;
      violation.result_info.forEach((obj) => {
          activeSecurityGroups.push(obj.object.group_id);
      });
  });
});
Object.keys(json_input.ec2_report).forEach((region) => {
  Object.keys(json_input.ec2_report[region]).forEach(key => {
      const tags = json_input.ec2_report[region][key].tags;
      const violations = json_input.ec2_report[region][key].violations["ec2-security-groups-list"];
      if (!violations) return;
  
      const currentSecGroup = violations['result_info'][0].object;
      if (groupIsActive(currentSecGroup.group_id)) return;
      const securityGroupIsNotUsedAlert = {
          'display_name': 'EC2 security group is not used',
          'description': 'Security group is not used anywhere',
          'category': 'Audit',
          'suggested_action': 'Remove this security group',
          'level': 'Warning',
          'region': violations.region
      };
      const violationKey = 'ec2-not-used-security-groups';
      if (!json_input.main_report[region][key]) json_input.main_report[region][key] = { violations: {}, tags: [] };
      json_input.main_report[region][key].violations[violationKey] = securityGroupIsNotUsedAlert;
      json_input.main_report[region][key].tags.concat(tags);
  });
});
callback(json_input.main_report);
  EOH
end

coreo_uni_util_variables "ec2-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-suppression-ec2" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
  const fs = require('fs');
  const yaml = require('js-yaml');
  let suppression;
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
  }
  coreoExport('suppression', JSON.stringify(suppression));
  function createViolationWithSuppression(result) {
      const regionKeys = Object.keys(violations);
      regionKeys.forEach(regionKey => {
          result[regionKey] = {};
          const objectIdKeys = Object.keys(violations[regionKey]);
          objectIdKeys.forEach(objectIdKey => {
              createObjectId(regionKey, objectIdKey);
          });
      });
  }
  
  function createObjectId(regionKey, objectIdKey) {
      const wayToResultObjectId = result[regionKey][objectIdKey] = {};
      const wayToViolationObjectId = violations[regionKey][objectIdKey];
      wayToResultObjectId.tags = wayToViolationObjectId.tags;
      wayToResultObjectId.violations = {};
      createSuppression(wayToViolationObjectId, regionKey, objectIdKey);
  }
  
  
  function createSuppression(wayToViolationObjectId, regionKey, violationObjectIdKey) {
      const ruleKeys = Object.keys(wayToViolationObjectId['violations']);
      ruleKeys.forEach(violationRuleKey => {
          result[regionKey][violationObjectIdKey].violations[violationRuleKey] = wayToViolationObjectId['violations'][violationRuleKey];
          Object.keys(suppression).forEach(suppressRuleKey => {
              suppression[suppressRuleKey].forEach(suppressionObject => {
                  Object.keys(suppressionObject).forEach(suppressObjectIdKey => {
                      setDateForSuppression(
                          suppressionObject, suppressObjectIdKey,
                          violationRuleKey, suppressRuleKey,
                          violationObjectIdKey, regionKey
                      );
                  });
              });
          });
      });
  }
  
  
  function setDateForSuppression(
      suppressionObject, suppressObjectIdKey,
      violationRuleKey, suppressRuleKey,
      violationObjectIdKey, regionKey
  ) {
      file_date = null;
      let suppressDate = suppressionObject[suppressObjectIdKey];
      const areViolationsEqual = violationRuleKey === suppressRuleKey && violationObjectIdKey === suppressObjectIdKey;
      if (areViolationsEqual) {
          const nowDate = new Date();
          const correctDateSuppress = getCorrectSuppressDate(suppressDate);
          const isSuppressionDate = nowDate <= correctDateSuppress;
          if (isSuppressionDate) {
              setSuppressionProp(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          } else {
              setSuppressionExpired(regionKey, violationObjectIdKey, violationRuleKey, file_date);
          }
      }
  }
  
  
  function getCorrectSuppressDate(suppressDate) {
      const hasSuppressionDate = suppressDate !== '';
      if (hasSuppressionDate) {
          file_date = suppressDate;
      } else {
          suppressDate = new Date();
      }
      let correctDateSuppress = new Date(suppressDate);
      if (isNaN(correctDateSuppress.getTime())) {
          correctDateSuppress = new Date(0);
      }
      return correctDateSuppress;
  }
  
  
  function setSuppressionProp(regionKey, objectIdKey, violationRuleKey, file_date) {
      const wayToViolationObject = result[regionKey][objectIdKey].violations[violationRuleKey];
      wayToViolationObject["suppressed"] = true;
      if (file_date != null) {
          wayToViolationObject["suppression_until"] = file_date;
          wayToViolationObject["suppression_expired"] = false;
      }
  }
  
  function setSuppressionExpired(regionKey, objectIdKey, violationRuleKey, file_date) {
      if (file_date !== null) {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_until"] = file_date;
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = true;
      } else {
          result[regionKey][objectIdKey].violations[violationRuleKey]["suppression_expired"] = false;
      }
      result[regionKey][objectIdKey].violations[violationRuleKey]["suppressed"] = false;
  }
  
  const violations = json_input['violations'];
  const result = {};
  createViolationWithSuppression(result, json_input);
  
  callback(result);
  EOH
end

coreo_uni_util_variables "ec2-for-suppression-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-ec2.return'}
            ])
end

coreo_uni_util_jsrunner "jsrunner-process-table-ec2" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    var fs = require('fs');
    var yaml = require('js-yaml');
    try {
        var table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
    } catch (e) {
    }
    coreoExport('table', JSON.stringify(table));
    callback(table);
  EOH
end


coreo_uni_util_jsrunner "jsrunner-process-alert-list-ec2" do
  action :run
  provide_composite_access true
  json_input '{"violations":COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report}'
  packages([
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  function <<-EOH
    let alertListToJSON = "${AUDIT_AWS_EC2_ALERT_LIST}";
    let alertListArray = alertListToJSON.replace(/'/g, '"');
    callback(alertListArray);
  EOH
end

coreo_uni_util_jsrunner "ec2-tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.7.8"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "alert list": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-alert-list-ec2.return,
                "table": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-table-ec2.return,
                "violations": COMPOSITE::coreo_uni_util_jsrunner.jsrunner-process-suppression-ec2.return}'
  function <<-EOH
const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;


const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG, 
    ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditEC2 = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const notifiers = AuditEC2.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "ec2-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
let rollup = '';
let emailText = '';
let numberOfViolations = 0;
for (var entry=0; entry < json_input.length; entry++) {
    if (json_input[entry]['endpoint']['to'].length) {
        numberOfViolations += parseInt(json_input[entry]['num_violations']);
        emailText += "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "Violations: " + json_input[entry]['num_violations'] + "\\n";
    }
}

rollup += 'number of Violations: ' + numberOfViolations + "\\n";
rollup += 'Rollup' + "\\n";
rollup += emailText;

rollup_string = rollup;
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-ec2-to-tag-values" do
  action :${AUDIT_AWS_EC2_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action :${AUDIT_AWS_EC2_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_EC2_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end
