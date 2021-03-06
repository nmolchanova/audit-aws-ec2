ec2 audit
============================
This composite monitors ec2 and reports best practice violations, standards body policy violations, and inventory


## Description
This composite monitors ec2 against best practices and reports violations and inventory


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_EC2_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1

### `AUDIT_AWS_EC2_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_EC2_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change


## Optional variables with default

### `AUDIT_AWS_EC2_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are ec2-inventory-instances ec2-inventory-security-groups ec2-ip-address-whitelisted ec2-unrestricted-traffic ec2-TCP-1521-0.0.0.0/0 ec2-TCP-3306-0.0.0.0/0 ec2-TCP-5432-0.0.0.0/0 ec2-TCP-27017-0.0.0.0/0 ec2-TCP-1433-0.0.0.0/0 ec2-TCP-3389-0.0.0.0/0 ec2-TCP-22-0.0.0.0/0 ec2-TCP-5439-0.0.0.0/0 ec2-TCP-23 ec2-TCP-21 ec2-TCP-20 ec2-TCP-8080 ec2-ports-range ec2-not-used-security-groups ec2-default-security-group-traffic ec2-vpc-flow-logs
  * default: ec2-ip-address-whitelisted, ec2-unrestricted-traffic, ec2-TCP-1521-0.0.0.0/0, ec2-TCP-3306-0.0.0.0/0, ec2-TCP-5432-0.0.0.0/0, ec2-TCP-27017-0.0.0.0/0, ec2-TCP-1433-0.0.0.0/0, ec2-TCP-3389-0.0.0.0/0, ec2-TCP-22-0.0.0.0/0, ec2-TCP-5439-0.0.0.0/0, ec2-TCP-23, ec2-TCP-21, ec2-TCP-20, ec2-TCP-8080, ec2-ports-range, ec2-not-used-security-groups, ec2-default-security-group-traffic, ec2-vpc-flow-logs

### `AUDIT_AWS_EC2_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the EC2 object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `HTML_REPORT_SUBJECT`:
  * description: Enter a custom report subject name.

### `AUDIT_AWS_EC2_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `FILTERED_OBJECTS`:
  * description: JSON object of string or regex of aws objects to include or exclude and tag in audit

### `AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME`:
  * description: Enter S3 bucket name to upload reports. (Optional)

## Tags
1. Audit
1. Best Practices
1. Inventory
1. ec2


## Categories
1. AWS Services Audit


## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2/master/images/icon.png "icon")

