audit EC2
============================
This stack will monitor EC2 and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor EC2 against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;EC2&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_EC2_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.


## Required variables with default

### `AUDIT_AWS_EC2_ALERT_LIST`:
  * description: Which alerts would you like to check for? (Default is all EC2 alerts)
  * default: ec2-ip-address-whitelisted, ec2-unrestricted-traffic, ec2-TCP-1521-0.0.0.0/0, ec2-TCP-3306-0.0.0.0/0, ec2-TCP-5432-0.0.0.0/0, ec2-TCP-27017-0.0.0.0/0, ec2-TCP-1433-0.0.0.0/0, ec2-TCP-3389-0.0.0.0/0, ec2-TCP-22-0.0.0.0/0, ec2-TCP-5439-0.0.0.0/0, ec2-TCP-23, ec2-TCP-21, ec2-TCP-20, ec2-ports-range

### `AUDIT_AWS_EC2_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_EC2_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_EC2_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-west-1,us-west-2.
  * default: us-east-1, us-west-1, us-west-2


## Optional variables with default

**None**


## Optional variables with no default

**None**

## Tags
1. Audit
1. Best Practices
1. Alert
1. EC2

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2/master/images/diagram.png "diagram")


## Icon


