audit EC2
============================
This stack will monitor EC2 and alert on things CloudCoreo developers think are violations of best practices


## Description

This repo is designed to work with CloudCoreo. It will monitor EC2 against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_EC2_ALERT_RECIPIENT value

## Variables Requiring Your Input

### `AUDIT_AWS_EC2_ALERT_RECIPIENT`:
  * description: email recipient for notification

## Variables Required but Defaulted

### `AUDIT_AWS_EC2_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: ec2-ip-address-whitelisted,ec2-unrestricted-traffic,ec2-TCP-1521-0.0.0.0/0,ec2-TCP-3306-0.0.0.0/0,ec2-TCP-5432-0.0.0.0/0,ec2-TCP-27017-0.0.0.0/0,ec2-TCP-1433-0.0.0.0/0,ec2-TCP-3389-0.0.0.0/0,ec2-TCP-22-0.0.0.0/0,ec2-TCP-5439-0.0.0.0/0,ec2-TCP-23,ec2-TCP-21,ec2-TCP-20,ec2-ports-range

### `AUDIT_AWS_EC2_ALERT_RECIPIENT`:
  * description: email recipient for notification

### `AUDIT_AWS_EC2_ALLOW_EMPTY`:
  * description: receive empty reports?

### `AUDIT_AWS_EC2_PAYLOAD_TYPE`:
  * description: json or text
  * default: json

### `AUDIT_AWS_EC2_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_EC2_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1,us-west-1,us-west-2

## Variables Not Required

**None**

## Tags

1. Audit
1. Best Practices
1. Alert
1. EC2

## Categories

1. Audit

## Diagram



## Icon



