# Troubleshooting Runbook for SSM Session Monitoring Step Function

## Overview

This runbook provides a series of troubleshooting steps for the SSM Session Monitoring Step Function, which monitors SSM Sessions for compliance with Guardrails and terminates non-compliant sessions.

## Prerequisites

- Access to the AWS Management Console
  - Central Log Archive account
  - Member AWS Accounts where stepfunction / solution is deployed
- Knowledge of AWS IAM permissions
- Knowledge of AWS Step Functions
- Subscription to solutions AWS SNS Topics
  - Central SNS Alerting Topic Subscription
  - Member AWS Accounts SNS Topic Subscription
- Knowledge of AWS CloudTrail
- Access to affected account(s) for troubleshooting

## Troubleshooting Steps

1. Review the SNS Notification event that triggered the SSM Session Monitoring Step Function in the affected account. </br>
 SNS Notification contains the enriched CloudTrail event that includes the reason for the session termination.
1. Identify the affected SSM Session and target instance based on the enriched CloudTrail event. Note the AWS account ID for the affected account.
2. Investigate the Step Function execution for any errors, including Lambda function errors, and identify any points of failure. </br>
Check the AWS CloudWatch logs for the Lambda functions for any errors or exceptions.
3. If SSM Session was terminated due to non compliant configuration, termination reason will be also sent via SNS Notification. That should be lead for further investigation.
4. If the S3 logs are not being delivered to the central bucket, it may be due to a network configuration issue for the affected instance. </br>
To resolve this issue, the network configuration of the instance should be reviewed, including VPC Endpoint policies, NACLs, and Security Groups.</br>
Ensure that the SSM agent is able to upload S3 logs by checking the CloudTrail logs for any changes to the VPC Endpoint policy, NACL, or Security Group that may have blocked the SSM agent from uploading logs from the EC2 instance to S3.
5. Investigate the affected instance for any malicious activities that may have tampered with the EC2 Instance Profile permissions.
6. If nothing above helps, you should also investigate Service Control Policies ( https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html ), can be that API's needed for Agent to upload logs or start session are blocked. This should be also visible in CloudTrail with errorMessage AccessDenied.

## Conclusion

Following the steps outlined in this runbook should help troubleshoot issues with the SSM Session Monitoring Step Function and determine the cause of non-compliant SSM Sessions.
Blog post documentation explains in detail how solution works, that should also help with investigation.

In case of issues , open issue on GitHub.
