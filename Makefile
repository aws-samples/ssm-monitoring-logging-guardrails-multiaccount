help: ## Display this help screen.
	@grep -h -E '^[1-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "· \033[36m%-30s\033[0m %s\n", $$1, $$2}'

deploy-log-archive-stack: ## Deploys the aws-ssm-guardrails-log-archive-account.template to the log archive account using parameter AWSRegion.
	$(eval pOrgId := $(shell aws organizations describe-organization --query "Organization.Id" | tr -d '"'))
	aws cloudformation deploy \
		--stack-name aws-ssm-guardrails-log-archive-account \
		--template-file aws-ssm-guardrails-log-archive-account.template \
		--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
		--parameter-overrides AWSOrgId=$(pOrgId) \
		--region $(AWSRegion) \
		--no-fail-on-empty-changes
	@make describe-log-archive-stack-outputs AWSRegion=$(AWSRegion)

describe-log-archive-stack-outputs: ## Describes the aws-ssm-guardrails-log-archive-account.template CloudFormation Outputs using parameter AWSRegion.
	@output=$$(aws cloudformation describe-stacks \
		--stack-name aws-ssm-guardrails-log-archive-account \
		--region $(AWSRegion) \
		--query "Stacks[0].Outputs" | jq -r '.[] | "\(.OutputKey)=\(.OutputValue)"') && \
	echo "##### Below is the command to deploy the stack in a different member AWS account. Please copy and paste the entire block of code into the shell of the target AWS Organizations Member Account. #####" && echo && \
	echo "make deploy-member-account-stack AWSRegion=$(AWSRegion) \\" && \
	echo "$$output" | awk 'NR > 1 { print last_line " \\" } { last_line = $$0 } END { print last_line }' && \
	echo -e "\n##### End of command #####\n"

delete-log-archive-stack: ## Deletes the CloudFormation stack deployed using the aws-ssm-guardrails-log-archive-account.template from the log archive account using parameter AWSRegion.
	python3 cleanup_aws_ssm_guardrails_log_archive_account_s3_buckets.py $(AWSRegion)
	aws cloudformation delete-stack \
		--stack-name  aws-ssm-guardrails-log-archive-account \
		--region $(AWSRegion)

deploy-member-account-stack: ## Deploys the aws-ssm-guardrails-org-member-account.template to the log archive account using parameter AWSRegion, CentralSSMSessionLoggingS3BucketName, CentralSSMSessionMonitoringKMSKeyArn, CentralSSMSessionMonitoringSecurityComplianceSNSTopicArn
	$(eval pOrgId := $(shell aws organizations describe-organization --query "Organization.Id" | tr -d '"'))
	aws cloudformation deploy \
		--stack-name aws-ssm-guardrails-org-member-account \
		--template-file aws-ssm-guardrails-org-member-account.template \
		--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
		--parameter-overrides AWSOrgId=$(pOrgId) CentralSSMSessionLoggingS3BucketName=$(CentralSSMSessionLoggingS3BucketName) CentralSSMSessionMonitoringKMSKeyArn=$(CentralSSMSessionMonitoringKMSKeyArn) CentralSSMSessionMonitoringSecurityComplianceSNSTopicArn=$(CentralSSMSessionMonitoringSecurityComplianceSNSTopicArn) \
		--region $(AWSRegion) \
		--no-fail-on-empty-changes

detach-member-account-policy-from-entities: # Removes from all IAM principals policy deployed via deploy-member-account-stack command in member account
	$(eval accountId := $(shell aws sts get-caller-identity --query "Account" | tr -d '"'))
	aws iam list-entities-for-policy \
	    --policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    --query "PolicyRoles[].[RoleName]" --output text | \
		while read line; do \
	    	echo "Detaching from IAM role $$line"; \
	    	aws iam detach-role-policy \
	    		--policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    		--role-name $$line; \
		done
	aws iam list-entities-for-policy \
	    --policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    --query "PolicyUsers[].[UserName]" --output text | \
		while read line; do \
	    	echo "Detaching from IAM user $$line"; \
	    	aws iam detach-user-policy \
	    		--policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    		--user-name $$line; \
		done
	aws iam list-entities-for-policy \
	    --policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    --query "PolicyGroups[].[GroupName]" --output text | \
		while read line; do \
	    	echo "Detaching from IAM group $$line"; \
	    	aws iam detach-group-policy \
	    		--policy-arn arn:aws:iam::$(accountId):policy/aws-ssm-guardrails-mandatory-policy-$(AWSRegion) \
	    		--group-name $$line; \
		done

delete-member-account-stack: ## Deletes the CloudFormation stack deployed using the template aws-ssm-guardrails-org-member-account.template from the member account using parameter AWSRegion.
	@make detach-member-account-policy-from-entities AWSRegion=$(AWSRegion)
	aws cloudformation delete-stack \
		--stack-name  aws-ssm-guardrails-org-member-account \
		--region $(AWSRegion)
