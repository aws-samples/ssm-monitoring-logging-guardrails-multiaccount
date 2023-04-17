import unittest
import os
import boto3
from botocore.exceptions import ClientError

# from jsonschema.exceptions import ValidationError, SchemaError
from unittest.mock import MagicMock, patch


class TestLambdaHandler(unittest.TestCase):
    def setUp(self):
        self.cloudtrail_event_digest = {
            "detail": {"requestParameters": {"target": "i-0123456789abcdef0"}}
        }
        os.environ[
            "SSM_POLICY_ARN"
        ] = "arn:aws:iam::123456789012:policy/aws-ssm-monitoring-mandatory-ssm-session-manager-policy"
        self.ec2_c = MagicMock()
        self.ssm_c = MagicMock()
        self.iam_c = MagicMock()
        self.ec2_c.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123456789012:instance-profile/test-instance-profile"
                            }
                        }
                    ]
                }
            ]
        }

        self.iam_c.list_instance_profiles.return_value = {
            "InstanceProfiles": [
                {
                    "InstanceProfileName": "test-instance-profile",
                    "Arn": "arn:aws:iam::123456789012:instance-profile/test-instance-profile",
                    "Roles": [
                        {
                            "RoleName": "test-role",
                            "Arn": "arn:aws:iam::123456789012:role/test-role",
                        }
                    ],
                }
            ]
        }

        self.iam_c.get_role.return_value = {
            "Role": {
                "RoleName": "test-role",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
            }
        }

        self.iam_c.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "NonCompliantPolicy1",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy1",
                },
                {
                    "PolicyName": "NonCompliantPolicy2",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy2",
                },
                {
                    "PolicyName": "NonCompliantPolicy2",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy3",
                },
                {
                    "PolicyName": "CompliantPolicy",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/CompliantPolicy",
                },
                {
                    "PolicyName": "aws-ssm-monitoring-mandatory-ssm-session-manager-policy",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/aws-ssm-monitoring-mandatory-ssm-session-manager-policy",
                },
            ]
        }

        self.iam_c.list_role_policies.return_value = {"PolicyNames": ["deny_all"]}

    def tearDown(self):
        del self.ec2_c
        del self.ssm_c
        del self.iam_c

    def client_factory(self, service):
        if service == "ec2":
            return self.ec2_c
        elif service == "iam":
            return self.iam_c
        elif service == "ssm":
            return self.ssm_c

    def mock_get_policy(self, PolicyArn):
        if PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy1":
            return {
                "Policy": {
                    "PolicyName": "NonCompliantPolicy1",
                    "Arn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy1",
                    "DefaultVersionId": "v1",
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy2":
            return {
                "Policy": {
                    "PolicyName": "NonCompliantPolicy2",
                    "Arn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy2",
                    "DefaultVersionId": "v1",
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy3":
            return {
                "Policy": {
                    "PolicyName": "NonCompliantPolicy3",
                    "Arn": "arn:aws:iam::123456789012:policy/NonCompliantPolicy3",
                    "DefaultVersionId": "v1",
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/CompliantPolicy":
            return {
                "Policy": {
                    "PolicyName": "CompliantPolicy",
                    "Arn": "arn:aws:iam::123456789012:policy/CompliantPolicy",
                    "DefaultVersionId": "v1",
                }
            }
        elif (
            PolicyArn
            == "arn:aws:iam::123456789012:policy/aws-ssm-monitoring-mandatory-ssm-session-manager-policy"
        ):
            return {
                "Policy": {
                    "PolicyName": "aws-ssm-monitoring-mandatory-ssm-session-manager-policy",
                    "Arn": "arn:aws:iam::123456789012:policy/aws-ssm-monitoring-mandatory-ssm-session-manager-policy",
                    "DefaultVersionId": "v1",
                }
            }

    def mock_get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy1":
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:*", "kms:*"],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Deny",
                                "Action": ["kms:*", "logs:*"],
                                "Resource": "*",
                            },
                        ]
                    }
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy2":
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "*",
                            },
                            {
                                "Effect": "Deny",
                                "Action": "s3:*",
                                "Resource": "*",
                            },
                        ]
                    }
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/NonCompliantPolicy3":
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": ["logs:*"],
                                "Resource": "*",
                            }
                        ]
                    }
                }
            }
        elif PolicyArn == "arn:aws:iam::123456789012:policy/CompliantPolicy":
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "*",
                            }
                        ]
                    }
                }
            }
        elif (
            PolicyArn
            == "arn:aws:iam::123456789012:policy/aws-ssm-monitoring-mandatory-ssm-session-manager-policy"
        ):
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "*",
                            }
                        ]
                    }
                }
            }

    def test_import_fails_without_env_variable(self):
        # Remove the environment variable if it exists
        if "SSM_POLICY_ARN" in os.environ:
            del os.environ["SSM_POLICY_ARN"]

        # Attempt to import the function and check that an ImportError is raised
        try:
            from aws_ssm_guardrails_org_member_account0 import (
                LambdaHandler,
            )
        except EnvironmentError as error:
            self.assertEqual(
                "Missing ENV variable SSM_POLICY_ARN", str(error.exception)
            )
        except Exception:
            self.fail("EnviromnentError was not raised.")

    @patch("boto3.client")
    def test_get_ssm_target_from_cloudtrail_event(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        self.assertEqual(
            "i-0123456789abcdef0",
            LambdaHandler(
                self.cloudtrail_event_digest
            ).get_ssm_target_from_cloudtrail_event(),
        )

    def test_get_ssm_target_from_cloudtrail_event_target_not_matching_pattern(self):
        cloudtrail_event_digest = {
            "detail": {"requestParameters": {"target": "BreakPattern"}}
        }
        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        try:
            LambdaHandler(
                cloudtrail_event_digest
            ).get_ssm_target_from_cloudtrail_event()
        except Exception as error:
            if not isinstance(error, ValueError):
                self.fail("ValueError was not raised!")

    @patch("boto3.client")
    def test_valid_ssm_managed_instance(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory

        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        self.ec2_c.describe_instances.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.Malformed"}}, "describe_instances"
        )

        self.ssm_c.describe_instance_information.return_value = {
            "InstanceInformationList": [
                {
                    "InstanceId": "mi-030a9d9bbe10fafcd",
                    "IamRole": "service-role/test-role",
                }
            ]
        }

        self.iam_c.get_role.return_value = {
            "Role": {
                "RoleName": "test-role",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
            }
        }

        result = LambdaHandler(
            self.cloudtrail_event_digest
        ).fetch_target_instance_profile_role()
        self.assertEqual(
            result,
            {
                "RoleName": "test-role",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
            },
        )

    @patch("boto3.client")
    def test_ec2_instance_id(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory

        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        cloudtrail_event_digest = {
            "detail": {"requestParameters": {"target": "i-0123456789abcdef0"}}
        }
        result = LambdaHandler(
            cloudtrail_event_digest
        ).fetch_target_instance_profile_role()
        self.assertEqual(
            result,
            {
                "RoleName": "test-role",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
            },
        )

    @patch("boto3.client")
    def test_validate_all_inline_policies_associated_with_iam_role(
        self, mock_boto3_client
    ):
        mock_boto3_client.side_effect = self.client_factory
        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        self.iam_c.list_role_policies.return_value = {"PolicyNames": ["deny_all"]}
        self.iam_c.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:*", "kms:*"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Deny",
                        "Action": ["kms:*", "logs:*"],
                        "Resource": "*",
                    },
                ]
            }
        }
        handler = LambdaHandler(self.cloudtrail_event_digest)
        handler.validate_all_inline_policies_associated_with_iam_role()
        self.assertTrue(handler.event["TerminateNonCompliantSession"])
        self.assertEqual(
            handler.event["TerminateReason"],
            [
                "test-role is having Explicit Deny for either s3, kms, logs Actions in "
                "attached IAM inline Policy deny_all, this has to be removed in order to be "
                "compliant."
            ],
        )

    @patch("boto3.client")
    def test_validate_all_policies_associated_with_iam_role(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        self.iam_c.get_policy.side_effect = self.mock_get_policy
        self.iam_c.get_policy_version.side_effect = self.mock_get_policy_version
        from aws_ssm_guardrails_org_member_account0 import (
            LambdaHandler,
        )

        handler = LambdaHandler(self.cloudtrail_event_digest)
        handler.validate_all_policies_associated_with_iam_role()

        # Assert
        self.assertTrue(handler.event["TerminateNonCompliantSession"])
        self.assertEqual(
            handler.event["TerminateReason"],
            [
                "test-role is having an explicit Deny for kms Actions in attached IAM Customer Managed Policy arn:aws:iam::123456789012:policy/NonCompliantPolicy1, this has to be removed in order to be compliant.",
                "test-role is having an explicit Deny for logs Actions in attached IAM Customer Managed Policy arn:aws:iam::123456789012:policy/NonCompliantPolicy1, this has to be removed in order to be compliant.",
                "test-role is having an explicit Deny for s3 Actions in attached IAM Customer Managed Policy arn:aws:iam::123456789012:policy/NonCompliantPolicy2, this has to be removed in order to be compliant.",
                "test-role is having an explicit Deny for logs Actions in attached IAM Customer Managed Policy arn:aws:iam::123456789012:policy/NonCompliantPolicy3, this has to be removed in order to be compliant.",
            ],
        )


if __name__ == "__main__":
    unittest.main()
