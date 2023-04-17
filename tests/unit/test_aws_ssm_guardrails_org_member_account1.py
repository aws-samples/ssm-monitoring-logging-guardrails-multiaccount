import unittest
import os
import boto3
from botocore.exceptions import ClientError
from unittest.mock import MagicMock, patch


class TestLambdaHandler(unittest.TestCase):
    def setUp(self):
        os.environ[
            "SESSION_LOGGING_BUCKET"
        ] = "central-log-ssm-audit-${AWS::Region}-${OrganizationId}"
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        if "SESSION_LOGGING_CW_GROUP" in os.environ:
            del os.environ["SESSION_LOGGING_CW_GROUP"]
        self.cloudtrail_event_digest = {
            "detail": {"responseElements": {"sessionId": "some_valid_session_id"}},
            "account": "1111111111111",
            "region": "us-east-1",
        }
        self.s3_c = MagicMock()
        self.cw_c = MagicMock()

    def tearDown(self):
        del self.s3_c
        del self.cw_c

    def client_factory(self, service):
        if service == "s3":
            return self.s3_c
        elif service == "logs":
            return self.cw_c

    def test_session_is_none_value_error(self):
        cloudtrail_event_digest = {"detail": {"responseElements": {"sessionId": None}}}
        from aws_ssm_guardrails_org_member_account1 import (
            lambda_handler,
        )

        try:
            lambda_handler(cloudtrail_event_digest, {})
        except ValueError:
            pass
        except Exception:
            self.fail("ValueError was not raised.")

    def test_import_fails_without_env_variable(self):
        # Remove the environment variable if it exists
        if "SESSION_LOGGING_BUCKET" in os.environ:
            del os.environ["SESSION_LOGGING_BUCKET"]

        # Attempt to import the function and check that an ImportError is raised
        try:
            from aws_ssm_guardrails_org_member_account1 import (
                lambda_handler,
            )
        except EnvironmentError:
            pass
        except Exception:
            self.fail("EnviromnentError was not raised.")

    @patch("boto3.client")
    def test_s3_logs_not_present(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        self.s3_c.list_objects_v2.return_value = {}
        self.cw_c.describe_log_streams.return_value = {
            "logStreams": ["Log Stream was present"]
        }
        from aws_ssm_guardrails_org_member_account1 import (
            lambda_handler,
        )

        self.assertFalse(
            lambda_handler(self.cloudtrail_event_digest, {}).get("S3SessionLogsPresent")
        )
        self.assertEqual(
            lambda_handler(self.cloudtrail_event_digest, {}).get("AlertReason"),
            "For SSM Session some_valid_session_id, Guardrails were not able to validate presence of SSM Session Logs - s3://central-log-ssm-audit-${AWS::Region}-${OrganizationId}/1111111111111/us-east-1/some_valid_session_id.log",
        )

    @patch("boto3.client")
    def test_s3_logs_present(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        os.environ["SESSION_LOGGING_CW_GROUP"] = "/ssm-session-logs"
        from aws_ssm_guardrails_org_member_account1 import (
            lambda_handler,
        )

        self.s3_c.list_objects_v2.return_value = {
            "Contents": ["Faking S3 List, should return True"]
        }

        self.assertTrue(
            lambda_handler(self.cloudtrail_event_digest, {}).get(
                "S3SessionLogsPresent"
            ),
        )

    @patch("boto3.client")
    def test_empty_ssm_session(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        os.environ["SESSION_LOGGING_CW_GROUP"] = "/ssm-session-logs"
        from aws_ssm_guardrails_org_member_account1 import (
            lambda_handler,
        )

        self.s3_c.list_objects_v2.return_value = {"Contents": []}

        self.cw_c.describe_log_streams.return_value = {"logStreams": []}

        self.assertTrue(
            lambda_handler(self.cloudtrail_event_digest, {}).get(
                "S3SessionLogsPresent"
            ),
        )


if __name__ == "__main__":
    unittest.main()
