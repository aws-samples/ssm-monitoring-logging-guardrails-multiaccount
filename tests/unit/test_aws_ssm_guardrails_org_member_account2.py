import unittest
import os
import boto3
from unittest.mock import MagicMock, patch


class TestLambdaHandler(unittest.TestCase):
    def setUp(self):
        self.cloudtrail_event_digest = {
            "detail": {"responseElements": {"sessionId": "some_valid_session_id"}}
        }
        self.ssm_c = MagicMock()

    def tearDown(self):
        del self.ssm_c

    def client_factory(self, service):
        if service == "ssm":
            return self.ssm_c

    @patch("boto3.client")
    def test_session_is_active(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        from aws_ssm_guardrails_org_member_account2 import (
            lambda_handler,
        )

        self.ssm_c.describe_sessions.return_value = {
            "Sessions": [
                {
                    "SessionId": "some_valid_session_id",
                    "Target": "string",
                    "Status": "Connected",
                }
            ]
        }

        self.assertEqual(
            self.cloudtrail_event_digest,
            lambda_handler(self.cloudtrail_event_digest, {}),
        )

    @patch("boto3.client")
    def test_session_is_not_active(self, mock_boto3_client):
        mock_boto3_client.side_effect = self.client_factory
        from aws_ssm_guardrails_org_member_account2 import (
            lambda_handler,
        )

        self.ssm_c.describe_sessions.return_value = {"Sessions": []}

        self.assertTrue(
            lambda_handler(self.cloudtrail_event_digest, {}).get("SessionIsTerminated"),
        )

    def test_session_is_none_value_error(self):
        cloudtrail_event_digest = {"detail": {"responseElements": {"sessionId": None}}}
        from aws_ssm_guardrails_org_member_account2 import (
            lambda_handler,
        )

        try:
            lambda_handler(cloudtrail_event_digest, {})
        except ValueError:
            pass
        except Exception as error:
            self.fail("ValueError was not raised.")


if __name__ == "__main__":
    unittest.main()
