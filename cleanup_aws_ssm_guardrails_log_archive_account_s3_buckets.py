import boto3
from botocore.exceptions import ClientError
import sys

region_name = sys.argv[1]
cf = boto3.client('cloudformation',region_name=region_name)
stack_name = 'aws-ssm-guardrails-log-archive-account'
try:
    response = cf.describe_stack_resources(StackName=stack_name)
    s3_buckets = [r['PhysicalResourceId'] for r in response['StackResources'] if r['ResourceType'] == 'AWS::S3::Bucket']
    # Check if TempDeployment is set to true
    response = cf.describe_stacks(StackName=stack_name)['Stacks'][0]
    production_deployment_paramaeter =[p['ParameterValue'] for p in response['Parameters'] if p['ParameterKey'] == 'ProductionDeployment'][0]
    if production_deployment_paramaeter and production_deployment_paramaeter.lower() == 'false':
        print("Trying to delete Cloudformation stack - aws-ssm-guardrails-log-archive-account in AWS account - {}, region - {}".format(boto3.client('sts').get_caller_identity()['Account'],region_name))
        # Print out the list of S3 buckets
        for bucket_name in s3_buckets:
            print('Cleaning up S3 bucket: {}'.format(bucket_name))
            s3 = boto3.resource('s3')
            try:
                bucket = s3.Bucket(bucket_name)
                bucket.object_versions.all().delete()
                bucket.delete()
            except ClientError as error:
                if error.response["Error"]["Code"] == "NoSuchBucket":
                    pass
            print('Deleted S3 bucket: {}'.format(bucket_name))
    else:
        print('TempDeployment is not set to true, skipping S3 cleanup')
except ClientError as error:
    if error.response["Error"]["Code"] == "ValidationError":
        print("Seems that Stack - {} - does not exist!".format(stack_name))