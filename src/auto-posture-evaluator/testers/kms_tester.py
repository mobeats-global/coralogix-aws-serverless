import json
import time
import boto3
import interfaces

class Tester(interfaces.TesterInterface):
    
    def __init__(self):
        self.aws_iam_client = boto3.client('kms', region_name='us-west-2') 
        self.keys = self.aws_iam_client.list_keys()
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')

    def declare_tested_service(self) -> str:
        return 'kms'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_rotation_enabled()

    def detect_rotation_enabled(self):
        test_name = "rotation_enabled"
        result = []
        for key in self.keys['Keys']:
            status = self.aws_iam_client.get_key_rotation_status(KeyId=key['KeyId'])
            if not status['KeyRotationEnabled']:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": key['KeyId'] + "@@" + key['KeyArn'],
                    "item_type": "kms_record",
                    "user_record": key,
                    "test_name": test_name,
                    "timestamp": time.time()
                })

        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "key_record",
                "timestamp": time.time()
            })    
        return result
