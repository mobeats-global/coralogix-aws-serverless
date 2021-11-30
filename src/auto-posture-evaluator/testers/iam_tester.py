import json
import time
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse


class Tester(interfaces.TesterInterface):
    
    def __init__(self):
        
        self.aws_iam_client = boto3.client('iam')        
        
        self.aws_iam_resource = boto3.resource('iam')

        self.users = self.aws_iam_client.list_users()

        self.access_key = self.aws_iam_resource.AccessKey('user_name','id')

        self.cache = {}

        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')

    def declare_tested_service(self) -> str:
        return 'iam'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        self.test_1()

    def test_1(self) -> str:
        for x in self.users:
            print(x['Users'])
        return 'testing'