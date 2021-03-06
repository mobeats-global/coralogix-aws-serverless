import json
import time
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse
from datetime import date


class Tester(interfaces.TesterInterface):
    
    def __init__(self):
        self.aws_iam_client = boto3.client('iam')        
        self.aws_iam_resource = boto3.resource('iam')
        self.users = self.aws_iam_client.list_users()
        self.policies = self.aws_iam_client.list_policies()
        self.password_policy = self.aws_iam_client.get_account_password_policy()
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
        self.detect_old_access_key()
        self.detect_attacched_users()
        self.detect_policy_require_symbols()
        self.detect_password_policy_length()

    def detect_old_access_key(self) -> str:
        result = []
        for user in self.users['Users']:
            days = self.days_between(user['CreateDate'])
            if(days > 90):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": user['UserId'] + "@@" + user['UserName'],
                    "item_type": "user_record",
                    "user_record": user,
                    "test_name": 'old_access_keys',
                    "timestamp": time.time()
                })
        
        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'old_access_keys',
                "item": None,
                "item_type": "user_record",
                "timestamp": time.time()
            })
        return result

    def days_between(self, d1):
        d1 = date(d1.year, d1.month, d1.day)
        d2 = date.today()
        return abs((d2 - d1).days)

    def detect_attacched_users(self) -> str:
        result = []
        for policy in self.policies['Policies']:
            response = self.aws_iam_resource.Policy(policy['Arn'])
            size = sum(1 for _ in response.attached_users.all())
            if(size == 0):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": policy['PolicyId'] + "@@" + policy['PolicyName'],
                    "item_type": "policy_record",
                    "policy_record": policy,
                    "test_name": 'policy_attached_users',
                    "timestamp": time.time()
                })
            
            if len(result) == 0:
               result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": 'policy_attached_users',
                    "item": None,
                    "item_type": "policy_record",
                    "timestamp": time.time()
                }) 

        return result

    def detect_policy_require_symbols(self):
        result = []
        if (self.password_policy['PasswordPolicy']['RequireSymbols']):
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_require_symbol',
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_require_symbol',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        
        return result

    def detect_password_policy_length(self):
        result = []
        if self.password_policy['PasswordPolicy']['MinimumPasswordLength'] < 14:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'minimum_password_policy_length',
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'minimum_password_policy_length',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
            
        return result    