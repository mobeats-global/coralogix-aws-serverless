import json
import time
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse
import os
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
        self.max_password_age = int(os.getenv("MAX_PASSWORD_AGE", 90))

    def declare_tested_service(self) -> str:
        return 'iam'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        self.detect_old_access_key()
        self.detect_attached_users()
        self.detect_policy_requires_symbol()
        self.detect_policy_requires_number()
        self.detect_password_policy_length()
        self.detect_policy_prevents_password_reuse()
        self.detect_policy_requires_symbol()
        self.detect_policy_requires_number()
        self.detect_policy_requires_lowercase()
        self.detect_policy_max_password_age()

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

    def detect_attached_users(self) -> str:
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

    def detect_policy_requires_symbol(self):
        result = []
        if self.password_policy['PasswordPolicy']['RequireSymbols']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_requires_symbol',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_requires_symbol',
                "timestamp": time.time()
            })
        
        return result

    def detect_policy_requires_number(self):
        result = []
        if self.password_policy['PasswordPolicy']['RequireNumbers']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_requires_number',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_requires_number',
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

    def detect_policy_requires_uppercase(self):
        result = []
        if self.password_policy['PasswordPolicy']['RequireUppercaseCharacters']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_requires_uppercase',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_requires_uppercase',
                "timestamp": time.time()
            })

        return result

    def detect_policy_prevents_password_reuse(self):
        result = []
        account_password_policy = self.aws_iam_resource.AccountPasswordPolicy()
        if (account_password_policy.password_reuse_prevention is None or account_password_policy.password_reuse_prevention == 0):
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'prevents_password_reuse',
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'prevents_password_reuse',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })    
        
        return result

    def detect_policy_requires_lowercase(self):
        result = []
        if self.password_policy['PasswordPolicy']['RequireLowercaseCharacters']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_requires_lowercase',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_requires_lowercase',
                "timestamp": time.time()
            })

        return result

    def detect_policy_max_password_age(self):
        result = []
        password_policy = self.password_policy['PasswordPolicy']
        if (password_policy['ExpirePasswords'] and password_policy['MaxPasswordAge'] <= self.max_password_age):
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": 'policy_max_password_age',
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": time.time()
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": 'policy_max_password_age',
                "timestamp": time.time()
            })

        return result
