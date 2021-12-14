import json
import time
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse
import os
import datetime 
from datetime import date


class Tester(interfaces.TesterInterface):
    
    def __init__(self):
        self.aws_iam_client = boto3.client('iam')        
        self.aws_iam_resource = boto3.resource('iam')
        self.users = self.aws_iam_client.list_users()
        self.policies = self.aws_iam_client.list_policies()
        self.account_summary = self.aws_iam_client.get_account_summary()
        try:
            self.password_policy = self.aws_iam_client.get_account_password_policy()
        except self.aws_iam_client.exceptions.NoSuchEntityException as ex:
            self.password_policy = {'PasswordPolicy' : {
                    'AllowUsersToChangePassword': False,
                    'ExpirePasswords': False,
                    'MinimumPasswordLength': 8, ## default
                    'RequireSymbols': True, ## default
                    'RequireNumbers': True,
                    'RequireUppercaseCharacters': True,
                    'RequireLowercaseCharacters': True
                }
            }
        self.access_key = self.aws_iam_resource.AccessKey('user_name','id')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.max_password_age = 90
        self.days_to_expire = 90

    def declare_tested_service(self) -> str:
        return 'iam'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return \
            self.detect_policy_prevents_password_reuse() + \
            self.detect_old_access_key() + \
            self.detect_attached_users() + \
            self.detect_policy_requires_symbol() + \
            self.detect_policy_requires_number() + \
            self.detect_password_policy_length() + \
            self.detect_policy_requires_uppercase() + \
            self.detect_policy_requires_lowercase() + \
            self.detect_policy_max_password_age() + \
            self.detect_root_access_key_is_present() + \
            self.detect_initial_set_up_keys() + \
            self.detect_user_inline_policy_in_group() + \
            self.detect_mfa_is_enabled_for_root() + \
            self.detect_full_policy_administrative_privileges()

    def date_converter(self, o):
        if isinstance(o, datetime.datetime):
            return o.__str__()

    def detect_old_access_key(self):
        test_name = "old_access_keys"
        result = []
        for user in self.users['Users']:
            days = self.days_between(user['CreateDate'])
            if(days > self.days_to_expire):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": user['UserId'] + "@@" + user['UserName'],
                    "item_type": "user_record",
                    "user_record": user,
                    "test_name": test_name,
                    "timestamp": self.date_converter(time.time())
                })
        
        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "user_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        return result

    def days_between(self, d1):
        d1 = date(d1.year, d1.month, d1.day)
        d2 = date.today()
        return abs((d2 - d1).days)

    def detect_attached_users(self):
        test_name = "policy_attached_users"
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
                    "test_name": test_name,
                    "timestamp": self.date_converter(datetime.datetime.now())
                })
            
            if len(result) == 0:
               result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": None,
                    "item_type": "policy_record",
                    "timestamp": self.date_converter(datetime.datetime.now())
                })

        return result

    def detect_policy_requires_symbol(self):
        test_name = "policy_requires_symbol"
        result = []
        if self.password_policy['PasswordPolicy']['RequireSymbols']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        
        return result

    def detect_policy_requires_number(self):
        test_name = "policy_requires_number"
        result = []
        if self.password_policy['PasswordPolicy']['RequireNumbers']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        
        return result

    def detect_password_policy_length(self):
        test_name = "minimum_password_policy_length"
        result = []
        if self.password_policy['PasswordPolicy']['MinimumPasswordLength'] < 14:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy,
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
            
        return result    

    def detect_policy_requires_uppercase(self):
        test_name = "policy_requires_uppercase"
        result = []
        if self.password_policy['PasswordPolicy']['RequireUppercaseCharacters']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def detect_policy_prevents_password_reuse(self):
        test_name = "prevents_password_reuse"
        result = []
        try:
            account_password_policy = self.aws_iam_resource.AccountPasswordPolicy()
            if ((not account_password_policy.password_reuse_prevention is None and isinstance(account_password_policy.password_reuse_prevention, int)) 
            or account_password_policy.password_reuse_prevention == 0):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": "password_policy@@" + self.account_id,
                    "item_type": "password_policy_record",
                    "password_policy_record": self.password_policy['PasswordPolicy'],
                    "test_name": test_name,
                    "timestamp": self.date_converter(datetime.datetime.now())
                })
            
        except self.aws_iam_client.exceptions.NoSuchEntityException as ex:
            account_password_policy = None
        except Exception as ex:    
            account_password_policy = None
        
        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })    
        return result

    def detect_policy_requires_lowercase(self):
        test_name = "policy_requires_lowercase"
        result = []
        if self.password_policy['PasswordPolicy']['RequireLowercaseCharacters']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.password_policy['PasswordPolicy'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def detect_policy_max_password_age(self):
        test_name = "policy_max_password_age"
        result = []
        password_policy = self.password_policy['PasswordPolicy']
        if (password_policy['ExpirePasswords'] and password_policy['MaxPasswordAge'] <= self.max_password_age):
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "password_policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": password_policy,
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def detect_root_access_key_is_present(self):
        test_name = "root_access_key_is_present"
        result = []
        if self.account_summary['SummaryMap']['AccountAccessKeysPresent']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "account_summary_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "account_summary_record": self.account_summary['SummaryMap'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        
        return result

    def detect_initial_set_up_keys(self):
        test_name = "initial_set_up_keys"
        result = []
        for user in self.users['Users']:
            access_keys = self.aws_iam_client.list_access_keys(UserName=user['UserName'])
            for item in access_keys['AccessKeyMetadata']:
                if self.is_same_date(user['CreateDate'], item['CreateDate']):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": "certificate@@" + self.account_id,
                        "item_type": "access_key_record",
                        "access_key_record": None,
                        "test_name": test_name,
                        "timestamp": self.date_converter(datetime.datetime.now())
                    })

        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": item,
                "item_type": "access_key_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def is_same_date(self, firstDate, secondDate):
        d1 = date(firstDate.year, firstDate.month, firstDate.day)
        d2 = date(secondDate.year, secondDate.month, secondDate.day)
        return d1 == d2

    def detect_user_inline_policy_in_group(self):
        test_name = "user_inline_policy_in_group"
        result = []
        for user in self.users['Users']:
            user_group = self.aws_iam_client.list_groups_for_user(UserName=user['UserName'])
            for group in user_group['Groups']:
                group_policy = self.aws_iam_client.list_attached_group_policies(GroupName=group['GroupName'])
                if len(group_policy['AttachedPolicies']) > 0:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": user['UserId'] + "@@" + user['UserName'],
                        "item_type": "user_record",
                        "user_record": user,
                        "test_name": test_name,
                        "timestamp": self.date_converter(datetime.datetime.now())
                    })
        
        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "user_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def detect_mfa_is_enabled_for_root(self):
        test_name = "detect_mfa_is_enabled"
        result = []
        if self.account_summary['SummaryMap']['AccountMFAEnabled']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "account_summary_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "account_summary_record": self.account_summary['SummaryMap'],
                "test_name": test_name,
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result

    def detect_full_policy_administrative_privileges(self):
        test_name = "full_policy_administrative_privileges"
        result = []
        local_policy = self.aws_iam_client.list_policies(Scope='Local')
        for policy in local_policy['Policies']:
            policy_version = self.aws_iam_client.list_policy_versions(PolicyArn=policy['Arn'])
            for version in policy_version['Versions']:
                version_permission = self.aws_iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=version['VersionId'])
                for permission in version_permission['PolicyVersion']['Document']['Statement']:
                    if permission['Effect'] == "Allow" and permission['Action'] == "*" and permission['Resource'] == "*":
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "item": policy['PolicyId'] + "@@" + policy['PolicyName'],
                            "item_type": "policy_record",
                            "policy_record": policy,
                            "test_name": test_name,
                            "timestamp": self.date_converter(datetime.datetime.now())
                        })

        if len(result) == 0:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": None,
                "item_type": "policy_record",
                "timestamp": self.date_converter(datetime.datetime.now())
            })

        return result