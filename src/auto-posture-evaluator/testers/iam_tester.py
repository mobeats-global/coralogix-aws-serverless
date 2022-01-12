import time
import boto3
import interfaces
import datetime
from datetime import date

class Tester(interfaces.TesterInterface):
    
    def __init__(self):
        self.aws_iam_client = boto3.client('iam')        
        self.aws_iam_resource = boto3.resource('iam')
        self.aws_kms_client = boto3.client('kms')
        self.users = self.aws_iam_client.list_users()
        self.policies = self.aws_iam_client.list_policies()
        self.roles = self.aws_iam_client.list_roles()
        self.account_summary = self.aws_iam_client.get_account_summary()
        self.kms_keys = self.aws_kms_client.list_keys()
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
        self.access_key_days_to_expire = 90
        self.server_certificate_days_to_expire = 30

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
            self.detect_full_policy_administrative_privileges() + \
            self.detect_support_role_manages_incidents() + \
            self.detect_user_has_admin_permissions() + \
            self.detect_role_uses_trusted_principals() + \
            self.detect_rotation_for_kms_is_enabled() + \
            self.detect_expired_server_certificates() + \
            self.detect_mfa_is_enabled_for_users() + \
            self.detect_validity_period_of_server_certificates()

    def detect_old_access_key(self):
        test_name = "old_access_keys"
        result = []
        try:
            for user in self.users['Users']:
                days = self.days_between(user['CreateDate'])
                if(days > self.access_key_days_to_expire):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": user['UserId'] + "@@" + user['UserName'],
                        "item_type": "user_record",
                        "user_record": self.serialize_date_field(user),
                        "test_name": test_name,
                        "timestamp": time.time(),
                        "test_result": "issue_found"
                    })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "test_name": test_name,
                        "item": user['UserId'] + "@@" + user['UserName'],
                        "item_type": "user_record",
                        "timestamp": time.time(),
                        "test_result": "no_issue_found"
                    })
        except:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "user_record@@" + self.account_id,
                "item_type": "user_record",
                "user_record": {
                    "error" : "Incorrect create date type in user."
                },
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
            
        return result

    def days_between(self, d1):
        d2 = date.today()
        if isinstance(d1, str):
            d1 = self.str_to_datetime(d1)
            
        date_to_compare = self.date_without_time(d1)
        return abs((d2 - date_to_compare).days)

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
                    "policy_record": self.serialize_date_field(policy),
                    "test_name": test_name,
                    "timestamp": time.time(),
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": policy['PolicyId'] + "@@" + policy['PolicyName'],
                    "item_type": "policy_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
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
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.serialize_date_field(self.password_policy['PasswordPolicy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
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
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.serialize_date_field(self.password_policy['PasswordPolicy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
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
                "password_policy_record": self.serialize_date_field(self.password_policy),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
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
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.serialize_date_field(self.password_policy['PasswordPolicy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
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
                    "password_policy_record": self.serialize_date_field(self.password_policy['PasswordPolicy']),
                    "test_name": test_name,
                    "timestamp": time.time(),
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": "password_policy@@" + self.account_id,
                    "item_type": "password_policy_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })
            
        except self.aws_iam_client.exceptions.NoSuchEntityException as ex:
            account_password_policy = None
        except Exception as ex:    
            account_password_policy = None
        
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
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.serialize_date_field(self.password_policy['PasswordPolicy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
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
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "password_policy@@" + self.account_id,
                "item_type": "password_policy_record",
                "password_policy_record": self.serialize_date_field(password_policy),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
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
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "account_summary_record": self.serialize_date_field(self.account_summary['SummaryMap']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
        
        return result

    def detect_initial_set_up_keys(self):
        test_name = "initial_set_up_keys"
        result = []
        try:
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
                            "test_name": test_name,
                            "timestamp": time.time(),
                            "test_result": "no_issue_found"
                        })
                    else:
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "test_name": test_name,
                            "item": "certificate@@" + self.account_id,
                            "item_type": "access_key_record",
                            "access_key_record": self.serialize_date_field(item),
                            "timestamp": time.time(),
                            "test_result": "issue_found"
                        })
        except:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": "certificate@@" + self.account_id,
                "item_type": "access_key_record",
                "access_key_record": {
                    "error": "Incorrect create date type in user or access key."
                },
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
            
        return result

    def is_same_date(self, firstDate, secondDate):
        if isinstance(firstDate, str):
            firstDate = self.str_to_datetime(firstDate)
        if isinstance(secondDate, str):
            secondDate = self.str_to_datetime(secondDate)

        d1 = self.date_without_time(firstDate)
        d2 = self.date_without_time(secondDate)

        return d1 == d2

    def str_to_datetime(self, str_date):
        return datetime.datetime.fromisoformat(str_date)

    def date_without_time(self, datetime):
        return date(datetime.year, datetime.month, datetime.day)

    def detect_user_inline_policy_in_group(self):
        test_name = "user_inline_policy_in_group"
        result = []
        for user in self.users['Users']:
            issue_detected = False
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
                        "user_record": self.serialize_date_field(user),
                        "test_name": test_name,
                        "timestamp": time.time(),
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": user['UserId'] + "@@" + user['UserName'],
                    "item_type": "user_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })

        return result

    def detect_mfa_is_enabled_for_root(self):
        test_name = "mfa_is_enabled_for_root"
        result = []
        if not self.account_summary['SummaryMap']['AccountMFAEnabled']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "account_summary@@" + self.account_id,
                "item_type": "account_summary_record",
                "account_summary_record": self.serialize_date_field(self.account_summary['SummaryMap']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })

        return result

    def detect_full_policy_administrative_privileges(self):
        test_name = "full_policy_administrative_privileges"
        result = []
        local_policy = self.aws_iam_client.list_policies(Scope='Local')
        for policy in local_policy['Policies']:
            issue_detected = False
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
                            "policy_record": self.serialize_date_field(policy),
                            "test_name": test_name,
                            "timestamp": time.time(),
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": policy['PolicyId'] + "@@" + policy['PolicyName'],
                    "item_type": "policy_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })

        return result

    def detect_support_role_manages_incidents(self):
        test_name = "support_role_manages_incidents"
        result = []
        policy = self.aws_iam_client.get_policy(PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
        entities = self.aws_iam_client.list_entities_for_policy(PolicyArn=policy['Policy']['Arn'], EntityFilter='Role', PolicyUsageFilter='PermissionsPolicy')
        if entities['PolicyRoles']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": policy['Policy']['PolicyId'] + "@@" + policy['Policy']['PolicyName'],
                "item_type": "policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": policy['Policy']['PolicyId'] + "@@" + policy['Policy']['PolicyName'],
                "item_type": "policy_record",
                "policy_record": self.serialize_date_field(policy['Policy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })

        return result

    def detect_user_has_admin_permissions(self):
        test_name = "user_has_admin_permissions"
        result = []
        policy = self.aws_iam_client.get_policy(PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        entities = self.aws_iam_client.list_entities_for_policy(PolicyArn=policy['Policy']['Arn'], EntityFilter='User', PolicyUsageFilter='PermissionsPolicy')
        if entities['PolicyUsers']:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "test_name": test_name,
                "item": policy['Policy']['PolicyId'] + "@@" + policy['Policy']['PolicyName'],
                "item_type": "policy_record",
                "timestamp": time.time(),
                "test_result": "no_issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": policy['Policy']['PolicyId'] + "@@" + policy['Policy']['PolicyName'],
                "item_type": "policy_record",
                "policy_record": self.serialize_date_field(policy['Policy']),
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })

        return result

    def detect_role_uses_trusted_principals(self):
        test_name = "role_uses_trusted_principals"
        result = []
        for rol in self.roles['Roles']:
            issue_detected = False
            for statement in rol['AssumeRolePolicyDocument']['Statement']:
                if not 'Principal' in statement:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": rol['RoleId'] + "@@" + rol['RoleName'],
                        "item_type": "role_record",
                        "role_record": self.serialize_date_field(rol),
                        "test_name": test_name,
                        "timestamp": time.time(),
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": rol['RoleId'] + "@@" + rol['RoleName'],
                    "item_type": "role_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })

        return result

    def detect_rotation_for_kms_is_enabled(self):
        test_name = "rotation_for_kms_is_enabled"
        result = []
        for key in self.kms_keys['Keys']:
            key_rotation_status = self.aws_kms_client.get_key_rotation_status(KeyId=key['KeyId'])
            if not key_rotation_status['KeyRotationEnabled']:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": key['KeyId'] + "@@" + key['KeyArn'],
                    "item_type": "kms_key_record",
                    "kms_key_record": self.serialize_date_field(key),
                    "test_name": test_name,
                    "timestamp": time.time(),
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": key['KeyId'] + "@@" + key['KeyArn'],
                    "item_type": "kms_key_record",
                    "test_name": test_name,
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })

        return result


    def detect_expired_server_certificates(self):
        test_name = "expired_server_certificates"
        result = []
        try:
            server_certificates = self.aws_iam_client.list_server_certificates()
            for certificate in server_certificates['ServerCertificateMetadataList']:
                if self.is_date_expired(certificate['Expiration']):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": certificate['ServerCertificateId'] + "@@" + certificate['ServerCertificateName'],
                        "item_type": "server_certificate_record",
                        "server_certificate_record": self.serialize_date_field(certificate),
                        "test_name": test_name,
                        "timestamp": time.time(),
                        "test_result": "issue_found"
                    })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "test_name": test_name,
                        "item": certificate['ServerCertificateId'] + "@@" + certificate['ServerCertificateName'],
                        "item_type": "server_certificate_record",
                        "timestamp": time.time(),
                        "test_result": "no_issue_found"
                    })
        except:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "server_certificate_record@@" + self.account_id,
                "item_type": "server_certificate_record",
                "server_certificate_record": {
                    "error" : "Incorrect expired date type in certificate."
                },
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
        
        return result

    def is_date_expired(self, d1):
        d2 = date.today()
        if isinstance(d1, str):
            d1 = self.str_to_datetime(d1)
        date_to_compare = self.date_without_time(d1)
        return date_to_compare < d2
        
    def detect_mfa_is_enabled_for_users(self):
        test_name = "mfa_is_enabled_for_users"
        result = []
        for user in self.users['Users']:
            mfa_devices = self.aws_iam_client.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices'] or not self.is_password_enabled(user['UserName']):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item": user['UserId'] + "@@" + user['UserName'],
                    "item_type": "user_record",
                    "user_record": self.serialize_date_field(user),
                    "test_name": test_name,
                    "timestamp": time.time(),
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "test_name": test_name,
                    "item": user['UserId'] + "@@" + user['UserName'],
                    "item_type": "user_record",
                    "timestamp": time.time(),
                    "test_result": "no_issue_found"
                })

        return result

    def is_password_enabled(self, user_name):
        try:
            self.aws_iam_client.get_login_profile(UserName=user_name)
            return True
        except:
            return False

    def detect_validity_period_of_server_certificates(self):
        test_name = "valid_period_of_server_certificates"
        result = []
        try:
            server_certificates = self.aws_iam_client.list_server_certificates()
            for certificate in server_certificates['ServerCertificateMetadataList']:
                days = self.days_between(certificate['Expiration'])
                if days > self.server_certificate_days_to_expire:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "item": certificate['ServerCertificateId'] + "@@" + certificate['ServerCertificateName'],
                        "item_type": "server_certificate_record",
                        "server_certificate_record": self.serialize_date_field(certificate),
                        "test_name": test_name,
                        "timestamp": time.time(),
                        "test_result": "issue_found"
                    })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "test_name": test_name,
                        "item": certificate['ServerCertificateId'] + "@@" + certificate['ServerCertificateName'],
                        "item_type": "server_certificate_record",
                        "timestamp": time.time(),
                        "test_result": "no_issue_found"
                    })
        except:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item": "server_certificate_record@@" + self.account_id,
                "item_type": "server_certificate_record",
                "server_certificate_record": {
                    "error" : "Incorrect expired date type in certificate."
                },
                "test_name": test_name,
                "timestamp": time.time(),
                "test_result": "issue_found"
            })
        
        return result

    def serialize_date_field(self, object):
        for key, value in object.items():
            if isinstance(value, datetime.datetime):
                object[key] = value.__str__()
            elif isinstance(value, dict):
                self.serialize_date_field(value)
        return object
