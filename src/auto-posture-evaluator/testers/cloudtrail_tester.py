import time
import boto3
import interfaces


class CloudtrailTester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_cloudtrail_client = boto3.client('cloudtrail')
    def declare_required_args(self) -> list:
        return []

    def declare_tested_resource_type(self) -> str:
        return 'cloudtrail'

    def declare_tested_service(self) -> str:
        return 'cloudtrail'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self, args_object) -> list:
        return \
        self.global_services_are_enabled() + \
        self.log_file_validation_is_enabled() + \
        self.multi_region_is_enabled() + \
        self.logs_encryption_is_enabled()

    def global_services_are_enabled(self):
        result = []
        #Get All Trails Description
        trail_list = self.aws_cloudtrail_client.describe_trails(trailNameList=[],includeShadowTrails=False)
        #Get the Array and process each element
        trails_array = trail_list.get("trailList")
        for trail_meta in trails_array:
            trailName = trail_meta["Name"]
            trailGlobal = trail_meta["IncludeGlobalServiceEvents"]
            trailBucket = trail_meta["S3BucketName"]
            if  trailGlobal  == False:
                result.append({
                    "item" : trailName,
                    "trail_bucket" : trailBucket,
                    "test_name" : 'global_services_are_enabled',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "test_name": 'global_services_are_enabled',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    def log_file_validation_is_enabled(self):
        result = []
        #Get All Trails Description
        trail_list = self.aws_cloudtrail_client.describe_trails(trailNameList=[],includeShadowTrails=False)
        #Get the Array and process each element
        trails_array = trail_list.get("trailList")
        for trail_meta in trails_array:
            trailName = trail_meta["Name"]
            trailLogValidation = trail_meta["LogFileValidationEnabled"]
            trailBucket = trail_meta["S3BucketName"]
            if  trailLogValidation  == False:
                result.append({
                    "item" : trailName,
                    "trail_bucket" : trailBucket,
                    "test_name" : 'log_file_validation_is_enabled',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "test_name": 'log_file_validation_is_enabled',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    
    def multi_region_is_enabled(self):
        result = []
        #Get All Trails Description
        trail_list = self.aws_cloudtrail_client.describe_trails(trailNameList=[],includeShadowTrails=False)
        #Get the Array and process each element
        trails_array = trail_list.get("trailList")
        for trail_meta in trails_array:
            trailName = trail_meta["Name"]
            trailMultiRegion = trail_meta["IsMultiRegionTrail"]
            trailBucket = trail_meta["S3BucketName"]
            if  trailMultiRegion  == False:
                result.append({
                    "item" : trailName,
                    "trail_bucket" : trailBucket,
                    "test_name" : 'multi_region_is_enabled',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "test_name": 'multi_region_is_enabled',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    
    def logs_encryption_is_enabled(self):
        result = []
        #Get All Trails Description
        trail_list = self.aws_cloudtrail_client.describe_trails(trailNameList=[],includeShadowTrails=False)
        #Get the Array and process each element
        trails_array = trail_list.get("trailList")
        for trail_meta in trails_array:
            trailName = trail_meta["Name"]
            trailBucket = trail_meta["S3BucketName"]
            if  ("KmsKeyId" in trail_meta)  == False:
                result.append({
                    "item" : trailName,
                    "trail_bucket" : trailBucket,
                    "test_name" : 'logs_encryption_is_enabled',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "test_name": 'logs_encryption_is_enabled',
            "item": None,
            "timestamp": time.time()                    
            })
        return result