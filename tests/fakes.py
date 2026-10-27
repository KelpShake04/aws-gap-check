"""테스트용 가짜 AWS 클라이언트. gapcheck.store가 쓰는 식 형태만 흉내 낸다."""
import copy
import io
import json
import re


class ClientError(Exception):
    def __init__(self, code, message=""):
        super().__init__(message or code)
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["PK"], Key["SK"]))
        return {"Item": copy.deepcopy(item)} if item else {}

    def put_item(self, Item):
        self.items[(Item["PK"], Item["SK"])] = copy.deepcopy(Item)

    def delete_item(self, Key):
        self.items.pop((Key["PK"], Key["SK"]), None)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeNames,
                    ExpressionAttributeValues, ConditionExpression):
        assert ConditionExpression == "attribute_exists(PK)"
        item = self.items.get((Key["PK"], Key["SK"]))
        if item is None:
            raise ClientError("ConditionalCheckFailedException")
        for name, value in re.findall(r"(#f\d+) = (:v\d+)", UpdateExpression):
            item[ExpressionAttributeNames[name]] = copy.deepcopy(ExpressionAttributeValues[value])

    def query(self, KeyConditionExpression, ExpressionAttributeValues,
              ScanIndexForward=True, ExclusiveStartKey=None):
        pk = ExpressionAttributeValues[":pk"]
        prefix = ExpressionAttributeValues.get(":sk", "") if "begins_with" in KeyConditionExpression else ""
        found = sorted((sk, item) for (p, sk), item in self.items.items()
                       if p == pk and sk.startswith(prefix))
        if not ScanIndexForward:
            found.reverse()
        return {"Items": [copy.deepcopy(item) for _, item in found]}

    def batch_writer(self):
        return _Batch(self)


class _Batch:
    def __init__(self, table):
        self.table = table

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def put_item(self, Item):
        self.table.put_item(Item=Item)

    def delete_item(self, Key):
        self.table.delete_item(Key=Key)


class FakeSts:
    """accounts: ExternalId별로 맡을 수 있는 계정. 없으면 AccessDenied."""

    def __init__(self, allowed=None):
        self.allowed = allowed or {}
        self.calls = []

    def assume_role(self, RoleArn, RoleSessionName, ExternalId, DurationSeconds):
        self.calls.append({"RoleArn": RoleArn, "ExternalId": ExternalId,
                           "RoleSessionName": RoleSessionName})
        account = RoleArn.split(":")[4]
        if self.allowed.get(ExternalId) != account:
            raise ClientError("AccessDenied")
        return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{account}:assumed-role/x/{RoleSessionName}"},
                "Credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "x", "SessionToken": "x"}}


class FakeCodeBuild:
    def __init__(self, fail_code=None):
        self.fail_code = fail_code
        self.started = []
        self.builds = {}

    def start_build(self, projectName, environmentVariablesOverride):
        if self.fail_code:
            raise ClientError(self.fail_code)
        build_id = f"{projectName}:build-{len(self.started) + 1}"
        self.started.append({"projectName": projectName,
                             "env": {v["name"]: v["value"] for v in environmentVariablesOverride}})
        return {"build": {"id": build_id}}

    def batch_get_builds(self, ids):
        return {"builds": [self.builds[i] for i in ids if i in self.builds]}


class FakeS3:
    def __init__(self):
        self.objects = {}

    def get_object(self, Bucket, Key):
        body = self.objects[(Bucket, Key)]
        return {"Body": io.BytesIO(body), "ContentLength": len(body)}

    def list_objects_v2(self, Bucket, Prefix):
        keys = [k for (b, k) in self.objects if b == Bucket and k.startswith(Prefix)]
        return {"Contents": [{"Key": k} for k in keys]} if keys else {}

    def delete_objects(self, Bucket, Delete):
        for obj in Delete["Objects"]:
            self.objects.pop((Bucket, obj["Key"]), None)

    def put_json(self, bucket, key, data):
        self.objects[(bucket, key)] = json.dumps(data).encode()
