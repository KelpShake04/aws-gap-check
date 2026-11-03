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
        assert ConditionExpression.startswith("attribute_exists(PK)")
        item = self.items.get((Key["PK"], Key["SK"]))
        if item is None:
            raise ClientError("ConditionalCheckFailedException")
        if "#status IN" in ConditionExpression:
            allowed = [v for k, v in ExpressionAttributeValues.items() if k.startswith(":s")]
            if item.get(ExpressionAttributeNames["#status"]) not in allowed:
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


class FakeCe:
    """Cost Explorer. rows: (날짜 'YYYY-MM-DD', 서비스, 금액). pages가 2 이상이면 NextPageToken으로 나눠 준다."""

    def __init__(self, rows=(), forecast="10.00", fail_code=None, forecast_fail=False, pages=1):
        self.rows, self.forecast, self.fail_code = list(rows), forecast, fail_code
        self.forecast_fail, self.pages = forecast_fail, pages
        self.usage_calls, self.forecast_calls = [], []

    def get_cost_and_usage(self, **kwargs):
        self.usage_calls.append(kwargs)
        if self.fail_code:
            raise ClientError(self.fail_code)
        days = sorted({day for day, _, _ in self.rows})
        size = max(1, -(-len(days) // self.pages))
        index = int(kwargs.get("NextPageToken", 0))
        chunk = days[index * size:(index + 1) * size]
        results = [{"TimePeriod": {"Start": day}, "Groups": [
            {"Keys": [service], "Metrics": {"UnblendedCost": {"Amount": str(amount), "Unit": "USD"}}}
            for d, service, amount in self.rows if d == day]} for day in chunk]
        page = {"ResultsByTime": results}
        if (index + 1) * size < len(days):
            page["NextPageToken"] = str(index + 1)
        return page

    def get_cost_forecast(self, **kwargs):
        self.forecast_calls.append(kwargs)
        if self.forecast_fail:
            raise ClientError("DataUnavailableException")
        return {"Total": {"Amount": self.forecast, "Unit": "USD"}}
