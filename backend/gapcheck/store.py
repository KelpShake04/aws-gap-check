"""DynamoDB 단일 테이블 접근. 사용자 데이터 키에는 항상 JWT의 sub가 들어간다(IDOR 방지).

키 규칙
  연결  PK=USER#{sub}               SK=CONN#{connId}
  스캔  PK=USER#{sub}               SK=SCAN#{scanId}
  결과  PK=USER#{sub}#SCAN#{scanId}  SK=FIND#{rank}#{checkId}
  해설  PK=EXPLAIN#{checkId}         SK={promptVersion}#{model}

table은 boto3 Table 리소스다. 테스트의 가짜 테이블이 흉내 낼 수 있도록 아래 식 형태만 쓴다.
숫자는 int만 저장한다(boto3 리소스는 float를 거부한다).
"""
from __future__ import annotations

from decimal import Decimal

from .common import error_code


class Store:
    def __init__(self, table):
        self.table = table

    # 연결
    def put_connection(self, sub: str, conn: dict) -> None:
        self.table.put_item(Item={"PK": f"USER#{sub}", "SK": f"CONN#{conn['id']}", **conn})

    def get_connection(self, sub: str, conn_id: str):
        return self._get(f"USER#{sub}", f"CONN#{conn_id}")

    def list_connections(self, sub: str) -> list:
        return self._query(f"USER#{sub}", "CONN#")

    def update_connection(self, sub: str, conn_id: str, fields: dict) -> bool:
        return self._update(f"USER#{sub}", f"CONN#{conn_id}", fields)

    def delete_connection(self, sub: str, conn_id: str) -> None:
        self.table.delete_item(Key={"PK": f"USER#{sub}", "SK": f"CONN#{conn_id}"})

    # 스캔
    def put_scan(self, sub: str, scan: dict) -> None:
        self.table.put_item(Item={"PK": f"USER#{sub}", "SK": f"SCAN#{scan['id']}", **scan})

    def get_scan(self, sub: str, scan_id: str):
        return self._get(f"USER#{sub}", f"SCAN#{scan_id}")

    def list_scans(self, sub: str) -> list:
        return self._query(f"USER#{sub}", "SCAN#", newest_first=True)

    def update_scan(self, sub: str, scan_id: str, fields: dict) -> bool:
        return self._update(f"USER#{sub}", f"SCAN#{scan_id}", fields)

    def claim_scan(self, sub: str, scan_id: str, from_statuses: tuple, fields: dict) -> bool:
        """상태가 from_statuses 중 하나일 때만 바꾼다. 중복 이벤트가 같은 스캔을 두 번 처리하지 않게 한다."""
        return self._update(f"USER#{sub}", f"SCAN#{scan_id}", fields, from_statuses)

    # 결과(check 단위)
    def put_findings(self, sub: str, scan_id: str, groups: list, expires: int) -> None:
        with self.table.batch_writer() as batch:
            for group in groups:
                batch.put_item(Item=self._finding_item(sub, scan_id, group, expires))

    def put_finding(self, sub: str, scan_id: str, group: dict, expires: int) -> None:
        self.table.put_item(Item=self._finding_item(sub, scan_id, group, expires))

    def list_findings(self, sub: str, scan_id: str) -> list:
        return self._query(f"USER#{sub}#SCAN#{scan_id}", "FIND#")

    def delete_findings(self, sub: str, scan_id: str) -> None:
        pk = f"USER#{sub}#SCAN#{scan_id}"
        items = self.table.query(KeyConditionExpression="PK = :pk",
                                 ExpressionAttributeValues={":pk": pk}).get("Items", [])
        with self.table.batch_writer() as batch:
            for item in items:
                batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})

    # 해설 캐시 (고객 데이터가 없는 일반 해설이라 사용자 사이에 공유)
    def get_explanation(self, check_id: str, version: str, model: str):
        item = self._get(f"EXPLAIN#{check_id}", f"{version}#{model}")
        return item["explanation"] if item else None

    def put_explanation(self, check_id: str, version: str, model: str, explanation: dict) -> None:
        self.table.put_item(Item={"PK": f"EXPLAIN#{check_id}", "SK": f"{version}#{model}",
                                  "explanation": explanation})

    # 내부
    @staticmethod
    def _finding_item(sub, scan_id, group, expires):
        return {"PK": f"USER#{sub}#SCAN#{scan_id}",
                "SK": f"FIND#{group['rank']}#{group['checkId']}",
                **group, "expiresAt": expires}

    def _get(self, pk, sk):
        item = self.table.get_item(Key={"PK": pk, "SK": sk}).get("Item")
        return _clean(item) if item else None

    def _query(self, pk, prefix, newest_first=False) -> list:
        kwargs = {
            "KeyConditionExpression": "PK = :pk AND begins_with(SK, :sk)",
            "ExpressionAttributeValues": {":pk": pk, ":sk": prefix},
            "ScanIndexForward": not newest_first,
        }
        items = []
        while True:
            page = self.table.query(**kwargs)
            items.extend(_clean(item) for item in page.get("Items", []))
            if "LastEvaluatedKey" not in page:
                return items
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _update(self, pk, sk, fields: dict, from_statuses: tuple = ()) -> bool:
        """있는 항목만 고친다. 없으면 False(update_item이 새 항목을 만들지 않게).

        from_statuses가 있으면 현재 status가 그중 하나일 때만 고친다.
        """
        keys = list(fields)
        names = {f"#f{i}": key for i, key in enumerate(keys)}
        values = {f":v{i}": fields[key] for i, key in enumerate(keys)}
        condition = "attribute_exists(PK)"
        if from_statuses:
            names["#status"] = "status"
            values.update({f":s{i}": status for i, status in enumerate(from_statuses)})
            condition += " AND #status IN (" + ", ".join(f":s{i}" for i in range(len(from_statuses))) + ")"
        try:
            self.table.update_item(
                Key={"PK": pk, "SK": sk},
                UpdateExpression="SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(keys))),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ConditionExpression=condition,
            )
        except Exception as err:
            if error_code(err) == "ConditionalCheckFailedException":
                return False
            raise
        return True


def _clean(item: dict) -> dict:
    return {key: _plain(value) for key, value in item.items() if key not in ("PK", "SK")}


def _plain(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value
