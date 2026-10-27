"""모델 출력 검증용 작은 JSON Schema 검증기(표준 라이브러리).

지원: type(object/array/string/integer), properties, required, items, minItems, maxItems,
minLength, maxLength, enum. 스키마에 없는 필드는 버린다. 길이가 넘는 문자열과 개수가 넘는
배열은 실패 대신 잘라 낸다(출력은 텍스트로만 쓰이므로 잘라도 안전하다). 제어 문자는 지운다.
"""
from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class ValidationError(ValueError):
    pass


def validate(value, schema: dict, path: str = "$"):
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict):
            raise ValidationError(f"{path}: object가 아님")
        for key in schema.get("required", []):
            if key not in value:
                raise ValidationError(f"{path}.{key}: 없음")
        return {key: validate(value[key], sub, f"{path}.{key}")
                for key, sub in schema.get("properties", {}).items() if key in value}
    if kind == "array":
        if not isinstance(value, list):
            raise ValidationError(f"{path}: array가 아님")
        items = [validate(item, schema["items"], f"{path}[{i}]") for i, item in enumerate(value)]
        if len(items) < schema.get("minItems", 0):
            raise ValidationError(f"{path}: 항목 수 부족")
        return items[:schema.get("maxItems", len(items))]
    if kind == "string":
        if not isinstance(value, str):
            raise ValidationError(f"{path}: string이 아님")
        text = _CONTROL.sub("", value).strip()
        if len(text) < schema.get("minLength", 0):
            raise ValidationError(f"{path}: 너무 짧음")
        if "enum" in schema and text not in schema["enum"]:
            raise ValidationError(f"{path}: 허용되지 않은 값")
        limit = schema.get("maxLength")
        if limit is not None and len(text) > limit:
            text = text[:limit - 1] + "…"
        return text
    if kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"{path}: integer가 아님")
        return value
    raise ValueError(f"지원하지 않는 type: {kind}")
