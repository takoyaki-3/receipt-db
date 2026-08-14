"""Firebase 認証済みユーザー向けレシート解析・保存 API。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
FIREBASE_JWKS_URL = (
    "https://www.googleapis.com/service_accounts/v1/jwk/"
    "securetoken@system.gserviceaccount.com"
)
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
MAX_IMAGE_BYTES = 4_500_000
ALLOWED_MIME_TYPES = {"image/jpeg": "jpg", "image/png": "png"}
EDITABLE_FIELDS = {
    "storeName", "purchasedAt", "address", "phone", "subtotal", "tax", "total",
    "currency", "paymentMethod", "category", "note", "items",
}

_jwks_cache: tuple[float, dict[str, Any]] | None = None
_table: Any | None = None
_s3: Any | None = None
_textract: Any | None = None


class JwtVerificationError(RuntimeError):
    pass


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def response(status: int, body: Any) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "access-control-allow-origin": "*",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
            "referrer-policy": "no-referrer",
        },
        "body": json.dumps(body, ensure_ascii=False, default=_json_default),
    }


def _base64url_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JwtVerificationError("JWT の Base64URL 形式が不正です") from exc


def _load_firebase_keys(*, force_refresh: bool = False) -> dict[str, Any]:
    global _jwks_cache
    now = time.time()
    if not force_refresh and _jwks_cache and _jwks_cache[0] > now:
        return _jwks_cache[1]
    try:
        request = Request(FIREBASE_JWKS_URL, headers={"Accept": "application/json"})
        with urlopen(request, timeout=5) as result:
            document = json.loads(result.read().decode("utf-8"))
            cache_control = result.headers.get("Cache-Control", "")
    except (HTTPError, URLError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtVerificationError("Firebase 公開鍵を取得できません") from exc
    keys = {
        key["kid"]: key for key in document.get("keys", [])
        if isinstance(key, dict) and key.get("kid") and key.get("kty") == "RSA"
        and key.get("alg") == "RS256" and key.get("use") == "sig"
    }
    if not keys:
        raise JwtVerificationError("Firebase 公開鍵が空です")
    max_age = 3600
    match = re.search(r"(?:^|,)\s*max-age=(\d+)", cache_control, re.I)
    if match:
        max_age = min(int(match.group(1)), 7200)
    _jwks_cache = (now + max_age, keys)
    return keys


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: dict[str, Any]) -> None:
    try:
        modulus = int.from_bytes(_base64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(_base64url_decode(jwk["e"]), "big")
    except (KeyError, TypeError) as exc:
        raise JwtVerificationError("Firebase 公開鍵の形式が不正です") from exc
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        raise JwtVerificationError("JWT 署名長が不正です")
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_size, "big")
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    padding_length = key_size - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    if padding_length < 8 or not hmac.compare_digest(encoded, expected):
        raise JwtVerificationError("JWT 署名が一致しません")


def verify_firebase_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtVerificationError("JWT 形式が不正です")
    try:
        header = json.loads(_base64url_decode(parts[0]))
        claims = json.loads(_base64url_decode(parts[1]))
        signature = _base64url_decode(parts[2])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtVerificationError("JWT を解析できません") from exc
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise JwtVerificationError("JWT ヘッダーが不正です")
    keys = _load_firebase_keys()
    jwk = keys.get(header["kid"])
    if jwk is None:
        jwk = _load_firebase_keys(force_refresh=True).get(header["kid"])
    if jwk is None:
        raise JwtVerificationError("JWT の公開鍵が見つかりません")
    _verify_rs256(f"{parts[0]}.{parts[1]}".encode(), signature, jwk)
    now = int(time.time())
    project_id = os.environ["FIREBASE_PROJECT_ID"]
    if claims.get("aud") != project_id:
        raise JwtVerificationError("JWT audience が不正です")
    if claims.get("iss") != f"https://securetoken.google.com/{project_id}":
        raise JwtVerificationError("JWT issuer が不正です")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise JwtVerificationError("JWT subject が不正です")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
        raise JwtVerificationError("JWT の有効期限が切れています")
    if not isinstance(claims.get("iat"), (int, float)) or claims["iat"] > now + 300:
        raise JwtVerificationError("JWT issued-at が不正です")
    return claims


def authorizer(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    try:
        scheme, token = event.get("authorizationToken", "").split(" ", 1)
        if scheme.lower() != "bearer" or not token:
            raise JwtVerificationError("Bearer token がありません")
        claims = verify_firebase_jwt(token)
    except (ValueError, JwtVerificationError, KeyError):
        LOGGER.warning("Authentication failed", exc_info=True)
        raise Exception("Unauthorized")
    method_arn = event["methodArn"].split("/")
    resource = "/".join(method_arn[:2] + ["*", "*"])
    return {
        "principalId": claims["sub"],
        "policyDocument": {"Version": "2012-10-17", "Statement": [{
            "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": resource,
        }]},
        "context": {
            "sub": claims["sub"],
            "email": str(claims.get("email", "")),
            "email_verified": str(bool(claims.get("email_verified", False))).lower(),
        },
    }


def _services() -> tuple[Any, Any, Any]:
    global _table, _s3, _textract
    import boto3

    if _table is None:
        _table = boto3.resource("dynamodb").Table(os.environ["RECEIPTS_TABLE_NAME"])
    if _s3 is None:
        _s3 = boto3.client("s3")
    if _textract is None:
        _textract = boto3.client("textract")
    return _table, _s3, _textract


def _money(value: str | None) -> Decimal | None:
    if not value:
        return None
    normalized = value.translate(str.maketrans("０１２３４５６７８９．，－", "0123456789.,-"))
    matches = re.findall(r"-?\d[\d,]*(?:\.\d+)?", normalized)
    if not matches:
        return None
    try:
        return Decimal(matches[-1].replace(",", ""))
    except Exception:
        return None


def _field_value(field: dict[str, Any]) -> tuple[str, Decimal]:
    detection = field.get("ValueDetection") or field.get("LabelDetection") or {}
    return str(detection.get("Text", "")).strip(), Decimal(str(detection.get("Confidence", 0)))


def parse_expense(document: dict[str, Any]) -> dict[str, Any]:
    expense_docs = document.get("ExpenseDocuments", [])
    if not expense_docs:
        raise ValueError("レシートを認識できませんでした")
    expense = expense_docs[0]
    summaries: dict[str, tuple[str, Decimal]] = {}
    for field in expense.get("SummaryFields", []):
        kind = str((field.get("Type") or {}).get("Text", "")).upper()
        value, confidence = _field_value(field)
        if kind and value and (kind not in summaries or confidence > summaries[kind][1]):
            summaries[kind] = (value, confidence)

    def summary(*names: str) -> str:
        return next((summaries[name][0] for name in names if name in summaries), "")

    items: list[dict[str, Any]] = []
    item_confidences: list[Decimal] = []
    for group in expense.get("LineItemGroups", []):
        for line in group.get("LineItems", []):
            fields: dict[str, tuple[str, Decimal]] = {}
            for field in line.get("LineItemExpenseFields", []):
                kind = str((field.get("Type") or {}).get("Text", "")).upper()
                value, confidence = _field_value(field)
                if kind and value:
                    fields[kind] = (value, confidence)
            name = (fields.get("ITEM") or fields.get("PRODUCT_CODE") or ("", Decimal(0)))[0]
            if not name:
                continue
            quantity_text = (fields.get("QUANTITY") or ("1", Decimal(0)))[0]
            quantity = _money(quantity_text) or Decimal(1)
            price = _money((fields.get("PRICE") or fields.get("UNIT_PRICE") or ("", Decimal(0)))[0])
            unit_price = _money((fields.get("UNIT_PRICE") or ("", Decimal(0)))[0])
            confidences = [value[1] for value in fields.values()]
            confidence = sum(confidences, Decimal(0)) / max(len(confidences), 1)
            item_confidences.append(confidence)
            items.append({
                "name": name, "quantity": quantity, "unitPrice": unit_price,
                "price": price, "confidence": confidence.quantize(Decimal("0.1")),
            })
    summary_confidences = [value[1] for value in summaries.values()]
    confidences = summary_confidences + item_confidences
    confidence = sum(confidences, Decimal(0)) / max(len(confidences), 1)
    raw_text = "\n".join(
        block.get("Text", "") for block in document.get("Blocks", [])
        if block.get("BlockType") == "LINE" and block.get("Text")
    )[:20000]
    return {
        "storeName": summary("VENDOR_NAME"),
        "purchasedAt": summary("INVOICE_RECEIPT_DATE"),
        "address": summary("ADDRESS"),
        "phone": summary("VENDOR_PHONE"),
        "subtotal": _money(summary("SUBTOTAL")),
        "tax": _money(summary("TAX")),
        "total": _money(summary("TOTAL", "AMOUNT_DUE")),
        "currency": "JPY",
        "paymentMethod": summary("PAYMENT_TERMS"),
        "items": items,
        "itemCount": len(items),
        "confidence": confidence.quantize(Decimal("0.1")),
        "rawText": raw_text,
    }


def _body(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON object が必要です")
    return value


def _user(event: dict[str, Any]) -> tuple[str, str, bool]:
    context = event.get("requestContext", {}).get("authorizer", {})
    return (
        str(context.get("sub", "")),
        str(context.get("email", "")).strip().lower(),
        str(context.get("email_verified", "false")).lower() == "true",
    )


def _clean_items(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list) or len(items) > 200:
        raise ValueError("items は200件以下の配列にしてください")
    cleaned = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("name", "")).strip():
            raise ValueError("各品目には商品名が必要です")
        cleaned.append({
            "name": str(item["name"]).strip()[:200],
            "quantity": Decimal(str(item.get("quantity") or 1)),
            "unitPrice": Decimal(str(item["unitPrice"])) if item.get("unitPrice") not in (None, "") else None,
            "price": Decimal(str(item["price"])) if item.get("price") not in (None, "") else None,
        })
    return cleaned


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    user_id, email, email_verified = _user(event)
    if not user_id:
        return response(401, {"message": "認証情報がありません"})
    allowed = {
        value.strip().lower() for value in os.environ.get("ALLOWED_EMAILS", "").split(",")
        if value.strip()
    }
    if not email_verified or (allowed and email not in allowed):
        return response(403, {"message": "このアプリの利用は許可されていません"})
    route = event.get("routeKey") or f"{event.get('httpMethod', '')} {event.get('resource', '')}"
    receipt_id = (event.get("pathParameters") or {}).get("id", "")
    table, s3, textract = _services()
    try:
        if route == "GET /receipts":
            from boto3.dynamodb.conditions import Key

            records: list[dict[str, Any]] = []
            query: dict[str, Any] = {"KeyConditionExpression": Key("user_id").eq(user_id)}
            while True:
                result = table.query(**query)
                records.extend(result.get("Items", []))
                if "LastEvaluatedKey" not in result:
                    break
                query["ExclusiveStartKey"] = result["LastEvaluatedKey"]
            records.sort(key=lambda item: item["createdAt"], reverse=True)
            for item in records:
                item.pop("rawText", None)
            return response(200, {"receipts": records, "user": email})

        if route == "POST /receipts":
            body = _body(event)
            mime_type = str(body.get("mimeType", ""))
            if mime_type not in ALLOWED_MIME_TYPES:
                return response(400, {"message": "JPEG または PNG の画像を選択してください"})
            try:
                image = base64.b64decode(str(body.get("image", "")), validate=True)
            except (ValueError, binascii.Error):
                return response(400, {"message": "画像データが不正です"})
            if not image or len(image) > MAX_IMAGE_BYTES:
                return response(413, {"message": "画像は4.5MB以下にしてください"})
            analyzed = textract.analyze_expense(Document={"Bytes": image})
            parsed = parse_expense(analyzed)
            now = datetime.now(timezone.utc).isoformat()
            receipt_id = str(uuid.uuid4())
            image_key = f"users/{user_id}/receipts/{receipt_id}.{ALLOWED_MIME_TYPES[mime_type]}"
            s3.put_object(
                Bucket=os.environ["IMAGES_BUCKET_NAME"], Key=image_key, Body=image,
                ContentType=mime_type, ServerSideEncryption="AES256",
                Metadata={"owner": user_id},
            )
            record = {
                "user_id": user_id, "receipt_id": receipt_id, "createdAt": now,
                "updatedAt": now, "imageKey": image_key, "mimeType": mime_type,
                "category": "未分類", "note": "", "source": "amazon-textract",
                **parsed,
            }
            table.put_item(Item=record, ConditionExpression="attribute_not_exists(receipt_id)")
            return response(201, {"receipt": record})

        if route == "GET /receipts/{id}":
            record = table.get_item(Key={"user_id": user_id, "receipt_id": receipt_id}).get("Item")
            if not record:
                return response(404, {"message": "レシートが見つかりません"})
            record["imageUrl"] = s3.generate_presigned_url(
                "get_object", Params={"Bucket": os.environ["IMAGES_BUCKET_NAME"], "Key": record["imageKey"]},
                ExpiresIn=300,
            )
            return response(200, {"receipt": record})

        if route == "PUT /receipts/{id}":
            current = table.get_item(Key={"user_id": user_id, "receipt_id": receipt_id}).get("Item")
            if not current:
                return response(404, {"message": "レシートが見つかりません"})
            body = _body(event)
            for field in EDITABLE_FIELDS:
                if field not in body:
                    continue
                if field == "items":
                    current[field] = _clean_items(body[field])
                    current["itemCount"] = len(current[field])
                elif field in {"subtotal", "tax", "total"}:
                    current[field] = Decimal(str(body[field])) if body[field] not in (None, "") else None
                else:
                    current[field] = str(body[field]).strip()[:2000]
            current["updatedAt"] = datetime.now(timezone.utc).isoformat()
            table.put_item(Item=current)
            return response(200, {"receipt": current})

        if route == "DELETE /receipts/{id}":
            current = table.get_item(Key={"user_id": user_id, "receipt_id": receipt_id}).get("Item")
            if not current:
                return response(404, {"message": "レシートが見つかりません"})
            table.delete_item(Key={"user_id": user_id, "receipt_id": receipt_id})
            s3.delete_object(Bucket=os.environ["IMAGES_BUCKET_NAME"], Key=current["imageKey"])
            return response(200, {"ok": True})
        return response(404, {"message": "Not found"})
    except ValueError as exc:
        return response(400, {"message": str(exc)})
    except Exception:
        LOGGER.exception("Receipt operation failed: route=%s user=%s", route, user_id)
        return response(500, {"message": "処理に失敗しました。時間をおいて再度お試しください"})
