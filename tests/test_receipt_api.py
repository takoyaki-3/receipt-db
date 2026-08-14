import base64
import json
import os
from pathlib import Path
import sys
import time
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / "lambda"))
import receipt_api


def encode(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def token(claims):
    return f"{encode({'alg': 'RS256', 'kid': 'key-1'})}.{encode(claims)}.{encode(b'signature')}"


def claims():
    now = int(time.time())
    return {
        "aud": "takoyaki3-auth",
        "iss": "https://securetoken.google.com/takoyaki3-auth",
        "sub": "user-1",
        "email": "owner@example.com",
        "email_verified": True,
        "iat": now - 10,
        "exp": now + 3600,
    }


def event(method, resource, body=None, receipt_id=None):
    value = {
        "httpMethod": method,
        "resource": resource,
        "requestContext": {"authorizer": {
            "sub": "user-1", "email": "owner@example.com", "email_verified": "true",
        }},
    }
    if body is not None:
        value["body"] = json.dumps(body)
    if receipt_id:
        value["pathParameters"] = {"id": receipt_id}
    return value


class ReceiptParserTests(unittest.TestCase):
    def test_parses_summary_and_all_line_items(self):
        document = {"ExpenseDocuments": [{
            "SummaryFields": [
                {"Type": {"Text": "VENDOR_NAME"}, "ValueDetection": {"Text": "たこやき商店", "Confidence": 99}},
                {"Type": {"Text": "TOTAL"}, "ValueDetection": {"Text": "￥1,280", "Confidence": 98}},
                {"Type": {"Text": "TAX"}, "ValueDetection": {"Text": "116円", "Confidence": 94}},
            ],
            "LineItemGroups": [{"LineItems": [
                {"LineItemExpenseFields": [
                    {"Type": {"Text": "ITEM"}, "ValueDetection": {"Text": "たこ焼き", "Confidence": 97}},
                    {"Type": {"Text": "QUANTITY"}, "ValueDetection": {"Text": "2", "Confidence": 92}},
                    {"Type": {"Text": "PRICE"}, "ValueDetection": {"Text": "1,200", "Confidence": 96}},
                ]},
            ]}],
        }], "Blocks": [{"BlockType": "LINE", "Text": "たこやき商店"}]}

        result = receipt_api.parse_expense(document)

        self.assertEqual(result["storeName"], "たこやき商店")
        self.assertEqual(result["total"], Decimal("1280"))
        self.assertEqual(result["tax"], Decimal("116"))
        self.assertEqual(result["items"][0]["quantity"], Decimal("2"))
        self.assertEqual(result["items"][0]["price"], Decimal("1200"))
        self.assertEqual(result["rawText"], "たこやき商店")

    def test_rejects_document_without_expense(self):
        with self.assertRaisesRegex(ValueError, "認識できません"):
            receipt_api.parse_expense({"ExpenseDocuments": []})


class AuthenticationTests(unittest.TestCase):
    @patch.dict(os.environ, {"FIREBASE_PROJECT_ID": "takoyaki3-auth"})
    @patch("receipt_api._verify_rs256")
    @patch("receipt_api._load_firebase_keys", return_value={"key-1": {}})
    def test_valid_firebase_token(self, _keys, verify):
        self.assertEqual(receipt_api.verify_firebase_jwt(token(claims()))["sub"], "user-1")
        verify.assert_called_once()

    @patch("receipt_api.verify_firebase_jwt", return_value=claims())
    def test_authorizer_allows_all_routes_in_stage(self, _verify):
        result = receipt_api.authorizer({
            "authorizationToken": "Bearer token",
            "methodArn": "arn:aws:execute-api:ap-northeast-1:123:api/prod/GET/receipts",
        }, None)
        self.assertEqual(result["principalId"], "user-1")
        self.assertEqual(result["policyDocument"]["Statement"][0]["Resource"], "arn:aws:execute-api:ap-northeast-1:123:api/prod/*/*")


class ApiTests(unittest.TestCase):
    @patch.dict(os.environ, {"ALLOWED_EMAILS": "owner@example.com", "IMAGES_BUCKET_NAME": "images"})
    @patch("receipt_api._services")
    @patch("receipt_api.parse_expense", return_value={"storeName": "店", "items": [], "itemCount": 0, "total": Decimal("500")})
    def test_upload_analyzes_and_stores_receipt(self, _parse, services):
        table, s3, textract = MagicMock(), MagicMock(), MagicMock()
        textract.analyze_expense.return_value = {"ExpenseDocuments": [{}]}
        services.return_value = table, s3, textract
        result = receipt_api.handler(event("POST", "/receipts", {
            "mimeType": "image/jpeg", "image": base64.b64encode(b"jpeg-image").decode(),
        }), None)

        self.assertEqual(result["statusCode"], 201)
        textract.analyze_expense.assert_called_once_with(Document={"Bytes": b"jpeg-image"})
        s3.put_object.assert_called_once()
        table.put_item.assert_called_once()

    @patch.dict(os.environ, {"ALLOWED_EMAILS": "someone@example.com"})
    @patch("receipt_api._services")
    def test_disallowed_email_is_rejected_before_aws_calls(self, services):
        result = receipt_api.handler(event("GET", "/receipts"), None)
        self.assertEqual(result["statusCode"], 403)
        services.assert_not_called()

    def test_response_serializes_decimal(self):
        body = json.loads(receipt_api.response(200, {"total": Decimal("123.5")})["body"])
        self.assertEqual(body["total"], 123.5)


if __name__ == "__main__":
    unittest.main()

