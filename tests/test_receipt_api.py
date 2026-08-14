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
        model_result = {
            "storeName": "たこやき商店", "purchasedAt": "2026-08-14", "address": "東京都",
            "phone": "03-0000-0000", "subtotal": 1164, "tax": 116, "total": 1280,
            "currency": "JPY", "paymentMethod": "現金", "confidence": 97.5,
            "rawText": "たこやき商店\nたこ焼き 2点 1,200",
            "items": [{
                "name": "たこ焼き", "quantity": 2, "unitPrice": 600, "price": 1200,
                "productCode": "A01", "discount": None, "taxRate": "10%", "confidence": 98,
            }],
        }
        document = {"candidates": [{"content": {"parts": [{"text": json.dumps(model_result)}]}}]}

        result = receipt_api.parse_gemini_response(document)

        self.assertEqual(result["storeName"], "たこやき商店")
        self.assertEqual(result["total"], Decimal("1280"))
        self.assertEqual(result["tax"], Decimal("116"))
        self.assertEqual(result["items"][0]["quantity"], Decimal("2"))
        self.assertEqual(result["items"][0]["price"], Decimal("1200"))
        self.assertEqual(result["items"][0]["unitPrice"], Decimal("600"))
        self.assertIn("たこやき商店", result["rawText"])

    def test_rejects_document_without_expense(self):
        with self.assertRaisesRegex(ValueError, "解析結果を取得できません"):
            receipt_api.parse_gemini_response({"candidates": []})

    @patch.dict(os.environ, {"GEMINI_API_KEY": "secret-key", "GEMINI_MODEL": "gemini-3.7-flash"})
    @patch("receipt_api.urlopen")
    def test_gemini_request_uses_requested_model_image_and_schema(self, urlopen):
        model_result = {
            "storeName": "店", "purchasedAt": "", "address": "", "phone": "",
            "subtotal": None, "tax": None, "total": 500, "currency": "JPY",
            "paymentMethod": "", "items": [], "confidence": 95, "rawText": "店",
        }
        api_response = {"candidates": [{"content": {"parts": [{"text": json.dumps(model_result)}]}}]}
        urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(api_response).encode()

        receipt_api.analyze_receipt(b"image", "image/jpeg")

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data)
        self.assertIn("gemini-3.7-flash:generateContent", request.full_url)
        self.assertEqual(request.get_header("X-goog-api-key"), "secret-key")
        self.assertEqual(payload["contents"][0]["parts"][1]["inline_data"]["mime_type"], "image/jpeg")
        self.assertEqual(payload["generationConfig"]["responseFormat"]["text"]["mimeType"], "application/json")


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
    @patch("receipt_api.analyze_receipt", return_value={"storeName": "店", "items": [], "itemCount": 0, "total": Decimal("500")})
    def test_upload_analyzes_and_stores_receipt(self, analyze, services):
        table, s3 = MagicMock(), MagicMock()
        services.return_value = table, s3
        result = receipt_api.handler(event("POST", "/receipts", {
            "mimeType": "image/jpeg", "image": base64.b64encode(b"jpeg-image").decode(),
        }), None)

        self.assertEqual(result["statusCode"], 201)
        analyze.assert_called_once_with(b"jpeg-image", "image/jpeg")
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
