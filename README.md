# Takoyaki3 Receipt

スマートフォンのカメラでレシートを撮影し、Gemini `gemini-3.7-flash` の画像理解と構造化出力で解析して、購入記録をユーザー別に保存する Web アプリです。`takoyaki3-home` と同じく `takoyaki3-auth` が発行する Firebase JWT を使用します。

## できること

- スマートフォン／PC カメラで撮影、または画像ファイルを選択
- 店名、購入日、住所、電話番号、小計、税、合計、支払方法を自動抽出
- 商品名、数量、単価、金額を全明細から抽出
- 原画像、OCR 原文、解析信頼度を記録
- 月別の支出・レシート枚数・品目数を集計
- 店名・品目検索、解析結果の手動修正、品目追加・削除
- レシート画像と記録の削除

## 構成

- Web: S3 + CloudFront（静的 HTML/CSS/JavaScript）
- API: API Gateway REST API + Python 3.12 Lambda
- 画像認識: Gemini Developer API `gemini-3.7-flash`（画像入力 + JSON Schema構造化出力）
- データ: DynamoDB（ユーザー ID + レシート ID）
- 原画像: 非公開 S3（詳細表示時だけ5分間の署名付き URL を発行）
- 認証: Firebase JWT Lambda Authorizer
- IaC: AWS CDK (TypeScript)

ブラウザは `https://takoyaki3-auth.web.app/?r=<このアプリのURL>` へ移動します。認証後に返る `?jwt=...` をメモリへ取り込み、すぐ URL から除去します。トークンは localStorage / sessionStorage に保存しません。API が 401 を返した場合は再認証します。さらに `AllowedEmails` で許可された、メール確認済みのユーザーだけがデータへアクセスできます。

## ローカル検証

Node.js 24、Python 3.12、AWS CDK CLI を使用します。

```powershell
npm install
npm run build
npm test
npm run synth
```

UI の見た目だけ確認する場合は `web` ディレクトリを任意の静的 HTTP サーバーで配信してください。認証・API 呼び出しにはデプロイ済み環境が必要です。

## デプロイ

```powershell
npx cdk bootstrap
npx cdk deploy Takoyaki3ReceiptStack `
  --parameters "AllowedEmails=owner@example.com,family@example.com" `
  --parameters "GeminiApiKey=YOUR_GEMINI_API_KEY"
```

Firebase プロジェクトを変更する場合は `--parameters FirebaseProjectId=...` も指定します。デプロイ後の `WebUrl` を、必要に応じて `takoyaki3-auth` 側のリダイレクト許可先へ登録してください。

GitHub Actions では次の Repository Secrets が必要です。

- `AWS_ROLE_ARN`: GitHub OIDC から引き受けるデプロイ用 IAM Role
- `ALLOWED_EMAILS`: 利用を許可するメールアドレス（カンマ区切り）
- `GEMINI_API_KEY`: Gemini Developer API の API キー

## データ保護と制約

- DynamoDB はポイントインタイムリカバリ、画像 S3 はバージョニングを有効化しています。
- スタック削除時もデータ用 DynamoDB/S3 は保持されます。
- 画像はブラウザで長辺 1800px、4.5MB 以下の JPEG に圧縮します。
- API Gateway の同期処理時間内に解析するため、通常の1枚もののレシートを対象とします。
- Gemini の結果は誤認識を含む可能性があるため、保存後の詳細画面で確認・修正してください。
- Gemini API キーは `NoEcho` の CloudFormation パラメータとして受け取り、ブラウザへは配信せず Lambda だけで使用します。
