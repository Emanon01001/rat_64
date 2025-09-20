# rat_64

クロスプラットフォーム対応のシステム情報収集・暗号化ツール

## 機能概要

このツールは、システムの詳細情報を収集し、暗号化して安全に保存・送信するためのRustアプリケーションです。

### 収集される情報
- **システム情報**: ホスト名、OS情報、ユーザー名、プロセッサ情報、CPUコア数
- **ネットワーク情報**: ローカルIP、グローバルIP、国コード
- **セキュリティ情報**: インストール済みセキュリティソフトウェア（Windows限定）
- **視覚情報**: スクリーンショット、Webカメラ画像（オプション）

### セキュリティ機能
- **AES-256-GCM暗号化**: 軍事グレードの暗号化でデータ保護
- **ランダムキー生成**: 各実行で新しい32バイトキーを生成
- **MessagePack形式**: 効率的なバイナリシリアライゼーション
- **Base64エンコーディング**: 安全なデータ転送

## ビルド方法

### 基本機能のみ（推奨）

```bash
cargo build --release
```

### Webカメラ機能を含む場合

Webカメラ機能を使用する場合は、事前にOpenCVとLLVM/Clangの環境設定が必要です：

**Windows:**
1. Visual Studio Build Tools または Visual Studio をインストール
2. LLVM をインストール (https://releases.llvm.org/download.html)
3. 環境変数を設定:
   - `LIBCLANG_PATH`: clang.dll のパス（例: `C:\Program Files\LLVM\bin`）
   - `LLVM_CONFIG_PATH`: llvm-config.exe のパス

**macOS:**
```bash
brew install llvm opencv
export LIBCLANG_PATH="/opt/homebrew/opt/llvm/lib"
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install llvm-dev libclang-dev libopencv-dev
```

その後、webcam機能を有効にしてビルド：
```bash
cargo build --release --features webcam
```

## 使用方法

### 1. データ収集・暗号化（メインプログラム）

```bash
# デバッグ版で実行
cargo run

# リリース版でビルドして実行
cargo build --release
./target/release/rat_64
```

**実行結果:**
- `data.dat` - 暗号化されたシステム情報と画像データ
- GoFile.ioへの自動アップロード（設定済みの場合）

### 2. データ復号化・解析

```bash
# 復号化ツールをビルド
cargo build --bin decrypt

# 復号化実行
./target/debug/decrypt data.dat
```

**復号化結果:**
- システム情報の詳細表示
- `screenshot.png` - デスクトップスクリーンショット
- `webcam.png` - Webカメラ画像（取得された場合）

## 暗号化キーについて

### キーの生成と管理

**自動キー生成（デフォルト）:**
- 各実行時に新しい32バイトAES-256キーを生成
- 12バイトのnonceも同時に生成
- キーとnonceはデータファイル内に埋め込まれる

**キーの種類:**
```rust
// AES-256キー（32バイト）
let key: [u8; 32] = [/* ランダム生成 */];

// Nonce（12バイト）- 暗号化の初期化ベクター
let nonce: [u8; 12] = [/* ランダム生成 */];
```

### セキュリティレベル

**レベル1 - Base64エンコーディング（後方互換）:**
- 単純なBase64エンコーディング
- 復号化: `./target/debug/decrypt data.dat`

**レベル2 - AES-256-GCM暗号化（推奨）:**
- 軍事グレードAES-256暗号化
- 認証付き暗号化（改ざん検出）
- キー・nonce自動管理

### キーファイルの取り扱い

**外部キーファイル使用（オプション）:**
```bash
# 32バイトキーファイルを使用
./target/debug/decrypt data.dat my_key.key
```

**注意事項:**
- キーファイルは正確に32バイトである必要があります
- キーを紛失するとデータの復号化は不可能になります
- 実運用では適切なキー管理システムを使用してください

## 高度な使用例

### 1. Webカメラ機能付きでビルド

```bash
# OpenCV環境設定後
cargo build --release --features webcam
./target/release/rat_64
```

### 2. 暗号化データの検証

```bash
# データファイルの内容確認
file data.dat
hexdump -C data.dat | head

# 復号化して内容確認
./target/debug/decrypt data.dat
```

### 3. カスタムキー使用

```python
# キーファイル生成例（Python）
import os
key = os.urandom(32)
with open('custom_key.key', 'wb') as f:
    f.write(key)
```

```bash
# カスタムキーで復号化
./target/debug/decrypt data.dat custom_key.key
```

## データ形式仕様

### MessagePack構造
```json
{
    "info": "base64_encoded_encrypted_system_info",
    "images": "base64_encoded_encrypted_images",
    "key": "base64_encoded_aes_key",      // AES使用時
    "nonce": "base64_encoded_nonce"       // AES使用時
}
```

### システム情報構造
```rust
struct SystemInfo {
    hostname: String,           // コンピュータ名
    os_name: String,           // OS種類
    os_version: String,        // OSバージョン
    username: String,          // ユーザー名
    global_ip: String,         // 外部IP
    local_ip: String,          // 内部IP
    cores: usize,              // CPUコア数
    security_software: Vec<String>, // セキュリティソフト
    processor: String,         // CPU情報
    country_code: String,      // 国コード
}
```

## トラブルシューティング

### よくある問題

**OpenCVビルドエラー:**
```bash
# Windows: Visual Studio Build Tools必須
# macOS: brew install llvm opencv
# Linux: sudo apt install llvm-dev libclang-dev
```

**復号化エラー:**
- ファイルが破損していないか確認
- キーファイル長（32バイト）を確認
- Base64形式での復号化を試行

**スクリーンショット失敗:**
- Wayland環境では追加設定が必要
- 権限不足の可能性

## セキュリティ警告

⚠️ **重要:** このツールは教育・研究目的で開発されています。
- 本人の同意なしに他人のシステムで実行しないでください
- 収集したデータは適切に管理してください
- 法的責任は使用者にあります

## ライセンス

このプロジェクトは個人利用・教育目的での使用を想定しています。商用利用や悪用は禁止します。