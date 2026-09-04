# ICNativeClient OSS 公開レビュー台帳

## 対象と用語

- **content canister ID**: request content の `canister_id`。delegation の target 制約に用いる。
- **effective canister ID**: HTTP API の routing 対象。証明書の canister range 検証に用いる。
- **trust root**: replica 証明書の署名検証を開始する公開鍵。mainnet は固定値、その他は呼び出し側注入とする。
- **verified API**: 証明書または node signature を検証してから結果を返す API。
- **unsafe API**: query 応答を暗号学的に検証せず返すことを名前で明示した API。

## ユーザーストーリー

| ID | 経路 | 期待結果 | 初期状態 |
|---|---|---|---|
| US-001 | 設定を生成する | canister ID、HTTPS URL、origin、callback、TTL、trust root が不正なら生成を拒否する | PASS |
| US-002 | HTTP envelope/response を処理する | tag 55799 を付与し、末尾データ、重複キー、過剰入力を拒否する | PASS |
| US-003 | query を実行する | subnet 証明書と Ed25519 node signature を検証し、鍵を1時間キャッシュする | PASS |
| US-004 | update/read_state を実行する | BLS、hash tree、delegation、range、request ID、時刻を検証済みの結果だけ返す | PASS |
| US-005 | Internet Identity で認証する | state、origin、鍵binding、署名chain、期限、targets、permissions、上限を検証する | PASS |
| US-006 | セッションを保存・読込する | 秘密鍵を公開型から隠し、更新失敗時も旧セッションを保持し、障害をthrowする | PASS |
| US-007 | principal・account・amount・poll を入力する | 長さ・ASCII数字・subaccount・試行回数を境界で拒否する | PASS |
| US-008 | OSS利用者が導入・報告する | LICENSE、notice、security、contribution、CI、移行・安全性文書が揃う | PASS |

## 発見事項と修正記録

| Finding | 優先度 | 根拠 | 状態 | 修正・再テスト |
|---|---:|---|---|---|
| F-001 read_state 証明書を未検証で信頼する | P0 | `ICClient.poll`、`ICCertificateVerifier` | RESOLVED | BLS・hash tree・request ID・時刻を検証 |
| F-002 query node signature を検証しない | P0 | `ICClient.queryRaw` | RESOLVED | certified subnet keyでEd25519署名を検証 |
| F-003 CBOR が非厳格で envelope tag がない | P1 | `ICCBOR` | RESOLVED | strict decoderとself-describe tagを追加 |
| F-004 delegation signature とchain制約が未検証 | P0 | `ICRC167Codec`、`ICIdentityValidation` | RESOLVED | Ed25519/canister signature、一段・二段chain、期限、target、permissions、循環・件数上限を検証 |
| F-005 session秘密鍵が公開 `Codable` APIに露出する | P1 | `ICAuthSession` | RESOLVED | 公開型から秘密鍵とCodable準拠を除外 |
| F-006 Keychain save が旧値を先に削除し load 障害を隠す | P1 | `ICIdentityStore` | RESOLVED | update-first保存、失敗時の旧値保持、未登録以外の読込障害throwを実装 |
| F-007 URL force unwrap と入力境界不足 | P2 | `Configuration`、authenticator、`Primitives`、`poll` | RESOLVED | throwing validationと上限検査を追加 |
| F-008 OSS公開物とCIが不足する | P1 | リポジトリ直下・`.github` | RESOLVED | LICENSE、notice、security、contribution、CIを追加 |
| F-009 公開0.3.0の認証制御が未統合 | P1 | `ICInternetIdentityAuthenticator` | RESOLVED | 330秒timeout、Task cancellation、明示callback path、shared/ephemeral browser選択、base64 URL transportを0.4.0へ統合 |

## 検証結果

- `qrun -- swift test --disable-sandbox`: PASS（31 macOS tests、0 failures）
- `qrun -- swift build -Xswiftc -swift-version -Xswiftc 6 -Xswiftc -strict-concurrency=complete -Xswiftc -warnings-as-errors`: PASS
- `xcodebuild -scheme ICNativeClient -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build`: PASS
- 実iOS Simulator上の `xcodebuild test`: PASS（0.3.0由来のiOS CI経路を再現）
- BLS 100回検証: 約0.08秒（ローカルdebug test、環境依存）
- 同一subnetの連続query: certified key取得1回。署名失敗時: 強制再取得1回で停止。PASS
- ICRC-167 Ed25519/canister signature、一段・二段chain、8時間既定TTL・明示指定最大30日をunit testで確認済み

## 未実施・外部確認が必要な項目

- 実運用Internet Identity、Associated Domains、AASAを組み合わせた物理iOS端末E2Eは、署名済みアプリ・公開callback origin・実ユーザー操作が必要なため未実施。公開前に実機で確認する。
- agent-rs由来のmainnet delegated-certificate fixtureでBLS、hash tree、subnet delegation、canister rangeの相互運用を確認済み。query node signatureはローカル生成vectorで改ざん・cache・一回refreshを確認したが、外部実装が生成した有効署名vectorによる相互運用確認は未実施。

## 計画からの仕様差分

- `internetIdentityURL` の既定値は、legacy hash routeの `https://id.ai/#authorize` ではなく、現行のdirect ICRC-167 endpointである `https://id.ai/authorize` とした。ICRC-167 payload自体をURL fragmentへ格納するため、legacy `#authorize`を既定fragmentとして併用すると上書きされる。validatorもHTTPS `/authorize` endpointだけを受理する。

## リポジトリ外の手動作業

- 公開前にGitHubの **Private Vulnerability Reporting** を有効化し、報告導線を確認する。
