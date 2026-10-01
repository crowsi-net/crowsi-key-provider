# crowsi-key-provider

TPM 2.0、PKCS#11 HSM、Cloud HSM等の非exportable鍵をCrowsiから利用するための
閉じたPortです。アプリケーションは秘密鍵を受け取らず、完全に束縛された
32-byte digestだけを署名境界へ渡します。

用途はPA、checkpoint、PEP enforcement receipt、独立read-back report、
workload certificate issuance、certificate authority receipt、
certificate manager commit receipt、certificate manager handoff receipt、
release、rescue/recoveryで分離されます。
同じ鍵ID・鍵materialを別用途へ再利用しません。証明書用ではCA adapterが
固定profileから構築したTBS certificateのdigestだけを渡し、専用key IDと
`workload-certificate-issuance` purposeを使用します。
CA操作結果と照合結果の署名には、別のkey IDと
`certificate-authority-receipt` purposeを使用します。証明書署名鍵を
protocol receiptへ流用しません。
ManagerがPAへ返すDurable Commit Evidenceはさらに別のkey ID/materialと
`certificate-manager-commit-receipt` purposeを使い、CA receiptをManager commitの
代用にしません。
ManagerからPAへのhandoff receiptも4本目のkey ID/materialと
`certificate-manager-handoff-receipt` purposeを使います。commit proofと
PA handoff proofは相互に代用できません。
Role separationは任意の事前ヘルパーではありません。`KeyProvider::open`は
SQLite v5台帳に生成された256-bit `ledger_instance_id`と
`role_manifest_digest_sha256`を含むrole claimを作り、物理鍵側へ耐久的にsealします。
claimはSecurity Domain、deployment、workload、key ID/version、SPKI、purpose、
source、algorithm、ledger instance、role manifestを束縛します。すでに別claimへ
束縛された鍵は起動時に拒否され、独立Verifierによるclaim署名、公開鍵binding、
hardware seal、durable counterの検証が揃わなければProviderを構築できません。

Wire応答は`crowsi://keys/signing-response/v2`です。Algorithmは
`ecdsa-p256-sha256-p1363-low-s`だけを許可し、独立Verifierがcanonical
IEEE P1363 encodingとlow-Sを検証した64-byte署名だけを返します。従来の
可変長v1応答として扱ってはなりません。

このcrateはハードウェアを偽装するsoftware fallbackを本番用に提供しません。
実Adapterはvendor attestation chain、専用OS identity、認証済みIPC、rate limit、
監査journalを個別に検証してから接続します。

Hardware key Portは署名結果を自己検証できません。Attestationはcanonical SPKIの
SHA-256とkey versionを含み、Policyへpinします。別の
`IndependentKeyVerifier`がvendor chainとその公開鍵bindingを検証した後、同じ
SPKIで署名を検証します。Attestした鍵と署名鍵の置換、暗黙rotation、同一key IDの
別versionはfail closedです。

各attestationは、request ID/nonce、署名digest、用途、key version、canonical
SPKI digest、verifier key、trust revision、短い有効期間を束縛したchallengeへ
vendor鍵で署名したbounded envelopeです。Portの自己申告は信頼せず、独立Verifierが
署名chain、challenge、公開鍵binding、envelopeから導出したfieldを確認します。
生のvendor evidenceはCoelaや呼出サービスの監査ログへ記録せず、応答を保持する場合も
owner-only領域に限定します。

`SqliteReplayLedger`はowner-onlyの耐久参照実装です。署名直前にRequest ID、
client Nonce、256-bit server challengeと、完全なrequest/policy binding、
台帳IDとrequest bindingから一意に導出したhardware operation IDを一つの
transactionで予約します。
DBはdomain、deployment、workload、key ID/version、SPKI、purpose、algorithm、
attestation verifier/trust revision、sign/recovery TTL policyへ固定され、別境界への再利用を
fail closedにします。不明な実行結果も
消費済みのまま保持し、自動再署名を許しません。`recover`は完了済みjournalを
読むか、同じoperation IDをhardwareからread backするだけです。adapterが
readbackを保証できない場合は`RecoveryUnsupported`で停止します。
元requestの期限後も、attemptへ固定したbounded recovery deadline内だけは
exact resultを解決できます。新規署名のfreshnessを緩和するものではありません。
hardware adapterは、role claimごとの単調増加fenceを使ってoperationをCASします。
新規claimだけが署名を許され、同一operationがすでに存在する場合は厳密一致の
readbackだけを許します。SQLiteファイルを複製しても、別requestや古いcounterで
再署名できません。同じrequestの競合は、最大1回の署名と同一結果のreadbackへ
収束します。

hardware claim後・DB fence更新前に停止した場合は、次回起動をrecovery-onlyに
限定します。hardwareがDBより1だけ先行する場合に限り、台帳に残る同一operationの
readbackと独立署名検証によって同期できます。結果不明時の自動再署名は行いません。
hardwareが2以上先行する場合、counterが後退した場合、claimや署名が変わった場合は
fail closedです。
Manager adapterはcanonical commit/handoff draftのdigest、request ID、nonceを
同じ`SigningRequestV1`へ固定し、初回だけ`sign`、不明結果には同一requestで
`recover`を呼びます。commitとhandoffはこの回復契約を共有しますが、
異なるpurpose・key policy・SQLite DBを使用します。
絶対path、非symlink、
同一owner、非共有書込みparent、既存0600 fileを必須とし、時刻watermarkも
同じSQLiteへ保存して再起動後の巻戻りを拒否します。

Role claimとhardware fence追加によりDB schemaはv5です。v4以前を暗黙変換せず、versionまたは
DDLが違えば起動を拒否します。運用移行では旧DBを退役させ、未解決attemptがない
ことを独立確認したうえで、新しいowner-only DBを作成します。

署名時刻はRequest呼出側から受け取らず、Signing Serviceが所有する
`TrustedClock`から取得します。Host clockを使う場合もSQLite watermarkで巻戻りを
拒否し、本番ではTPM/HSMまたは外部rollback anchorも組み合わせます。

## Production adapter gap

このcrateは契約、台帳、検証順序を実装しますが、実TPM 2.0、PKCS#11、Cloud HSM
adapterはまだ提供しません。production adapterは、role claimのhardware seal、
署名付きbinding evidence、永続operation CAS、counter、exact readbackを実装し、
別実装の`IndependentKeyVerifier`で検証できる必要があります。未実装の環境を
software鍵へfallbackしてはならず、`KeyProvider::open`を失敗させます。
