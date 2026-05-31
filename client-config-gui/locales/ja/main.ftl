# TapAuth Configuration GUI – 日本語 (ja) Fluent Localization
# locale-name: 日本語

# ── Application ──
app-title = TapAuth 設定

# ── Button Labels ──
btn-back = 戻る
btn-cancel = キャンセル
btn-done = 完了
btn-confirm = 確認
btn-remove = 削除
btn-pair-new-device = 新しいデバイスをペアリング
btn-manage-devices = デバイスを管理
btn-settings = 設定
btn-save-config = 設定を保存
btn-rotate-csk = クライアント対称鍵をローテーション
btn-recover-keys = 鍵を復元（ペアリングはクリアされます）

# ── Status Labels ──
label-please-wait = お待ちください
label-rotating = ローテーション中…
label-recovering = 復元中…
label-recovery-success = 復元に成功しました！デーモンを再起動し、デバイスを再ペアリングしてください。
label-recovery-failed = 復元に失敗しました: {$error}
label-tpm-error =  {$error}

# ── Page Titles ──
title-main-menu = TapAuth 設定
title-paired-devices = ペアリング済みデバイス
title-settings = 設定

# ── Pairing Screen ──
pairing-title = デバイスペアリング
pairing-preparing = ペアリング準備中…
pairing-verify-sas-title = セキュリティコードを確認
pairing-compare-code = このコードをコンピューターに表示されているコードと比較してください：
pairing-sas-ensure-match = デバイスにこのコードが一致していることを確認してください：
pairing-completing = ペアリングを完了中…
pairing-success = ペアリング成功！
pairing-failed = ペアリング失敗
pairing-scan-qr = スマートフォンでこのQRコードをスキャンしてください
pairing-enter-manually = または手動で入力：
pairing-device-id = デバイスID: {$device_id}

# ── Device List Screen ──
devices-none-for-user = 現在のユーザーにはペアリング済みデバイスがありません
devices-current-user = 現在のユーザー: {$username}
devices-users-list = ユーザー: {$users}{$info}
devices-shared-info =  （{$count}人の他のユーザー{$s}と共有）
devices-id-truncated = ID: {$prefix}…{$suffix}

# ── Settings Screen ──
settings-config-section = 設定
settings-hostname-label = ホスト名:
settings-hostname-placeholder = ホスト名を入力
settings-udp-port-label = UDPポート:
settings-udp-port-placeholder = UDPポートを入力（デフォルト: 36692）
settings-security-section = セキュリティ
settings-language-section = 言語
settings-csk-warning = 警告：CSKをローテーションすると、すべてのペアリング済みデバイスが無効になります。
    再ペアリングが必要です。
settings-config-saved = 設定が正常に保存されました。
settings-csk-rotated = CSKが正常にローテーションされました。すべてのペアリングがクリアされました。
settings-error-prefix = エラー: {$message}
settings-invalid-port = 無効なポート番号（1-65535である必要があります）

# ── IPC Errors ──
error-ipc-connection-timeout = デーモンへの接続がタイムアウトしました。tapauthdは実行中ですか？
error-ipc-connection-failed = デーモンに接続できませんでした: {$detail}
error-ipc-send-timeout = リクエストの送信がタイムアウトしました
error-ipc-send-failed = リクエストの送信に失敗しました: {$detail}
error-ipc-response-timeout = デーモンが時間内に応答しませんでした
error-ipc-read-failed = 応答の読み取りに失敗しました: {$detail}
error-ipc-decode-failed = 応答のデコードに失敗しました: {$detail}
error-ipc-unexpected-envelope = デーモンが予期しない応答を返しました
error-ipc-unexpected-response = デーモンからの予期しない応答

# ── System Error/Warning Dialogs ──
error-user-missing-title = システムユーザーが見つかりません
error-user-missing-message = システムユーザー 'tapauthd' が必要ですが、見つかりませんでした。

    このユーザーはインストール時に作成されるはずです。

    推奨される対応：
    1. ログアウトして再度ログインする（またはシステムを再起動する）
    2. アプリケーションを再度起動してみる

    問題が解決しない場合は、手動でユーザーを作成する必要があります：
        sudo useradd --system --no-create-home tapauthd

error-group-missing-title = システムグループが見つかりません
error-group-missing-message = システムグループ 'tapauthd-clients' が必要ですが、見つかりませんでした。

    このグループはインストール時に作成されるはずです。

    推奨される対応：
    1. アプリケーションを再インストールして、システムグループが正しく設定されていることを確認してください
    2. または、手動でグループを作成してください：
        sudo groupadd --system tapauthd-clients

warn-group-missing-title = グループメンバーシップが必要です
warn-group-missing-message = 'tapauthd-clients' グループのメンバーではありません。
    このメンバーシップがないと、TapAuthデーモンと通信できません。

    グループに自分を追加するには、ターミナルで次のコマンドを実行してください：
        sudo usermod -aG tapauthd-clients $USER

    その後、変更を有効にするためにログアウトして再度ログインしてください。
    （現在のセッションで 'newgrp tapauthd-clients' を実行することもできます）
