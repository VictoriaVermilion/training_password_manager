import flet as ft
import password_manager_core
import os
import configparser


def master_password_setup_ui(page: ft.Page):
    page.title = "マスターパスワード設定"
    page.vertical_alignment = ft.MainAxisAlignment.START

    # デフォルト設定iniファイルを作成（初回起動時）
    _create_default_settings_ini()

    info_text = ft.Text(
        "マスターパスワードを12文字以上で設定してください。このパスワードはパスワードマネージャーの"
        "全てのデータを保護するために使用されます。忘れないように注意してください。"
    )

    password_input = ft.TextField(
        label="マスターパスワード",
        width=400,
        password=True,
        can_reveal_password=True,
    )

    confirm_password_input = ft.TextField(
        label="マスターパスワード（確認）",
        width=400,
        password=True,
        can_reveal_password=True,
    )

    error_message = ft.Text(color=ft.Colors.RED)

    def set_master_password(e):
        pwd = password_input.value
        confirm_pwd = confirm_password_input.value

        if pwd != confirm_pwd:
            error_message.value = "エラー: パスワードが一致しません。"
            page.update()
            return

        if len(pwd) < 12:
            error_message.value = (
                "エラー: マスターパスワードは12文字以上である必要があります。"
            )
            page.update()
            return

        # マスターパスワードを保存
        password_manager_core.hash_master_password(pwd)

        # コールバックを呼び出してメインUIに遷移
        if master_password_verified_callback:
            master_password_verified_callback(pwd)

    set_password_button = ft.ElevatedButton(
        text="マスターパスワードを設定", on_click=set_master_password
    )

    page.add(
        info_text,
        password_input,
        confirm_password_input,
        set_password_button,
        error_message,
    )


def master_password_input_ui(page: ft.Page):
    page.title = "マスターパスワード入力"
    page.vertical_alignment = ft.MainAxisAlignment.START

    info_text = ft.Text(
        "マスターパスワードを入力してください。正しいパスワードを入力すると、"
        "パスワード管理UIにアクセスできます。"
    )

    password_input = ft.TextField(
        label="マスターパスワード",
        width=400,
        password=True,
        can_reveal_password=True,
    )

    error_message = ft.Text(color=ft.Colors.RED)

    def verify_master_password(e):
        pwd = password_input.value

        if password_manager_core.verify_master_password(pwd):
            # マスターパスワードが正しい場合のコールバックを呼び出す
            if master_password_verified_callback:
                master_password_verified_callback(pwd)  # pwdを引数として渡す
        else:
            error_message.value = "エラー: マスターパスワードが正しくありません。"
            page.update()

    verify_password_button = ft.ElevatedButton(
        text="マスターパスワードを確認", on_click=verify_master_password
    )

    page.add(
        info_text,
        password_input,
        verify_password_button,
        error_message,
    )


master_password_verified_callback = None


def set_master_password_verified_callback(callback):
    global master_password_verified_callback
    master_password_verified_callback = callback


def _create_default_settings_ini():
    """初回起動時にデフォルト Argon2 設定を含む settings.ini を作成"""
    settings_path = os.path.join("password_file", "settings.ini")
    if os.path.exists(settings_path):
        return  # 既に存在する場合は作成しない

    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg["argon2"] = {
        "memory_cost": "102400",
        "time_cost": "2",
        "parallelism": "8",
    }
    cfg["file_paths"] = {
        "password_file": "password_file\\passwords.txt",
    }
    try:
        with open(settings_path, "w", encoding="utf-8") as f:
            cfg.write(f)
    except Exception as ex:
        print(f"警告: デフォルト settings.ini の作成に失敗しました: {ex}")
