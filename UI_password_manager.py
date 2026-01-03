import flet as ft
import os
import password_manager_core
import time
import secrets
import threading
import configparser
import csv
import io


async def main_ui(page: ft.Page, master_password: str):
    page.title = "パスワードマネージャー"
    page.vertical_alignment = ft.MainAxisAlignment.START

    # --- アプリケーションの状態管理 ---
    # メモリ上に全パスワード情報を保持するリスト
    all_passwords = []

    # UIの初期化時に、マスターパスワードで復号して全データを読み込む
    try:
        all_passwords = password_manager_core.get_decrypted_passwords(master_password)
    except Exception as e:
        page.add(
            ft.Text(
                f"エラー: パスワードファイルの読み込みに失敗しました: {e}",
                color=ft.Colors.RED,
            )
        )
        return

    password_notice = ft.Text(
        "最小長さ～最大長さの範囲でランダムで生成されます。"
        "固定の文字数のパスワードを生成したい場合は、最小長さと最大長さを同じにしてください。"
    )

    # ========== 状態管理とコア機能 ==========
    error_message = ft.Text(color=ft.Colors.RED)
    time_counter = ft.Text()
    error_message_tab2 = ft.Text(color=ft.Colors.RED)
    time_counter_tab2 = ft.Text()
    error_message_tab3 = ft.Text(color=ft.Colors.RED)
    time_counter_tab3 = ft.Text()

    clipboard_clear_thread = None

    password_list_view = ft.ListView(expand=True, spacing=10, padding=10)

    def save_all_passwords_to_file():
        """メモリ上のall_passwordsを暗号化してファイルにアトミックに保存する（CSV形式、totp_secret含む）"""
        try:
            buf = io.StringIO()
            writer = csv.writer(buf)
            for p in all_passwords:
                writer.writerow(
                    [
                        p.get("service_name", ""),
                        p.get("username", ""),
                        p.get("password", ""),
                        p.get("totp_secret", ""),
                    ]
                )
            content_string = buf.getvalue()
            content_bytes = content_string.encode("utf-8")
            password_manager_core.encrypt_password_file(content_bytes, master_password)
            return True
        except Exception as e:
            msg = f"エラー: 保存に失敗しました: {e}"
            error_message.value = msg
            error_message_tab2.value = msg
            page.update()
            return False

    def refresh_password_list():
        """メモリ上のall_passwordsを元にパスワードリストUIを更新"""
        password_list_view.controls.clear()
        if not all_passwords:
            password_list_view.controls.append(
                ft.Text("登録されたパスワードはありません。", color=ft.Colors.GREY)
            )
        else:
            for idx, p in enumerate(all_passwords):
                # (UIコンポーネントの作成ロジックは変更なし)
                service_text = ft.Text(f"サービス名: {p['service_name']}")
                username_text = ft.Text(
                    f"ユーザー名: {p['username']}",
                    color=ft.Colors.BLUE,
                    weight=ft.FontWeight.BOLD,
                )
                username_detector = ft.GestureDetector(
                    content=username_text,
                    on_tap=lambda e, user=p["username"]: on_double_click(user),
                )
                password_text = ft.Text(
                    f"パスワード: {'*' * len(p['password'])}",
                    color=ft.Colors.RED,
                    weight=ft.FontWeight.BOLD,
                )
                password_detector = ft.GestureDetector(
                    content=password_text,
                    on_tap=lambda e, pwd=p["password"]: on_double_click(pwd),
                )
                menu_button = ft.PopupMenuButton(
                    icon=ft.Icons.MORE_VERT,
                    tooltip="メニュー",
                    items=[
                        ft.PopupMenuItem(
                            text="編集",
                            icon=ft.Icons.EDIT,
                            on_click=lambda e, i=idx, item=p: open_edit_dialog(i, item),
                        ),
                        ft.PopupMenuItem(
                            text="削除",
                            icon=ft.Icons.DELETE,
                            on_click=lambda e, i=idx, item=p: open_delete_dialog(
                                i, item
                            ),
                        ),
                    ],
                )
                password_list_view.controls.append(service_text)
                password_list_view.controls.append(
                    ft.Row(
                        controls=[username_detector, menu_button],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    )
                )
                password_list_view.controls.append(password_detector)

                # TOTP 表示: シークレットが設定されていればコードを生成してコピーできる
                totp_secret = p.get("totp_secret", "")

                def make_copy_totp(secret):
                    def _handler(e):
                        try:
                            code = password_manager_core.generate_totp_code(secret)
                            page.set_clipboard(code)
                            clear_clipboard_sync(code, 10)
                        except Exception as ex:
                            error_message_tab2.value = (
                                f"TOTP の生成に失敗しました: {ex}"
                            )
                            page.update()

                    return _handler

                if totp_secret:
                    # シークレットの妥当性を確認して表示を決める（無効なら例外を捕捉して無効表示）
                    try:
                        code = password_manager_core.generate_totp_code(totp_secret)
                        totp_row = ft.Row(
                            controls=[
                                ft.Text("TOTP: ", weight=ft.FontWeight.BOLD),
                                ft.ElevatedButton(
                                    text="コードをコピー",
                                    on_click=make_copy_totp(totp_secret),
                                ),
                            ],
                            spacing=10,
                        )
                    except Exception:
                        # 無効なシークレット
                        totp_row = ft.Row(
                            controls=[
                                ft.Text("TOTP: ", weight=ft.FontWeight.BOLD),
                                ft.Text("無効なシークレット", color=ft.Colors.GREY),
                                ft.ElevatedButton(text="コードをコピー", disabled=True),
                            ],
                            spacing=10,
                        )
                else:
                    totp_row = ft.Row(
                        controls=[
                            ft.Text("TOTP: 未設定", color=ft.Colors.GREY),
                            ft.ElevatedButton(text="コードをコピー", disabled=True),
                        ],
                        spacing=10,
                    )

                password_list_view.controls.append(totp_row)
                password_list_view.controls.append(ft.Divider())
        page.update()

    # ========== タブ1: パスワード生成 ==========
    service_name_input = ft.TextField(label="タイトル", width=400)
    username_input = ft.TextField(label="ユーザー名", width=400)
    min_length_input = ft.TextField(
        label="パスワードの最小長さ(12以上)", value="18", width=200
    )
    max_length_input = ft.TextField(label="パスワードの最大長さ", value="24", width=200)
    special_chars_checkbox = ft.Checkbox(label="特殊文字を使用する", value=True)
    password_output = ft.TextField(
        label="生成されたパスワード",
        width=400,
        password=True,
        can_reveal_password=True,
        read_only=True,
    )

    def generate_password(e):
        try:
            min_len, max_len = int(min_length_input.value), int(max_length_input.value)
            if min_len < 12 or max_len < 12:
                raise ValueError(
                    "パスワードの最小長さは12文字以上である必要があります。"
                )
            if min_len > max_len:
                raise ValueError("最小長さは最大長さ以下である必要があります。")
            length = secrets.choice(range(min_len, max_len + 1))
            password = password_manager_core.generate_secure_password(
                length, special_chars_checkbox.value
            )
            password_output.value = password
            error_message.value = ""
        except ValueError as ve:
            error_message.value = f"エラー: {ve}"
        page.update()

    def on_save_click(e):
        service_name, username, password = (
            service_name_input.value,
            username_input.value,
            password_output.value,
        )
        if not all([service_name, username, password]):
            error_message.value = (
                "エラー: タイトル、ユーザー名、パスワードを入力してください。"
            )
            page.update()
            return

        all_passwords.append(
            {
                "service_name": service_name,
                "username": username,
                "password": password,
                "totp_secret": "",
            }
        )
        if save_all_passwords_to_file():
            msg = "パスワードを保存しました。"
            error_message.value = msg
            error_message_tab2.value = msg
            refresh_password_list()  # 保存後にリストを更新
        page.update()

    # ========== タブ2: 登録したパスワード ==========
    def on_double_click(text):
        nonlocal clipboard_clear_thread
        page.set_clipboard(text)
        clipboard_clear_thread = clear_clipboard_sync(text, 10)

    def open_edit_dialog(idx, item):
        service_edit = ft.TextField(value=item["service_name"], label="サービス名")
        username_edit = ft.TextField(value=item["username"], label="ユーザー名")
        password_edit = ft.TextField(
            value=item["password"],
            label="パスワード",
            password=True,
            can_reveal_password=True,
        )

        totp_edit = ft.TextField(
            value=item.get("totp_secret", ""),
            label="TOTP シークレットキー (任意)",
            width=400,
        )

        def on_save_edit(save_e):
            all_passwords[idx] = {
                "service_name": service_edit.value,
                "username": username_edit.value,
                "password": password_edit.value,
                "totp_secret": totp_edit.value,
            }
            if save_all_passwords_to_file():
                dlg.open = False
                error_message_tab2.value = "パスワードを編集しました。"
                page.update()
                refresh_password_list()

        def on_cancel_edit(cancel_e):
            dlg.open = False
            page.update()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("パスワードを編集"),
            content=ft.Column(
                controls=[service_edit, username_edit, password_edit, totp_edit],
                tight=True,
            ),
            actions=[
                ft.TextButton("保存", on_click=on_save_edit),
                ft.TextButton("キャンセル", on_click=on_cancel_edit),
            ],
        )
        page.dialog = dlg
        dlg.open = True
        page.add(dlg)
        page.update()

    def open_delete_dialog(idx, item):
        def on_confirm_delete(confirm_e):
            all_passwords.pop(idx)
            if save_all_passwords_to_file():
                confirm_dlg.open = False
                error_message_tab2.value = "パスワードを削除しました。"
                page.update()
                refresh_password_list()

        def on_cancel_delete(cancel_e):
            confirm_dlg.open = False
            page.update()

        confirm_dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("削除確認"),
            content=ft.Text(f"{item['service_name']} のパスワードを削除しますか？"),
            actions=[
                ft.TextButton("削除", on_click=on_confirm_delete),
                ft.TextButton("キャンセル", on_click=on_cancel_delete),
            ],
        )
        page.dialog = confirm_dlg
        confirm_dlg.open = True
        page.add(confirm_dlg)
        page.update()

    def on_tab_change(e):
        if e.control.selected_index == 1:
            refresh_password_list()

    # ========== クリップボード処理など ==========
    def clear_clipboard_sync(password, delay_seconds=10):
        def clear_task():
            try:
                for i in range(delay_seconds, 0, -1):
                    msg = f"クリップボードクリアまでの時間: {i}秒"
                    (
                        time_counter.value,
                        time_counter_tab2.value,
                        time_counter_tab3.value,
                    ) = msg, msg, msg
                    page.update()
                    time.sleep(1)
                page.set_clipboard("")
                msg = "クリップボードをクリアしました"
                time_counter.value, time_counter_tab2.value, time_counter_tab3.value = (
                    msg,
                    msg,
                    msg,
                )
                page.update()
            except Exception:
                pass

        thread = threading.Thread(target=clear_task, daemon=True)
        thread.start()
        return thread

    def on_copy_click(e):
        nonlocal clipboard_clear_thread
        page.set_clipboard(password_output.value)
        clipboard_clear_thread = clear_clipboard_sync(password_output.value, 10)

    generate_button = ft.ElevatedButton(
        text="パスワード生成", on_click=generate_password
    )
    copy_to_clipboard_button = ft.ElevatedButton(
        text="クリップボードにコピー", on_click=on_copy_click
    )
    save_button = ft.ElevatedButton(text="パスワードを保存", on_click=on_save_click)

    # タブ3: 設定画面
    # 暗号化のストレッチング回数などを設定できるようにする
    # 設定はiniファイルで書きだし、そこから読み込めるようにする

    # Argon2のmemory_cost,time_cost,parallelismを設定できる関数

    argon2_setting_text = ft.Text("Argon2の設定")

    argon2_memory_cost = ft.TextField(label="memory_cost", value="102400", width=400)
    argon2_time_cost = ft.TextField(label="time_cost", value="2", width=400)
    argon2_parallelism = ft.TextField(label="parallelism", value="8", width=400)

    error_message_tab3 = ft.Text(color=ft.Colors.RED)
    time_counter_tab3 = ft.Text()

    def load_argon2_settings():
        """password_file/settings.ini が存在すれば読み込んでフィールドに反映する"""
        settings_path = os.path.join("password_file", "settings.ini")
        if not os.path.exists(settings_path):
            return
        cfg = configparser.ConfigParser()
        try:
            cfg.read(settings_path, encoding="utf-8")
            if "argon2" in cfg:
                sec = cfg["argon2"]
                # 存在する値だけ上書き（strのまま）
                if "memory_cost" in sec:
                    argon2_memory_cost.value = sec.get(
                        "memory_cost", argon2_memory_cost.value
                    )
                if "time_cost" in sec:
                    argon2_time_cost.value = sec.get(
                        "time_cost", argon2_time_cost.value
                    )
                if "parallelism" in sec:
                    argon2_parallelism.value = sec.get(
                        "parallelism", argon2_parallelism.value
                    )
        except Exception as ex:
            # 読み込み失敗は警告表示に留める
            error_message_tab3.value = (
                f"警告: settings.ini の読み込みに失敗しました: {ex}"
            )
            page.update()

    # 起動時に設定を反映
    load_argon2_settings()

    # Argon2設定をiniファイルに出力する関数

    def save_argon2_settings(e):
        # 入力を検証し、password_file/settings.ini に保存する
        try:
            mem = int(argon2_memory_cost.value)
            tcost = int(argon2_time_cost.value)
            parallel = int(argon2_parallelism.value)
            if mem <= 0 or tcost <= 0 or parallel <= 0:
                raise ValueError("値は正の整数である必要があります。")
        except Exception as ex:
            error_message_tab3.value = f"エラー: 無効な Argon2 設定 - {ex}"
            page.update()
            return

        cfg = configparser.ConfigParser()
        cfg["argon2"] = {
            "memory_cost": str(mem),
            "time_cost": str(tcost),
            "parallelism": str(parallel),
        }

        try:
            os.makedirs(os.path.join(os.getcwd(), "password_file"), exist_ok=True)
            settings_path = os.path.join("password_file", "settings.ini")
            with open(settings_path, "w", encoding="utf-8") as f:
                cfg.write(f)

            error_message_tab3.value = f"Argon2 設定を保存しました: {settings_path}"
            page.update()

            # 設定が保存されたら、マスターパスワードの再ハッシュを促すダイアログを表示
            _show_rehash_confirmation_dialog(mem, tcost, parallel)
        except Exception as ex:
            error_message_tab3.value = f"エラー: 設定の保存に失敗しました。{ex}"
            page.update()

    argon2_button = ft.TextButton(
        text="Argon2設定を保存", on_click=save_argon2_settings
    )

    # Argon2 ハッシュ化テスト機能
    def show_argon2_test_dialog(e):
        """Argon2 パラメータのハッシュ化テストダイアログを表示"""
        # ランダムで24字程度のパスワードを生成
        test_password_value = password_manager_core.generate_secure_password(24)
        test_result_display = ft.Column(
            controls=[],
            tight=True,
        )

        def on_run_test(test_e):
            test_result_display.controls.clear()
            pwd = test_password_value

            try:
                mem = int(argon2_memory_cost.value)
                tcost = int(argon2_time_cost.value)
                parallel = int(argon2_parallelism.value)
                if mem <= 0 or tcost <= 0 or parallel <= 0:
                    raise ValueError(
                        "Argon2 のパラメータは正の整数である必要があります。"
                    )
            except Exception as ex:
                test_result_display.controls.append(
                    ft.Text(
                        f"エラー: Argon2 パラメータが不正です: {ex}",
                        color=ft.Colors.RED,
                    )
                )
                page.update()
                return

            # テスト実行
            test_result_display.controls.append(
                ft.Text("テスト実行中...", color=ft.Colors.BLUE)
            )
            page.update()

            result = password_manager_core.test_argon2_hash(
                pwd, m=mem, t=tcost, p=parallel
            )

            test_result_display.controls.clear()
            if result["success"]:
                test_result_display.controls.extend(
                    [
                        ft.Text(
                            "✓ テスト成功",
                            color=ft.Colors.GREEN,
                            size=16,
                            weight=ft.FontWeight.BOLD,
                        ),
                        ft.Text(
                            f"実行時間: {result['execution_time']:.3f} 秒", size=14
                        ),
                        ft.Divider(),
                    ]
                )
            else:
                test_result_display.controls.append(
                    ft.Text(
                        f"✗ テスト失敗\n実行時間: {result['execution_time']:.3f} 秒\nエラー: {result['error']}",
                        color=ft.Colors.RED,
                    )
                )
            page.update()

        def on_cancel_test(cancel_e):
            test_dlg.open = False
            page.update()

        test_dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Argon2 ハッシュ化テスト"),
            content=ft.Column(
                controls=[
                    ft.Text(
                        "現在の Argon2 パラメータでハッシュ化テストを実行します。\n"
                    ),
                    ft.Text("0.5秒以上かかるように設定することが推奨されます。\n"),
                    ft.Divider(),
                    ft.ElevatedButton(
                        text="テスト実行",
                        on_click=on_run_test,
                    ),
                    ft.Divider(),
                    test_result_display,
                ],
                scroll=ft.ScrollMode.AUTO,
                tight=True,
            ),
            actions=[
                ft.TextButton("閉じる", on_click=on_cancel_test),
            ],
        )
        page.dialog = test_dlg
        test_dlg.open = True
        page.add(test_dlg)
        page.update()

    argon2_test_button = ft.TextButton(
        text="ハッシュ化テスト実行", on_click=show_argon2_test_dialog
    )

    master_password_text = ft.Text("マスターパスワードの設定")

    def open_change_master_password_dialog(e):
        """マスターパスワード変更ダイアログを表示する"""
        current_pwd = ft.TextField(
            label="現在のマスターパスワード",
            width=400,
            password=True,
            can_reveal_password=True,
        )
        new_pwd = ft.TextField(
            label="新しいマスターパスワード",
            width=400,
            password=True,
            can_reveal_password=True,
        )
        confirm_pwd = ft.TextField(
            label="新しいマスターパスワード（確認）",
            width=400,
            password=True,
            can_reveal_password=True,
        )
        dlg_error = ft.Text(color=ft.Colors.RED)

        def on_save_master(e_save):
            # 現在のパスワード確認
            if not password_manager_core.verify_master_password(current_pwd.value):
                dlg_error.value = "エラー: 現在のマスターパスワードが正しくありません。"
                page.update()
                return
            # 新しいパスワード確認
            if new_pwd.value != confirm_pwd.value:
                dlg_error.value = "エラー: 新しいパスワードが一致しません。"
                page.update()
                return
            if len(new_pwd.value) < 12:
                dlg_error.value = (
                    "エラー: マスターパスワードは12文字以上である必要があります。"
                )
                page.update()
                return

            # Argon2 パラメータを UI から取得して検証
            try:
                mem = int(argon2_memory_cost.value)
                tcost = int(argon2_time_cost.value)
                parallel = int(argon2_parallelism.value)
                if mem <= 0 or tcost <= 0 or parallel <= 0:
                    raise ValueError(
                        "Argon2 のパラメータは正の整数である必要があります。"
                    )
            except Exception as ex:
                dlg_error.value = f"エラー: Argon2 パラメータが不正です: {ex}"
                page.update()
                return

            # ハッシュを指定パラメータで更新
            password_manager_core.hash_master_password(
                new_pwd.value, m=mem, t=tcost, p=parallel
            )
            dlg_error.value = (
                "マスターパスワードを変更しました。アプリを再起動してください。"
            )
            page.update()
            dlg_master.open = False
            page.update()

        def on_cancel_master(e_cancel):
            dlg_master.open = False
            page.update()

        dlg_master = ft.AlertDialog(
            modal=True,
            title=ft.Text("マスターパスワードの変更"),
            content=ft.Column(
                controls=[current_pwd, new_pwd, confirm_pwd, dlg_error],
                tight=True,
            ),
            actions=[
                ft.TextButton("保存", on_click=on_save_master),
                ft.TextButton("キャンセル", on_click=on_cancel_master),
            ],
        )

        page.dialog = dlg_master
        dlg_master.open = True
        page.add(dlg_master)
        page.update()

    set_password_button = ft.ElevatedButton(
        text="マスターパスワードを設定", on_click=open_change_master_password_dialog
    )

    # ========== パスワードファイルパス設定 ==========
    password_file_path_text = ft.Text(
        "パスワードファイルの保存先設定", size=16, weight="bold"
    )

    def load_password_file_path():
        """settings.ini からパスワードファイルパスを読み込む"""
        try:
            settings_path = os.path.join("password_file", "settings.ini")
            if os.path.exists(settings_path):
                cfg = configparser.ConfigParser()
                cfg.read(settings_path, encoding="utf-8")
                if "file_paths" in cfg and "password_file" in cfg["file_paths"]:
                    return cfg["file_paths"]["password_file"]
        except Exception:
            pass
        return "password_file\\passwords.txt"

    password_file_path_input = ft.TextField(
        label="パスワードファイルパス",
        value=load_password_file_path(),
        width=400,
        hint_text="例: password_file\\passwords.txt または C:\\Users\\YourName\\passwords.txt",
    )

    def save_password_file_path(e):
        """パスワードファイルパスを settings.ini に保存"""
        new_path = password_file_path_input.value.strip()
        if not new_path:
            error_message_tab3.value = "エラー: パスが入力されていません。"
            page.update()
            return

        try:
            # パスの親ディレクトリを作成
            parent_dir = os.path.dirname(new_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            # 設定ファイルに保存
            cfg = configparser.ConfigParser()
            settings_path = os.path.join("password_file", "settings.ini")
            if os.path.exists(settings_path):
                cfg.read(settings_path, encoding="utf-8")

            if "file_paths" not in cfg:
                cfg["file_paths"] = {}
            cfg["file_paths"]["password_file"] = new_path

            os.makedirs(os.path.dirname(settings_path), exist_ok=True)
            with open(settings_path, "w", encoding="utf-8") as f:
                cfg.write(f)

            # グローバル変数を更新
            password_manager_core.set_password_file_path(new_path)
            error_message_tab3.value = (
                f"✓ パスワードファイルの保存先を変更しました: {new_path}"
            )
        except Exception as ex:
            error_message_tab3.value = f"エラー: パスの変更に失敗しました: {ex}"

        page.update()

    def on_browse_directory(e: ft.FilePickerResultEvent):
        """ディレクトリ選択後、パスを入力フィールドに反映"""
        if e.path:
            # ユーザーが選択したディレクトリに passwords.txt を付与
            selected_path = os.path.join(e.path, "passwords.txt")
            password_file_path_input.value = selected_path
            password_file_path_input.update()

    # ファイルピッカー（ディレクトリ選択モード）
    directory_picker = ft.FilePicker(on_result=on_browse_directory)
    page.overlay.append(directory_picker)

    pick_folder_dialog = ft.FilePicker(on_result=on_browse_directory)
    page.overlay.append(pick_folder_dialog)

    browse_button = ft.TextButton(
        text="選択",
        icon=ft.Icons.FOLDER,
        on_click=lambda _: pick_folder_dialog.get_directory_path(dialog_title="選択"),
    )

    change_password_file_path_button = ft.ElevatedButton(
        text="保存先を変更", on_click=save_password_file_path
    )

    # ========== タブ構造の作成 ==========
    # タブ1: パスワード生成
    tab1_content = ft.Column(
        controls=[
            password_notice,
            service_name_input,
            username_input,
            min_length_input,
            max_length_input,
            special_chars_checkbox,
            generate_button,
            password_output,
            copy_to_clipboard_button,
            save_button,
            time_counter,
            error_message,
        ],
        scroll=ft.ScrollMode.AUTO,
    )

    tab1 = ft.Tab(text="パスワード生成", content=tab1_content)

    # タブ2: 登録したパスワード
    # Columnにexpand=Trueを設定し、親（Tabs）の高さに追従させる
    tab2_content = ft.Column(
        controls=[
            ft.Text(
                "登録したパスワード一覧: 文字をクリックするとクリップボードにコピーできます"
            ),
            ft.Divider(),
            password_list_view,  # ListView (expand=True)
            time_counter_tab2,
            error_message_tab2,
        ],
        expand=True,
    )

    tab3_content = ft.Column(
        controls=[
            argon2_setting_text,
            argon2_memory_cost,
            argon2_time_cost,
            argon2_parallelism,
            ft.Row(
                controls=[argon2_button, argon2_test_button],
                spacing=10,
            ),
            ft.Divider(),
            password_file_path_text,
            password_file_path_input,
            ft.Row(
                controls=[browse_button, change_password_file_path_button],
                spacing=10,
            ),
            ft.Divider(),
            master_password_text,
            set_password_button,
            error_message_tab3,
        ],
        scroll=ft.ScrollMode.AUTO,
    )

    tab2 = ft.Tab(text="登録したパスワード", content=tab2_content)
    tab3 = ft.Tab(text="設定", content=tab3_content)

    # タブバーの作成
    # 【重要】Tabsにもexpand=Trueを設定して、画面全体の高さを確保する
    tabs = ft.Tabs(
        selected_index=0,
        tabs=[tab1, tab2, tab3],
        on_change=on_tab_change,
        expand=True,  # これがないと中身のスクロールが機能しません
    )

    # ページへの追加
    def _show_rehash_confirmation_dialog(mem, tcost, parallel):
        """Argon2 設定変更後、マスターパスワード再ハッシュの確認ダイアログを表示"""
        rehash_pwd = ft.TextField(
            label="現在のマスターパスワード",
            width=400,
            password=True,
            can_reveal_password=True,
        )
        rehash_error = ft.Text(color=ft.Colors.RED)

        def on_confirm_rehash(confirm_e):
            try:
                password_manager_core.rehash_master_password(
                    rehash_pwd.value, m=mem, t=tcost, p=parallel
                )
                rehash_error.value = (
                    "マスターパスワードを新しい Argon2 設定で再ハッシュしました。"
                )
                page.update()
                rehash_dlg.open = False
                page.update()
            except Exception as ex:
                rehash_error.value = f"エラー: {str(ex)}"
                page.update()

        def on_cancel_rehash(cancel_e):
            rehash_dlg.open = False
            page.update()

        rehash_dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("マスターパスワードを再ハッシュしますか？"),
            content=ft.Column(
                controls=[
                    ft.Text(
                        "Argon2 設定が変更されました。既存のマスターパスワードを新しい設定で再ハッシュしますか？"
                    ),
                    ft.Text("（後でマスターパスワードを変更するだけでも OK です）"),
                    ft.Divider(),
                    rehash_pwd,
                    rehash_error,
                ],
                tight=True,
            ),
            actions=[
                ft.TextButton("再ハッシュ", on_click=on_confirm_rehash),
                ft.TextButton("後で実行", on_click=on_cancel_rehash),
            ],
        )
        page.dialog = rehash_dlg
        rehash_dlg.open = True
        page.add(rehash_dlg)
        page.update()

    page.add(tabs)


if __name__ == "__main__":
    ft.app(target=main_ui)
