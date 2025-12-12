import password_manager_core
import UI_password_manager
import master_password_UI
import os
import flet as ft
import asyncio

# 初回起動かどうかをチェックする関数
def first_run_check():
    return not password_manager_core.master_password_exists()


def main(page: ft.Page):
    # 古い、脆弱なキーファイルを削除する
    old_key_file = "password_file\\encryption_key.txt"
    if os.path.exists(old_key_file):
        try:
            os.remove(old_key_file)
            print(f"INFO: 古いキーファイル {old_key_file} を削除しました。")
        except OSError as e:
            print(f"WARN: 古いキーファイルの削除に失敗しました: {e}")

    # アプリ起動時に設定ファイルからパスワードファイルパスを読み込む
    password_manager_core.load_password_file_path_from_config()

    async def show_password_manager(master_password: str):
        """
        マスターパスワードを受け取り、パスワード管理UIを表示する。
        """
        page.clean()
        # main_uiにマスターパスワードを渡す
        await UI_password_manager.main_ui(page, master_password)

    def on_master_password_verified(master_password: str):
        """
        マスターパスワードが検証された後に呼び出されるコールバック。
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(show_password_manager(master_password))
        except RuntimeError:
            asyncio.run(show_password_manager(master_password))

    def on_first_run_setup_complete(master_password: str):
        """
        初回マスターパスワード設定完了後に呼び出されるコールバック。
        空のパスワードファイルを作成・暗号化してからUIを表示する。
        """
        # 空のパスワードファイルを作成・暗号化
        password_manager_core.encrypt_password_file(b"", master_password)
        # 通常のコールバックを呼び出す
        on_master_password_verified(master_password)
    
    # --- メインロジック ---
    if first_run_check():
        # 初回起動時
        # 1. マスターパスワード設定UIを表示
        # 2. 設定完了後、on_first_run_setup_complete が呼ばれる
        # 3. on_first_run_setup_complete が空のパスワードファイルを作成し、on_master_password_verified を呼ぶ
        # 4. on_master_password_verified が show_password_manager を呼ぶ
        # 5. show_password_manager がメインUIを表示
        master_password_UI.set_master_password_verified_callback(on_first_run_setup_complete)
        master_password_UI.master_password_setup_ui(page)
    else:
        # 通常起動時
        # 1. マスターパスワード入力UIを表示
        # 2. 検証成功後、on_master_password_verified が呼ばれる
        # 3. on_master_password_verified が show_password_manager を呼ぶ
        # 4. show_password_manager がメインUIを表示
        master_password_UI.set_master_password_verified_callback(on_master_password_verified)
        master_password_UI.master_password_input_ui(page)


ft.app(target=main)
