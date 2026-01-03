import secrets
import string
from passlib.hash import argon2
import os
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import time as time_module
import configparser
import shutil
import pyotp
import csv
import io

# ソルトファイルと鍵の定数
SALT_FILEPATH = "password_file\\salt.txt"
KEY_BYTES = 32  # 256ビット鍵
PBKDF2_ITERATIONS = 390000  # OWASP推奨のイテレーション数

# パスワードファイルがメモリ上で復号されているかを示すフラグ
_password_file_decrypted_in_memory = False

# パスワードファイルの保存先（デフォルト）
_password_file_path = "password_file\\passwords.txt"


def set_password_file_path(filepath):
    """
    パスワードファイルの保存先を設定し、既存のファイルを新しい場所に移動する。
    """
    global _password_file_path
    old_filepath = _password_file_path

    if old_filepath == filepath:
        return  # 同じパスなら何もしない

    # 古いファイルが存在する場合のみ移動処理を行う
    if os.path.exists(old_filepath):
        try:
            # 新しい保存先のディレクトリが存在しない場合は作成
            new_dir = os.path.dirname(filepath)
            if new_dir:
                os.makedirs(new_dir, exist_ok=True)

            # ファイルを新しい場所にコピー
            shutil.copy2(old_filepath, filepath)

            # 古いファイルを削除
            os.remove(old_filepath)

        except Exception as e:
            # エラーが発生した場合は、操作をロールバック（新しいファイルを削除）
            if os.path.exists(filepath):
                os.remove(filepath)
            raise IOError(f"パスワードファイルの移動に失敗しました: {e}")

    # すべての操作が成功したら、グローバル変数を更新
    _password_file_path = filepath


def get_password_file_path():
    """現在のパスワードファイル保存先を取得"""
    return _password_file_path


def load_password_file_path_from_config():
    """settings.ini からパスワードファイルパスを読み込む"""
    try:
        settings_path = os.path.join("password_file", "settings.ini")
        if os.path.exists(settings_path):
            cfg = configparser.ConfigParser()
            cfg.read(settings_path, encoding="utf-8")
            if "file_paths" in cfg and "password_file" in cfg["file_paths"]:
                set_password_file_path(cfg["file_paths"]["password_file"])
    except Exception as ex:
        print(f"警告: パスワードファイルパスの読み込みに失敗しました: {ex}")


# ランダムなパスワードを生成する関数
def generate_secure_password(length, use_special_chars=True):
    # 短すぎる文字数のパスワードは拒否
    # 今回は12文字以上とする
    if length < 12:
        raise ValueError("パスワードの長さは12文字以上である必要があります。")
    # 使用する文字セットを定義
    # 英大文字、英小文字、数字、記号を含む(記号は有効な場合のみ)
    if use_special_chars:
        characters = string.ascii_letters + string.digits + string.punctuation
    else:
        characters = string.ascii_letters + string.digits
    # ランダムに文字を選んでパスワードを生成
    password = "".join(secrets.choice(characters) for _ in range(length))
    return password


def get_or_create_salt():
    """ソルトを読み込むか、存在しない場合は新規作成する"""
    if os.path.exists(SALT_FILEPATH):
        with open(SALT_FILEPATH, "rb") as f:
            return f.read()
    else:
        salt = get_random_bytes(16)
        os.makedirs(os.path.dirname(SALT_FILEPATH), exist_ok=True)
        with open(SALT_FILEPATH, "wb") as f:
            f.write(salt)
        return salt


def derive_key(master_password, salt):
    """マスターパスワードとソルトからPBKDF2で暗号化キーを派生させる"""
    return PBKDF2(master_password, salt, dkLen=KEY_BYTES, count=PBKDF2_ITERATIONS)


def encrypt_password_file(plaintext_bytes, master_password, filepath=None):
    """
    平文のバイトデータをマスターパスワードで暗号化し、ファイルに保存する。
    """
    if filepath is None:
        filepath = get_password_file_path()

    salt = get_or_create_salt()
    key = derive_key(master_password, salt)

    # 空のデータは空ファイルとして保存
    if not plaintext_bytes:
        with open(filepath, "wb") as f:
            f.write(b"")
        return

    # 暗号化
    nonce = get_random_bytes(24)  # XChaCha20-Poly1305 用の 24 バイトナンス
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

    # 暗号化された内容を保存（nonce + ciphertext + tag）
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(nonce + ciphertext + tag)


def decrypt_password_file(master_password, filepath=None):
    """
    パスワードファイルをマスターパスワードで復号化し、平文のバイトデータを返す。
    ディスクへの書き込みは行わない。
    """
    if filepath is None:
        filepath = get_password_file_path()

    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return b""  # ファイルが存在しないか空なら空のバイト列を返す

    if not os.path.exists(SALT_FILEPATH):
        raise FileNotFoundError(
            "ソルトファイルが見つかりません。アプリケーションが正しく初期化されていません。"
        )

    with open(SALT_FILEPATH, "rb") as f:
        salt = f.read()

    key = derive_key(master_password, salt)

    with open(filepath, "rb") as f:
        data = f.read()

    # nonce(24) + tag(16) + 最低1バイトのデータが必要
    if len(data) < 24 + 16 + 1:
        raise ValueError("パスワードファイルが破損しているか、不正な形式です。")

    nonce = data[:24]
    tag = data[-16:]
    ciphertext = data[24:-16]

    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError) as e:
        raise ValueError(
            "パスワードファイルの復号化に失敗しました。マスターパスワードが間違っているか、ファイルが破損している可能性があります。"
        )


# パスワードファイルを復号化して内容を取得する関数
def get_decrypted_passwords(master_password, filepath=None):
    if filepath is None:
        filepath = get_password_file_path()

    try:
        decrypted_bytes = decrypt_password_file(master_password, filepath)
    except ValueError as e:
        # 復号エラーはここで捕捉し、空リストを返すか、再度例外を送出するか選択
        # UI側でエラーメッセージを処理するため、ここでは再送出が適切
        raise e

    passwords = []
    if not decrypted_bytes:
        return passwords

    try:
        decrypted_content = decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("パスワードファイルのデータが破損しており、読み込めません。")

    # CSV としてパースして、オプションで 4 列目に totp_secret を扱う
    reader = csv.reader(decrypted_content.splitlines())
    for row in reader:
        if not row or all([not cell.strip() for cell in row]):
            continue
        if len(row) < 3:
            print(f"警告: 保存ファイルの行が不正な形式です。スキップします: {row}")
            continue
        service_name = row[0]
        username = row[1]
        password = row[2]
        totp_secret = row[3] if len(row) >= 4 else ""
        passwords.append(
            {
                "service_name": service_name,
                "username": username,
                "password": password,
                "totp_secret": totp_secret,
            }
        )
    return passwords


# マスターパスワードが存在するかチェックする関数
def master_password_exists():
    return os.path.exists("password_file\\master_password.txt")


# マスターパスワードのハッシュ化関数
def hash_master_password(master_password, m=102400, t=2, p=8):
    # Argon2でハッシュ化
    hashed_password = argon2.using(
        type="id", memory_cost=m, time_cost=t, parallelism=p
    ).hash(master_password)
    # ファイルに保存
    with open("password_file\\master_password.txt", "w") as f:
        f.write(hashed_password)


# マスターパスワードの検証関数
def verify_master_password(input_password):
    # 保存されたハッシュを読み込み
    if not os.path.exists("password_file\\master_password.txt"):
        raise FileNotFoundError("マスターパスワードファイルが存在しません。")
    with open("password_file\\master_password.txt", "r") as f:
        stored_hash = f.read()
    # 入力されたパスワードを検証
    return argon2.verify(input_password, stored_hash)


# マスターパスワードを再ハッシュする関数（パスワード自体は変わらない、Argon2設定のみ変更）
def rehash_master_password(current_password, m=102400, t=2, p=8):
    """
    現在のマスターパスワード（プレーンテキスト）を検証して、
    新しい Argon2 パラメータでハッシュを再生成する。
    パスワードの値自体は変わらない。
    """
    # 現在のパスワードが正しいか確認
    if not verify_master_password(current_password):
        raise ValueError("現在のマスターパスワードが正しくありません。")
    # 新しいパラメータで再ハッシュ
    hash_master_password(current_password, m=m, t=t, p=p)


# Argon2 パラメータでハッシュ化テストを行う関数
def test_argon2_hash(test_password, m=102400, t=2, p=8):
    """
    与えられたパラメータでハッシュ化テストを実行し、
    実行時間とハッシュ結果を返す。
    実際のマスターパスワードファイルは変更しない。

    戻り値: {
        "success": bool,
        "hash": str（ハッシュ値、成功時のみ）,
        "execution_time": float（秒）,
        "error": str（エラー時のみ）,
    }
    """

    try:
        start_time = time_module.time()
        hashed_password = argon2.using(
            type="id", memory_cost=m, time_cost=t, parallelism=p
        ).hash(test_password)
        end_time = time_module.time()

        execution_time = end_time - start_time
        return {
            "success": True,
            "hash": hashed_password,
            "execution_time": execution_time,
        }
    except Exception as ex:
        end_time = time_module.time()
        execution_time = end_time - start_time
        return {
            "success": False,
            "execution_time": execution_time,
            "error": str(ex),
        }


# TOTP シークレットキーに基づいてワンタイムパスワードを生成する関数
def generate_totp_code(secret_key):
    """
    与えられたシークレットキーから TOTP ワンタイムパスワードを生成する。
    デフォルトでは30秒ごとにコードが変わる。
    """
    totp = pyotp.TOTP(secret_key)
    return totp.now()
