"""
Запустите один раз локально:

    pip install bcrypt
    python generate_admin_hash.py

Введите пароль администратора (ввод скрыт). Скрипт напечатает bcrypt-хеш —
именно его нужно положить в переменную окружения ADMIN_PASSWORD_HASH на
Render/Fly. Сам пароль в открытом виде никуда не сохраняется и не
логируется.
"""
import getpass
import bcrypt

password = getpass.getpass("Пароль администратора: ")
confirm = getpass.getpass("Повторите пароль: ")

if password != confirm:
    raise SystemExit("Пароли не совпадают.")

hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
print("\nADMIN_PASSWORD_HASH=" + hashed.decode())
print("\n^ скопируйте эту строку целиком в переменные окружения сервиса.")
