#
# Catware DataBase Encryption Client v1
#

from Crypto.Cipher import AES
from json import dumps, loads
import os
from requests import get
from getpass import getpass
from datetime import datetime
from hashlib import sha256
import random
from base64 import b64encode, b64decode

gensym = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+/<>?"
_IV_ = b"CATDBECENCRYPTED"

# debug_mode содержит булево значение, отвечающее за включение совместимости с режимом отладки. Если True, то обработанное в коде программы исключение будет вызываться намеренно.
debug_mode = True


def encrypt(dct, key):
    obj = AES.new(gethash(key), AES.MODE_CBC, _IV_)
    dct = dumps(dct)
    while len(dct) % 16 != 0: dct += " "
    return b64encode(obj.encrypt(dct.encode("utf-8"))).decode("utf-8")


def decrypt(token, key):
    obj = AES.new(gethash(key), AES.MODE_CBC, _IV_)
    return loads(obj.decrypt(b64decode(token.encode("utf-8"))).decode("utf-8").rstrip())


def gethash(string, hex=False):
    if hex:
        return sha256(str(string).encode("utf-8")).hexdigest()
    else:
        return sha256(str(string).encode("utf-8")).digest()


def passwdgen():
    password = ""
    for x in range(random.randint(20, 50)):
        password += random.choice(gensym)
    return password


def readff(file):  # Read From File
    try:
        Ff = open(file, 'r', encoding='UTF-8')
        Contents = Ff.read()
        Ff.close()
        return Contents
    except:
        return None


def writeto(text, target):
    file = open(str(target), 'w', encoding='utf-8')
    file.write(str(text))
    file.close()


working = True

special_variables = dir()
special_variables.append("special_variables")

while working:
    chosen = False
    while not chosen:
        mode = 0
        print(f"""\n\n\nCatware DataBase Encryption Client | CDBEC v1
1. Открыть локальную базу данных
2. Открыть базу данных по URL
3. Создать базу данных
4. Выйти из программы""")
        try:
            mode = int(input("Выберите действие: "))
            if 1 <= mode <= 4: chosen = True
            print("\n")
        except:
            pass

    if 1 <= mode <= 2:
        got_file = False
        decoded = False
        try:
            while not got_file:
                try:
                    if mode == 1:
                        path = input("Введите путь к файлу (.db-catencrypted): ")
                        db = loads(readff(path))
                    else:
                        url = input("Введите ссылку на файл (.db-catencrypted): ")
                        db = loads(get(url).content)
                    got_file = "name" in db.keys() and db["version"] == 1 and "contents" in db.keys()
                    if db["version"] != 1:
                        print("Несовместимая версия базы.\n")
                    else:
                        print("Несовместимая база. Проверьте целостность.\n")
                except KeyboardInterrupt: raise KeyboardInterrupt
                except:
                    print(f"Не удалось открыть базу.\n")
        except KeyboardInterrupt:
            print("\nПрервано по запросу пользователя. Возврат в главное меню.\n")
        except Exception as e:
            print(f"\nНе удалось распознать файл как базу CDBE: {str(e)}\nВозврат в главное меню.\n")
            if debug_mode: raise e
        if got_file:
            db["name"] = "<без названия>" if not db["name"].strip() else db["name"]
            print("Проверка хэш-суммы базы...")
            hash = gethash(f'{db["contents"]}{db["name"]}{db["last_changed"]}', True)
            print(f"Подлинная хэш-сумма базы:  {hash}")
            if "sha256" in db.keys():
                print(f"Заявленная хэш-сумма базы: {db['sha256']}")
                if hash.lower() == db["sha256"].lower():
                    print("Проверка подлинности успешна.")
                else:
                    print("ВНИМАНИЕ! Проверка подлинности неуспешна: заявленная хэш-сумма не совпадает с подлинной. Это значит, что пакет был изменён вручную.")
            else:
                print("ВНИМАНИЕ! Проверка подлинности не удалась: отсутствует запись о заявленной хэш-сумме.")
            print(f"\nОткрытие базы \"{db['name']}\"")

            try:
                while not decoded:
                    try:
                        password = getpass("Введите пароль (символы будут скрыты): ")
                        db["contents"] = decrypt(db["contents"], password)
                        decoded = True
                        last_sha = gethash(str(db["contents"]) + db["name"] + password)
                    except KeyboardInterrupt:
                        raise KeyboardInterrupt
                    except:
                        print("Дешифрование не удалось. Возможно, введён неверный пароль.")
            except KeyboardInterrupt:
                print("\nПрервано по запросу пользователя. Возврат в главное меню.\n")

        if decoded:
            print("\nВход в режим просмотра и редактирования баз.")
            print(f"База {db['name']} открыта успешно.")
            print("Для просмотра списка команд введите help.\n")

        while decoded:
            try:
                text = str(input("~> ")).strip()
                splitted = text.split(" ")
                cmd = splitted[0].lower()
                args = splitted[1:]

                if cmd == "help":
                    print(f"""
Команды режима чтения и редактирования:

help - показать это сообщение;
ls - показать список базы;
o <номер пункта> - вывести содержимое пункта под указанным номером;
n <название пункта> - создать новый пункт с указанным названием;
e <номер пункта> - изменить содержимое пункта под указанным номером;
name - вывести название базы;
name <новое название> - переименовать базу;
ren <номер пункта> - переименовать пункт под указанным номером;
rm <номер пункта> - удалить пункт под указанным номером;
passwd - сменить пароль базы;

save - сохранить базу со внесёнными изменениями;
exit - выйти из режима чтения и редактирования базы.

{'''Команды отладки:
exec <команда> - выполняет команду в текущей среде.''' if debug_mode else ""}
            """)

                elif cmd == "ls":
                    if db["contents"]["items"] == {}:
                        print("\n<пусто>\n")
                    else:
                        ret = "\n"
                        for x in db["contents"]["items"].keys():
                            ret += f"{x} - {db['contents']['items'][x]['name']}\n"
                        print(ret)

                elif cmd == "o":
                    if len(args) >= 1:
                        if args[0] in db["contents"]["items"].keys():
                            if db['contents']['items'][args[0]]['name'] != "":
                                print(
                                    f"{db['contents']['items'][args[0]]['name']}:\n{db['contents']['items'][args[0]]['text']}\n")
                            else:
                                print(f"{db['contents']['items'][args[0]]['name']}:\n<пусто>\n")
                        else:
                            print(f"\nПункта \"{args[0]}\" не существует.\n")
                    else:
                        print("\nДанная команда требует аргумента.\n")

                elif cmd == "n":
                    if len(args) >= 1:
                        if len(db['contents']['items']) > 0:
                            index = str(int([*db["contents"]["items"]][-1]) + 1)
                        else:
                            index = "1"

                        db["contents"]["items"][index] = {}
                        db["contents"]["items"][index]["name"] = " ".join(args)
                        db["contents"]["items"][index]["text"] = ""

                        print(f"Новый пункт с названием \"{' '.join(args)}\" успешно создан.\n")

                    else:
                        print("\nДанная команда требует аргумента.\n")

                elif cmd == "e":
                    if len(args) == 1:
                        if args[0] in db["contents"]["items"].keys():
                            print(f"\nВы редактируете содержимое пункта {db['contents']['items'][args[0]]['name']}\n")
                            print("Вставьте текст ниже. Когда закончите, нажмите Ctrl+C.\n\n==========")
                            lines = []

                            while True:
                                try:
                                    lines.append(input())
                                except KeyboardInterrupt:
                                    answered = False
                                    while not answered:
                                        try:
                                            print("\n==========\n\nВыберите дальнейшее действие:\ny - сохранить и выйти;\nn - не сохранять изменения.\n")
                                            answer = input(">").strip()
                                            answered = answer.lower() in ["y", "n"]
                                        except: pass

                                    if answer == "y":
                                        db['contents']['items'][args[0]]['text'] = "\n".join(lines)
                                        print("\nИзменения сохранены.\n")

                                    del answered
                                    del answer
                                    break

                        else:
                            print("\nТакого пункта не существует.\n")
                    elif len(args):
                        print("\nДанная команда требует лишь одного аргумента.\n")
                    else:
                        print("\nДанная команда требует аргумента.\n")

                elif cmd == "rm":
                    if len(args) == 1:
                        if args[0] in db["contents"]["items"].keys():
                            del db["contents"]["items"][args[0]]
                            a = 1
                            keys = sorted(db["contents"]["items"])
                            for y in keys:
                                db["contents"]["items"][str(a)] = db["contents"]["items"].pop(y)
                                a += 1

                            print("\nУспешно.\n")
                        else:
                            print(f"\nПункта \"{args[0]}\" не существует.\n")
                    else:
                        print("\nДанная команда требует одного аргумента.\n")

                elif cmd == "name":
                    if len(args) == 0:
                        print("\n")
                        print(db["name"])
                        print("\n")
                    else:
                        db["name"] = " ".join(args)
                        print(f"\nБаза успешно переименована. Новое имя: {db['name']}\n")

                elif cmd == "passwd":
                    checked = False
                    while not checked:
                        print(
                            "\nПридумайте пароль, который будет использоваться в качестве ключа шифрования для этой базы данных.")
                        print(
                            "Мы советуем использовать длинные пароли (от 20 символов), содержащие в себе комбинации прописных и строчных букв, цифр и знаков препинания.")
                        print("Вы можете оставить поле для ввода пароля пустым, и мы автоматически сгенерируем ключ.\n")
                        password = getpass("Введите пароль (символы будут скрыты): ")
                        if password:
                            password2 = getpass("Повторите пароль (символы будут скрыты): ")
                            checked = password == password2
                            if not checked: print("Введённые пароли не совпадают.")
                        else:
                            password = passwdgen()
                            print(f"\nПароль сгенерирован: {password}")
                            print(
                                "Сохраните его в надёжном месте для дальнейшей работы с базой. Пароль не подлежит восстановлению.")
                            checked = True
                    del password2

                elif cmd == "save":
                    time = int(datetime.utcnow().timestamp())
                    print("\nНачинаю шифрование...")
                    db_save = db.copy()
                    last_sha = gethash(db["contents"])
                    db_save["contents"] = encrypt(db_save["contents"], password)
                    db_save["last_changed"] = time
                    db_save["sha256"] = gethash(f'{db_save["contents"]}{db_save["name"]}{db_save["last_changed"]}', True)
                    if mode == 1:
                        writeto(dumps(db_save, ensure_ascii=False), path)
                        print(f"База сохранена в {os.path.abspath(path)}")
                    else:
                        writeto(dumps(db_save, ensure_ascii=False), f"export/{time}.db-catencrypted")
                        print(f"База сохранена в export/{time}.db-catencrypted.")
                    del db_save
                    print("\n")

                elif cmd == "exit":
                    if gethash(str(db["contents"]) + db["name"] + password) != last_sha:
                        answered = False
                        answ = ""
                        while not answered:
                            try:
                                print("""
Вы внесли изменения в базу, но не сохранили их. Желаете ли вы выйти без сохранения?

y - выйти без сохранения;
s - сохранить и выйти;
n - отмена операции.""")
                                answ = input("Выберите действие: ").lower().strip()
                                answered = answ in ["y", "s", "n"]
                                print("\n")
                            except:
                                pass

                        if answ == "s":
                            time = int(datetime.utcnow().timestamp())
                            print("\nНачинаю шифрование...")
                            db["contents"] = encrypt(db["contents"], password)
                            db["last_changed"] = time
                            db["sha256"] = gethash(f'{db["contents"]}{db["name"]}{db["last_changed"]}', True)
                            if mode == 1:
                                writeto(dumps(db, ensure_ascii=False), path)
                                print(f"База сохранена в {os.path.abspath(path)}")
                            else:
                                writeto(dumps(db, ensure_ascii=False), f"export/{time}.db-catencrypted")
                                print(f"База сохранена в export/{time}.db-catencrypted.")

                        if answ != "n":
                            print("\nОчистка данных...")
                            del db
                            del password
                            decoded = False
                    else:
                        print("\nОчистка данных...")
                        del db
                        del password
                        decoded = False

                elif cmd == "exec" and debug_mode:
                    if len(args) >= 1:
                        exec(" ".join(args))

                elif cmd == "":
                    pass
                else:
                    print("\nНеизвестная команда.\n")

            except KeyboardInterrupt:
                print("^C\nДля получения списка команд введите help, для безопасного выхода из режима просмотра и редактирования введите exit.\n")
            except Exception as e:
                print(f"\nВо время выполнения команды произошло необрабатываемое исключение: {str(e)}\n")
                if debug_mode: raise e


    elif mode == 3:
        try:
            print("Создаётся новая база данных.")
            try:
                os.mkdir("export")
            except:
                pass
            checked = False
            db_name = input("Название (оно не будет зашифровано): ")

            while not checked:
                print("\nПридумайте пароль, который будет использоваться в качестве ключа шифрования для создаваемой базы данных.")
                print("Мы советуем использовать длинные пароли (от 20 символов), содержащие в себе комбинации прописных и строчных букв, цифр и знаков препинания.")
                print("Вы можете оставить поле для ввода пароля пустым, и мы автоматически сгенерируем ключ.\n")
                password = getpass("Введите пароль (символы будут скрыты): ")
                if password:
                    password2 = getpass("Повторите пароль (символы будут скрыты): ")
                    checked = password == password2
                    if not checked: print("Введённые пароли не совпадают.")
                else:
                    password = passwdgen()
                    print(f"\nПароль сгенерирован: {password}")
                    print("Сохраните его в надёжном месте для дальнейшей работы с базой. Пароль не подлежит восстановлению.")
                    checked = True

            time = int(datetime.utcnow().timestamp())
            db = {"name": "<без названия>" if not db_name.rstrip() else db_name, "version": 1, "last_changed": time, "contents": {"items": {}}}

            print("\nНачинаю шифрование...")
            db["contents"] = encrypt(db["contents"], password)
            db["sha256"] = gethash(f'{db["contents"]}{db["name"]}{db["last_changed"]}', True)
            writeto(dumps(db, ensure_ascii=False), f"export/{time}.db-catencrypted")
            print(f"Новая база успешно создана и сохранена в export/{time}.db-catencrypted.")
            print("\nВНИМАНИЕ! Вы можете переименовать файл базы при необходимости, однако не следует изменять файл базы вручную во избежание ошибок дешифрования.\n")

            print("\nОчистка данных...")
            del password
            del password2
            del db
            print("Успешно!\n")

            print("Чтобы начать работу с базой, выберите пункт 1.")

        except KeyboardInterrupt:
            print("\nПрервано по запросу пользователя. Возврат в главное меню.\n")
        except Exception as e:
            print(f"\nВо время создания базы произошло необрабатываемое исключение: {str(e)}\nВозврат в главное меню.\n")
            if debug_mode: raise e

    elif mode == 4:
        print("Очистка данных...")
        for variable in dir():
            if variable not in special_variables: exec(f"del {variable}")
        working = False