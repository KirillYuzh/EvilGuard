# EvilGuard by Hex Bomb team

## Кирилл Южаков, Ксения Кравчук, Панков Георгий
### Проектный практикум (февраль-март 2025)

Это не продакшн решение! Конечно же!)
<a id="server-ip-instruction"></a>
На данный момент для работы программы необходимо запустить сервер внутри вашей локальной сети. Вы можете запустить его на своём компьютере по инструкции ниже (если внутри вашей локальной сети уже есть запущенный сервер, можете пропустить этот шаг и начать использовать приложение сразу)[*](#server-ip).

Инструкция по запуску сервера:
1. Создать и активировать виртуальное окружение `python3 -m venv .venv` `source .venv/bin/activate` (команды могут отличаться в зависимости от вашей ОС)
2. Скачать необходимые библиотеки `pip install -r requirements.txt`
3. Локально запустить сервер `uvicorn main:app --host 0.0.0.0 --port 8000 --reload` (p.s. зайдите на сайт VirusTotal, перейдите во вкладку api и скопируйте свой ключ, вставьте его в main.py - VIRUSTOTAL_API_KEY)
4. Скачать приложение по ссылке ниже (или из раздела release)
5. Запустить приложение (при необходимости следуйте инструкциям внутри файла INSTALL)
6. Пользуйтесь!)


> [!NOTE]
> ### Логика работы
> - Отправляем файл на сервер
> - Декомпилируем (RetDec)
> - Ищем паттерны
> - Отправляем на VirusTotal (при необходимости)
> - Отправляем отчёт пользователю


# Скачать:
- Windows:
[Версия для windows](https://github.com/KirillYuzh/EvilGuard/releases/download/main/EvilGuard-Windows.exe)

> [!TIP]
> Если SmartScreen блокирует запуск:
> 1. Нажмите "Подробнее" в предупреждении
> 2. Выберите "Выполнить в любом случае

- MacOS:
[Версия для macOS](https://github.com/KirillYuzh/EvilGuard/releases/download/main/EvilGuard-MacOS.dmg)

> [!TIP]
> После скачивания:
> 1. Откройте Terminal
> 2. Выполните:  
> ``` bash
>   xattr -cr EvilGuard-MacOS.dmg  # Удаляет карантинные атрибуты
>   open EvilGuard-MacOS.dmg       # Открывает образ
>   cd /Volumes/EvilGuard/
>   chmod +x Install.command
>   ./Install.command
> ```

- Linux (debian):
[Версия для debian](https://github.com/KirillYuzh/EvilGuard/releases/download/main/EvilGuard-Linux.deb)

> [!TIP]
> Установка после скачивания:
> ``` bash
> sudo dpkg -i EvilGuard.deb
> ```

P.S.
<a id="server-ip"></a>
[*](#server-ip-instruction) На данный момент приложение настроено на работу с сервером по адресу 172.20.10.4:8000
