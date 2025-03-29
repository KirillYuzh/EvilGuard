# EvilGuard by Hex Bomb team

## Кирилл Южаков, Ксения Кравчук, Панков Георгий
### Проектный практикум (февраль-март 2025)

Это не продакшн решение! Конечно же!)
На данный момент для работы программы необходимо локально запустить сервер:
1. Создать и активировать виртуальное окружение `python3 -m venv .venv` `source .venv/bin/activate` (команды могут отличаться в зависимости от вашей ОС)
2. Скачать необходимые библиотеки `pip install -r requirements.txt`
3. Локально запустить сервер `uvicorn main:app --host 0.0.0.0 --port 8000 --reload` (p.s. зайдите на сайт VirusTotal, перейдите во вкладку api и скопируйте свой ключ, вставьте его в main.py - VIRUSTOTAL_API_KEY)
4. Скачать приложение из по ссылке ниже (или из раздела release)
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
[Версия для windows](https://github.com/dwolke-up/AntivirusByHexBomb/releases/download/main/EvilGuard-Windows.exe)

> [!TIP]
> Если SmartScreen блокирует запуск:
> 1. Нажмите "Подробнее" в предупреждении
> 2. Выберите "Выполнить в любом случае

- MacOS:
[Версия для macOS](https://github.com/dwolke-up/AntivirusByHexBomb/releases/download/main/EvilGuard-MacOS.dmg)

> [!TIP]
> После скачивания ZIP:
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
[Версия для debian](https://github.com/dwolke-up/AntivirusByHexBomb/releases/download/main/EvilGuard-Linux.deb)

> [!TIP]
> Установка после скачивания:
> ``` bash
> sudo dpkg -i EvilGuard.deb
> ```
