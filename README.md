# EvilGuard by Hex Bomb team


> [!NOTE]
> ### Логика работы
> - Отправляем файл на сервер
> - Декомпилируем (RetDec)
> - Ищем паттерны
> - Отправляем на VirusTotal (при необходимости)
> - Отправляем отчёт пользователю


### Скачать:
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