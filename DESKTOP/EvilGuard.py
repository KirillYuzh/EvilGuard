import os
import psutil 
import sys
import requests
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QPushButton, QLabel, QTextEdit, QFileDialog,
                            QMessageBox, QProgressBar, QScrollArea, QLayout)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import QSize


class AntivirusApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('EvilGuard')
        self.setFixedSize(650, 400)
        icon = QIcon()
        pixmap = QPixmap("icon.png") 
        pixmap = pixmap.scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, 
                             Qt.TransformationMode.SmoothTransformation)
        icon.addPixmap(pixmap)
        self.setWindowIcon(icon)
        self.virustotal_data = None
        self.current_file_path = None  # Для хранения пути к проверяемому файлу
        self.init_ui()

    def init_ui(self):
        """Настройка пользовательского интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        self.setStyleSheet("""
        QMainWindow {
            qproperty-windowIcon: url(mtuci.png);
        }
        QWidget {
            background: #333333;
            color: white;
        }
        QLabel {
            font-size: 14px;
            font-family: 'Verdana';
            text-align: left;
            background: transparent;
        }
        QPushButton {
            background-color: #7871aa;
            color: white;
            font-size: 14px;
            font-weight: bold;
            font-family: 'Verdana';
            padding: 12px 20px;
            border-radius: 5px;
            border: 2px solid white;
            min-height: 40px;
            min-width: 200px;
        }
        QPushButton:hover {
            background-color: #4e5283;
        }
        QPushButton#detailsBtn {
            background-color: rgba(255, 255, 255, 0.5);
            color: white;
            font-size: 14px;
            padding: 8px 15px;
            min-width: 150px;
        }
        QProgressBar {
            border: 1px solid white;
            border-radius: 5px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #7871aa;
        }
        QTextEdit {
            background: #444444;
            border: 1px solid white;
            border-radius: 5px;
            padding: 5px;
            font-family: 'Verdana';
            font-size: 14px;
        }
        QMessageBox {
            font-size: 14px;
        }
        QMessageBox QLabel {
            font-size: 14px;
        }
        QMessageBox QPushButton {
            min-width: 200px;
            padding: 8px;
            font-size: 14px;
        }
        """)

        title_label = QLabel()
        title_label.setTextFormat(Qt.TextFormat.RichText)
        title_label.setText("""
            <h1 style="font-size: 24px; font-weight: bold; text-align: center;">EvilGuard</h1>
            <h4 style="font-size: 18px; text-align: center; color: rgba(255, 255, 255, 0.5);">by Hex Bomb team</h4>
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # Анимация загрузки
        self.loading_bar = QProgressBar()
        self.loading_bar.setRange(0, 0)
        self.loading_bar.setTextVisible(False)
        self.loading_bar.hide()
        layout.addWidget(self.loading_bar)

        # Статус
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-size: 14px; text-align: center; color: rgba(255, 255, 255, 0.8); margin-top: auto; margin-bottom: 120px;")
        self.status_label.setTextFormat(Qt.TextFormat.RichText)
        self.status_label.setText("""
            <p>-- Приложение написано на python --</з>
            <p>-- Для первичного анализа используется декомпиляция на основе RetDec --</p>
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        # Кнопка отчёта VirusTotal
        self.btn_details = QPushButton('Показать детали отчёта')
        self.btn_details.setObjectName("detailsBtn")
        self.btn_details.clicked.connect(self.show_virustotal_details)
        self.btn_details.setEnabled(False)
        self.btn_details.hide()
        layout.addWidget(self.btn_details)

        # Кнопка загрузки файла
        self.btn_upload = QPushButton('Выберите файл для проверки')
        self.btn_upload.clicked.connect(self.upload_file)
        layout.addWidget(self.btn_upload)

    def upload_file(self):
        """Загрузка и отпрака файла"""
        file_path, _ = QFileDialog.getOpenFileName(self, 'Выберите файл', '', 'Executable Files (*.exe)')
        if not file_path:
            return

        self.current_file_path = file_path  # Сохраняем путь к файлу
        self.loading_bar.show()
        self.btn_upload.setEnabled(False)
        self.status_label.setText("Отправляем файл на сервер...")

        QTimer.singleShot(1500, lambda: self.send_file_to_server(file_path))

    def send_file_to_server(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                # response = requests.post("http://172.20.10.4:8000/upload", files=files)
                response = requests.post("http://localhost:8000/upload", files=files)

                if response.status_code != 200:
                    raise Exception("Ошибка на стороне сервера.")
                
                self.status_label.setText("Файл отправлен, ожидаем ответа...")
                QTimer.singleShot(2000, lambda: self.process_response(response))

        except Exception as e:
            self.loading_bar.hide()
            self.btn_upload.setEnabled(True)
            self.show_error_message(f"Не удалось загрузить файл: {e}")
            self.status_label.setText("Ошибка загрузки")

    def process_response(self, response):
        """Обработка ответа от сервера"""
        try:
            data = response.json()
            self.loading_bar.hide()
            self.btn_upload.setEnabled(True)
            
            if data.get("status") == "error":
                raise Exception(data.get("message", "Неизвестная ошибка"))
            
            self.status_label.setText("Отчёт получен!")
            self.virustotal_data = data.get("virustotal_report")
            
            # Показываем кнопку только для вредоносных файлов
            status = data.get("status", "unknown")
            if status in ["suspicious", "malicious"]:
                self.btn_details.show()
                self.btn_details.setEnabled(True)
            else:
                self.btn_details.hide()
            
            # Показываем краткий статус
            if status == "clean":
                self.show_info_message("Результат проверки", "✅ Файл чистый, можно запускать!")
            elif status == "suspicious":
                self.show_warning_message("Результат проверки", "⚠️ Файл подозрительный, лучше не запускать!")
            elif status == "malicious":
                self.handle_malicious_file()
                
        except Exception as e:
            self.loading_bar.hide()
            self.btn_upload.setEnabled(True)
            self.show_error_message(f"Не удалось получить ответ: {e}")
            self.status_label.setText("Ошибка обработки ответа")

    def handle_malicious_file(self):
        """Обработка вредоносного файла"""
        # Проверяем, запущен ли файл
        file_name = os.path.basename(self.current_file_path)
        is_running = self.check_if_process_running(file_name)
        
        message = "❌ Обнаружен вредоносный файл!\n\n"
        message += "Этот файл представляет угрозу для вашей системы.\n\n"
        
        if is_running:
            message += "⚠️ Внимание: файл в данный момент запущен!\n\n"
        
        message += "Удалить этот файл?"

        # Создаем кастомное сообщение с кнопками Да/Нет
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Вредоносный файл")
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Icon.Critical)
        
        # Создаем и настраиваем кнопки
        yes_button = msg_box.addButton("Да", QMessageBox.ButtonRole.YesRole)
        no_button = msg_box.addButton("Нет", QMessageBox.ButtonRole.NoRole)
        
        # Настраиваем стиль кнопок
        yes_button.setStyleSheet("""
            QPushButton {
                min-width: 80px;
                padding: 8px;
                font-size: 14px;
                font-family: 'Verdana';
            }
        """)
        no_button.setStyleSheet("""
            QPushButton {
                min-width: 80px;
                padding: 8px;
                font-size: 14px;
                font-family: 'Verdana';
            }
        """)
        
        msg_box.exec()

        if msg_box.clickedButton() == yes_button:
            self.delete_malicious_file()
        
        # В любом случае пытаемся завершить процесс
        if is_running:
            self.terminate_process(file_name)

    def check_if_process_running(self, process_name):
        """Проверяет, запущен ли процесс с указанным именем"""
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    return True
            return False
        except Exception as e:
            print(f"Ошибка при проверке процессов: {e}")
            return False

    def terminate_process(self, process_name):
        """Завершает процесс по имени"""
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'].lower() == process_name.lower():
                    try:
                        psutil.Process(proc.info['pid']).terminate()
                        self.show_info_message("Процесс завершен", 
                                             f"Процесс {process_name} был успешно завершен.")
                        return True
                    except Exception as e:
                        print(f"Ошибка при завершении процесса: {e}")
                        self.show_warning_message("Ошибка", 
                                                f"Не удалось завершить процесс {process_name}.")
            return False
        except Exception as e:
            print(f"Ошибка при поиске процессов: {e}")
            return False

    def delete_malicious_file(self):
        """Удаляет вредоносный файл"""
        try:
            if os.path.exists(self.current_file_path):
                os.remove(self.current_file_path)
                self.show_info_message("Файл удален", 
                                     "Вредоносный файл был успешно удален.")
                self.current_file_path = None
            else:
                self.show_warning_message("Файл не найден", 
                                         "Файл уже был удален или перемещен.")
        except Exception as e:
            self.show_error_message(f"Не удалось удалить файл: {e}")

    def show_virustotal_details(self):
        """Отчёт от VirusTotal"""
        if not self.virustotal_data:
            return
            
        details_text = f"🔍 Подробный отчёт VirusTotal\n\n"
        details_text += f"SHA-256: {self.virustotal_data.get('sha256', 'N/A')}\n"
        details_text += f"Обнаружено: {self.virustotal_data.get('positives', 0)} из {self.virustotal_data.get('total', 0)} антивирусов\n\n"
        
        if "scans" in self.virustotal_data:
            details_text += "📊 Результаты сканирования:\n"
            scans = self.virustotal_data.get("scans", {})
            for scanner, result in scans.items():
                if result.get("detected"):
                    details_text += f"  🔴 {scanner}: {result.get('result', 'Обнаружена угроза')}\n"
                else:
                    details_text += f"  🟢 {scanner}: Чистый\n"
        
        details_text += f"\n🔗 Ссылка на отчёт: {self.virustotal_data.get('permalink', 'N/A')}"
        
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Подробный отчёт VirusTotal")
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setSizeGripEnabled(True)  
        font = QFont("Verdana", 12)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlainText(details_text)
        text_edit.setFont(font)
        text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        
        text_edit.setMinimumSize(600, 600)
        
        layout = dialog.layout()
        layout.addWidget(text_edit, 0, 0, 1, layout.columnCount())
        
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
        ok_button = dialog.button(QMessageBox.StandardButton.Ok)
        ok_button.setMinimumSize(120, 40)
        ok_button.setFont(font)
        
        dialog.exec()

    def show_info_message(self, title, message):
        """Окно с информационным сообщением (файл чистый)"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Verdana", 14))
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        ok_button = msg.button(QMessageBox.StandardButton.Ok)
        ok_button.setMinimumSize(40, 10)
        ok_button.setFont(QFont("Verdana", 12))
        msg.setSizeGripEnabled(True)
        msg.layout().setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        msg.setMinimumSize(600, 400)  
        
        msg.exec()

    def show_warning_message(self, title, message):
        """Окно с предупреждением (файл подозрительный)"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Verdana", 14))
        
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        ok_button = msg.button(QMessageBox.StandardButton.Ok)
        ok_button.setMinimumSize(40, 10)
        ok_button.setFont(QFont("Verdana", 12))
        
        msg.setSizeGripEnabled(True)
        msg.layout().setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        msg.setMinimumSize(600, 400)
        
        msg.exec()

    def show_critical_message(self, title, message):
        """Окно с критическим сообщением (файл вредоносный)"""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setFont(QFont("Verdana", 14))
        
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        ok_button = msg.button(QMessageBox.StandardButton.Ok)
        ok_button.setMinimumSize(40, 10)
        ok_button.setFont(QFont("Verdana", 12))
        
        msg.setSizeGripEnabled(True)
        msg.layout().setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        msg.setMinimumSize(600, 400)
        
        msg.exec()

    def show_error_message(self, message):
        self.show_critical_message("Ошибка", message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec())