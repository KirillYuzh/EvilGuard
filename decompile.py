import subprocess
import os


def decompile_with_retdec(exe_path: str, output_path: str) -> str:
    """Декомпилирует бинарный файл с помощью RetDec"""
    if not os.path.exists(exe_path):
        raise FileNotFoundError(f"Файл {exe_path} не найден!")
    
    cmd = [
        "retdec-decompiler",
        "--cleanup",  # Удалить временные файлы
        exe_path,
        "-o", output_path
    ]
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60 
        )
        
        if result.returncode != 0:
            print(f"Ошибка декомпиляции:\n{result.stderr}")
            return None
        
        return output_path if os.path.exists(output_path) else None
    
    except subprocess.TimeoutExpired:
        print("RetDec превысил время выполнения!")
        return None
    except Exception as e:
        print(f"Неизвестная ошибка: {e}")
        return None
