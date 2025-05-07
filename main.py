from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
import subprocess
import os
import requests
import logging
import uvicorn
import time
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from decompile import *


scan_stats = defaultdict(int)

app = FastAPI()

VIRUSTOTAL_API_KEY = "api_key"

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SUSPICIOUS_PATTERNS = [
    "system(", "exec(", "popen(", "CreateRemoteThread", "VirtualAllocEx",
    "LoadLibrary", "GetProcAddress", "NtCreateThreadEx", "GetConsoleWindow", "ShowConsoleWindow"
]

VT_CACHE = {}
CACHE_TTL = timedelta(hours=24)  # Храним отчеты 24 часа

def get_cached_report(file_hash):
    if file_hash in VT_CACHE:
        cached_at, report = VT_CACHE[file_hash]
        if datetime.now() - cached_at < CACHE_TTL:
            return report
    return None

def check_multiple_hashes(hashes: list) -> dict:
    """Проверяет до 25 хешей за один запрос (VT limit)"""
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': ','.join(hashes[:25])  # 25 хешей в одном запросе
    }
    return requests.get(url, params=params).json()

def calculate_file_hash(file_path: str) -> str:
    """Вычисляет SHA-256 хеш файла"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):  # Читаем файл блоками по 8KB
            sha256.update(chunk)
    return sha256.hexdigest()

def check_virustotal(file_path: str) -> dict:
    """Проверяет файл через VirusTotal с кешированием и статистикой"""
    scan_stats['total_checks'] += 1
    
    # Получаем хеш файла
    file_hash = calculate_file_hash(file_path)
    
    # Пытаемся получить существующий отчет
    report = get_existing_virustotal_report(file_hash)
    
    if report and report.get('response_code') == 1:
        logger.info(f"Using cached report for hash: {file_hash}")
        scan_stats['cached'] += 1
        return report
    
    # Если отчета нет, загружаем файл
    logger.info(f"No cached report found, uploading file: {file_path}")
    scan_stats['new_uploads'] += 1
    return upload_file_to_virustotal(file_path)

def get_existing_virustotal_report(file_hash: str) -> dict | None:
    """Запрашивает существующий отчет по хешу"""
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': file_hash
    }
    try:
        # Таймаут (соединение: 5 сек, чтение: 10 сек)
        response = requests.get(url, params=params, timeout=(5, 10))
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"VirusTotal API returned status {response.status_code}")
            
    except requests.exceptions.Timeout:
        logger.error("VirusTotal request timed out")
    except requests.exceptions.RequestException as e:
        logger.error(f"Request to VirusTotal failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    
    return None

def upload_file_to_virustotal(file_path: str) -> dict:
    """Загружает файл в VirusTotal"""
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {'apikey': VIRUSTOTAL_API_KEY}
    
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, files=files, params=params, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Upload failed with status {response.status_code}")
            return {'error': 'Upload failed'}
            
    except requests.exceptions.Timeout:
        logger.error("File upload to VirusTotal timed out")
        return {'error': 'Timeout'}
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return {'error': str(e)}

def analyze_code(file_path: str) -> dict:
    """Анализ кода с очисткой временных файлов"""
    try:
        output_file = "decompiled.c"
        decompiled_path = decompile_with_retdec(file_path, output_file)
        
        if not decompiled_path:
            return {"status": "error", "message": "Decompilation failed"}
        
        with open(decompiled_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        
        findings = [pattern for pattern in SUSPICIOUS_PATTERNS if pattern in code]

        # Удаление временных файлов декомпиляции
        try:
            # Основной файл
            if os.path.exists(decompiled_path):
                os.remove(decompiled_path)
            
            # Другие файлы RetDec
            temp_files = [
                "decompiled.ll",           
                "decompiled.bc",            
                "decompiled.dsm",           
                "decompiled.config.json",   
            ]
            
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    
        except Exception as cleanup_error:
            logger.warning(f"Failed to clean up temporary files: {cleanup_error}")

        return {
            "status": "dangerous" if findings else "clean",
            "suspect_functions": findings
        }
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        # Сохраняем временный файл
        file_path = os.path.join("uploads", file.filename)
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        
        # Проверяем через VirusTotal (с кешированием)
        virustotal_report = check_virustotal(file_path)
        
        # Анализируем код
        analysis_result = analyze_code(file_path)
        
        # Формируем ответ
        positives = virustotal_report.get('positives', 0)
        status = "malicious" if positives >= 5 else "suspicious" if positives >= 1 else "clean"
        
        return JSONResponse({
            "status": status,
            "hash": calculate_file_hash(file_path),
            "positives": positives,
            "virustotal_report": virustotal_report,
            "code_analysis": analysis_result
        })
        
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

def send_to_virustotal(file_path: str):
    """Отправляет файл в VirusTotal и возвращает полный отчет"""

    logger.info("Отправляем файл на virustotal")
    
    # Загружаем файл и получаем scan_id
    upload_url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {"apikey": VIRUSTOTAL_API_KEY}
    
    with open(file_path, "rb") as file:
        files = {"file": file}
        upload_response = requests.post(upload_url, files=files, params=params)
    
    if upload_response.status_code != 200:
        return {"error": "Ошибка загрузки файла"}
    
    scan_data = upload_response.json()
    scan_id = scan_data.get("scan_id")
    
    if not scan_id:
        return {"error": "Не удалось получить scan_id"}
    
    # Запрашиваем отчет 
    report_url = "https://www.virustotal.com/vtapi/v2/file/report"
    report_params = {
        "apikey": VIRUSTOTAL_API_KEY,
        "resource": scan_id,
        "allinfo": 1
    }
    
    max_retries = 5
    retry_delay = 15  
    
    for _ in range(max_retries):
        report_response = requests.get(report_url, params=report_params)
        
        if report_response.status_code != 200:
            return {"error": "Ошибка запроса отчета"}
        
        report_data = report_response.json()
        
        if report_data.get("response_code") == 1:
            return report_data
        
        # Delay и повторная попытка - если отчет не готов
        time.sleep(retry_delay)
    
    return {"error": "Отчет не готов после нескольких попыток"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

# uvicorn main:app --host 0.0.0.0 --port 8000 --reload
