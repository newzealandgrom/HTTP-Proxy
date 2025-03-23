#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP/HTTPS прокси-сервер с веб-панелью управления пользователями
Для Ubuntu 22.04
"""

import os
import sys
import base64
import sqlite3
import threading
import logging
import argparse
import socket
import select
import ssl
import subprocess
from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("proxy_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("proxy_server")

# Базовые настройки
DEFAULT_PROXY_PORT = 8080
DEFAULT_ADMIN_PORT = 5000
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"
DB_FILE = "proxy_users.db"
BUFFER_SIZE = 16384  # Увеличенный размер буфера
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# Создаем самоподписанный сертификат, если его нет
def create_self_signed_cert():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        logger.info("Создание самоподписанного сертификата...")
        try:
            subprocess.run([
                'openssl', 'req', '-new', '-newkey', 'rsa:2048', '-days', '365', '-nodes', 
                '-x509', '-subj', '/CN=ProxyServer', '-keyout', KEY_FILE, '-out', CERT_FILE
            ], check=True)
            logger.info("Сертификат успешно создан")
        except subprocess.CalledProcessError as e:
            logger.error(f"Ошибка при создании сертификата: {e}")
            logger.error("Пожалуйста, установите OpenSSL и создайте сертификаты вручную")
            print("Ошибка: Не удалось создать сертификаты для HTTPS. Установите OpenSSL.")

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Создаем таблицу пользователей, если она не существует
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Создаем таблицу администраторов, если она не существует
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Создаем таблицу статистики, если она не существует
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        url TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        bytes INTEGER DEFAULT 0
    )
    ''')
    
    # Проверяем, есть ли админ по умолчанию
    cursor.execute("SELECT COUNT(*) FROM admins WHERE username = ?", (DEFAULT_ADMIN_USER,))
    if cursor.fetchone()[0] == 0:
        # Создаем хеш пароля
        hashed_password = bcrypt.generate_password_hash(DEFAULT_ADMIN_PASS).decode('utf-8')
        # Добавляем админа по умолчанию
        cursor.execute("INSERT INTO admins (username, password) VALUES (?, ?)", 
                      (DEFAULT_ADMIN_USER, hashed_password))
    
    # Проверяем, есть ли пользователь по умолчанию
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,))
    if cursor.fetchone()[0] == 0:
        # Добавляем пользователя по умолчанию
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      (DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS))
    
    conn.commit()
    conn.close()
    logger.info("База данных инициализирована")

# Класс для проверки аутентификации пользователей прокси
class ProxyAuth:
    @staticmethod
    def check_auth(username, password):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ? AND active = 1", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            stored_password = result[0]
            # Для простой аутентификации прокси используем открытый текст
            return password == stored_password
        return False

# Класс HTTP прокси-сервера с аутентификацией
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_CONNECT(self):
        """Обработка HTTPS соединений через SSL-туннель"""
        logger.info(f"CONNECT запрос: {self.path}")
        
        # Проверка аутентификации
        auth_header = self.headers.get('Proxy-Authorization')
        if not auth_header:
            logger.info("CONNECT: Нет заголовка авторизации")
            self.send_auth_request()
            return
        
        try:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                logger.info(f"CONNECT: Неверный тип авторизации: {auth_type}")
                self.send_auth_request()
                return
                
            user_pass = base64.b64decode(auth_string).decode('utf-8')
            username, password = user_pass.split(':', 1)
            
            logger.info(f"CONNECT: Попытка аутентификации: пользователь={username}")
            
            if not ProxyAuth.check_auth(username, password):
                logger.info(f"CONNECT: Аутентификация не удалась для пользователя: {username}")
                self.send_auth_request()
                return
            
            logger.info(f"CONNECT: Аутентификация успешна для пользователя: {username}")
            
            # Разбираем адрес и порт из CONNECT-запроса
            address = self.path.split(':')
            hostname = address[0]
            port = int(address[1]) if len(address) > 1 else 443
            
            # Создаем сокет для подключения к целевому серверу
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(30)  # Устанавливаем тайм-аут
            
            try:
                target_socket.connect((hostname, port))
                
                # Отправляем успешный ответ клиенту
                self.send_response(200, 'Connection Established')
                self.send_header('Proxy-Agent', 'Python Proxy Server')
                self.end_headers()
                
                # Получаем сокет клиента
                client_socket = self.connection
                
                # Перенаправление данных в обе стороны
                self.forward_data(client_socket, target_socket, username, hostname)
                
            except socket.timeout:
                logger.error(f"CONNECT: Тайм-аут при подключении к {hostname}:{port}")
                self.send_error(504, f"Тайм-аут при подключении к {hostname}:{port}")
                return
            except socket.gaierror:
                logger.error(f"CONNECT: Невозможно разрешить имя хоста {hostname}")
                self.send_error(502, f"Невозможно разрешить имя хоста {hostname}")
                return
            except Exception as e:
                logger.error(f"CONNECT: Ошибка при подключении к {hostname}:{port}: {e}")
                self.send_error(502, f"Невозможно подключиться к {hostname}:{port}")
                return
        
        except Exception as e:
            logger.error(f"CONNECT: Неожиданная ошибка: {e}")
            try:
                self.send_error(500, "Внутренняя ошибка сервера")
            except:
                pass  # Игнорируем ошибки при отправке ответа об ошибке
    
    def forward_data(self, client_socket, target_socket, username, hostname):
        """Перенаправление данных между клиентом и целевым сервером"""
        client_buffer = target_buffer = b''
        total_bytes = 0
        
        # Не используем неблокирующий режим для сокетов
        client_socket.setblocking(1)
        target_socket.setblocking(1)
        
        # Устанавливаем тайм-аут
        client_socket.settimeout(60)
        target_socket.settimeout(60)
        
        try:
            while True:
                # Ждем данные от клиента или сервера
                inputs = [client_socket, target_socket]
                try:
                    readable, _, exceptional = select.select(inputs, [], inputs, 30)
                
                    if exceptional:
                        break
                    
                    if not readable:
                        continue
                    
                    # Получаем данные от клиента
                    if client_socket in readable:
                        try:
                            data = client_socket.recv(BUFFER_SIZE)
                            if not data:
                                break
                            target_socket.sendall(data)
                        except (ConnectionResetError, BrokenPipeError) as e:
                            logger.warning(f"CONNECT: Ошибка при чтении/записи клиентских данных: {e}")
                            break
                        except socket.timeout:
                            logger.debug("CONNECT: Тайм-аут при чтении клиентских данных")
                            continue
                    
                    # Получаем данные от целевого сервера
                    if target_socket in readable:
                        try:
                            data = target_socket.recv(BUFFER_SIZE)
                            if not data:
                                break
                            client_socket.sendall(data)
                            total_bytes += len(data)
                        except (ConnectionResetError, BrokenPipeError) as e:
                            logger.warning(f"CONNECT: Ошибка при чтении/записи данных сервера: {e}")
                            break
                        except socket.timeout:
                            logger.debug("CONNECT: Тайм-аут при чтении данных сервера")
                            continue
                except select.error:
                    break
        finally:
            # Закрываем соединения
            try:
                client_socket.close()
            except:
                pass
                
            try:
                target_socket.close()
            except:
                pass
            
            # Записываем статистику только если были переданы данные
            if total_bytes > 0:
                try:
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO stats (username, url, bytes) VALUES (?, ?, ?)",
                        (username, f"https://{hostname}", total_bytes)
                    )
                    conn.commit()
                    conn.close()
                except Exception as e:
                    logger.error(f"Ошибка при записи статистики: {e}")
    
    def do_GET(self):
        logger.info(f"GET запрос: {self.path}")
        logger.info(f"Заголовки: {self.headers}")
        self.handle_request()
    
    def do_POST(self):
        logger.info(f"POST запрос: {self.path}")
        logger.info(f"Заголовки: {self.headers}")
        self.handle_request()
    
    def do_PUT(self):
        logger.info(f"PUT запрос: {self.path}")
        self.handle_request()
    
    def do_DELETE(self):
        logger.info(f"DELETE запрос: {self.path}")
        self.handle_request()
    
    def do_HEAD(self):
        logger.info(f"HEAD запрос: {self.path}")
        self.handle_request()
    
    def do_OPTIONS(self):
        logger.info(f"OPTIONS запрос: {self.path}")
        self.handle_request()
    
    def do_PATCH(self):
        logger.info(f"PATCH запрос: {self.path}")
        self.handle_request()
    
    def handle_request(self):
        """Обработка HTTP запросов"""
        # Проверка аутентификации
        auth_header = self.headers.get('Proxy-Authorization')
        if not auth_header:
            logger.info("Нет заголовка авторизации")
            self.send_auth_request()
            return
        
        try:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                logger.info(f"Неверный тип авторизации: {auth_type}")
                self.send_auth_request()
                return
                
            user_pass = base64.b64decode(auth_string).decode('utf-8')
            username, password = user_pass.split(':', 1)
            
            logger.info(f"Попытка аутентификации: пользователь={username}")
            
            if not ProxyAuth.check_auth(username, password):
                logger.info(f"Аутентификация не удалась для пользователя: {username}")
                self.send_auth_request()
                return
            
            logger.info(f"Аутентификация успешна для пользователя: {username}")
            # Аутентификация прошла успешно, обрабатываем запрос
            self.proxy_request(username)
        
        except Exception as e:
            logger.error(f"Ошибка аутентификации: {e}")
            self.send_auth_request()
            return
    
    def send_auth_request(self):
        """Отправка запроса на аутентификацию"""
        self.send_response(407)
        self.send_header('Proxy-Authenticate', 'Basic realm="Proxy Authentication Required"')
        self.send_header('Content-Type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>407 Proxy Authentication Required</h1></body></html>")
    
    def proxy_request(self, username):
        """Проксирование HTTP запросов"""
        url = self.path
        
        # Если URL не является абсолютным, добавляем http://
        if not url.startswith('http'):
            url = 'http://' + url
        
        try:
            logger.info(f"Проксирование запроса: {url}")
            
            # Создаем запрос
            req = Request(url)
            
            # Копируем метод запроса
            req.method = self.command
            
            # Копируем заголовки из запроса клиента
            for header in self.headers:
                if header.lower() not in ('proxy-authorization', 'proxy-connection', 'connection', 'keep-alive',
                                         'proxy-authenticate', 'trailer', 'te'):
                    req.add_header(header, self.headers[header])
            
            # Добавляем заголовок X-Forwarded-For для маскировки IP
            client_ip = self.client_address[0]
            x_forwarded_for = self.headers.get('X-Forwarded-For', '')
            if x_forwarded_for:
                req.add_header('X-Forwarded-For', f"{x_forwarded_for}, {client_ip}")
            else:
                req.add_header('X-Forwarded-For', client_ip)
            
            # Копируем данные из тела запроса (для POST и др.)
            content_length = int(self.headers.get('Content-Length', 0))
            body_data = self.rfile.read(content_length) if content_length > 0 else None
            
            # Устанавливаем максимальное количество перенаправлений
            max_redirects = 5
            redirect_count = 0
            
            while redirect_count < max_redirects:
                try:
                    # Выполняем запрос
                    with urlopen(req, data=body_data, timeout=30) as response:
                        status_code = response.status
                        
                        # Проверяем, является ли ответ перенаправлением
                        if status_code in (301, 302, 303, 307, 308):
                            redirect_url = response.headers.get('Location')
                            if redirect_url:
                                logger.info(f"Перенаправление на: {redirect_url}")
                                url = redirect_url
                                req = Request(url)
                                req.method = 'GET'  # При перенаправлении используем GET
                                
                                # Копируем заголовки
                                for header in self.headers:
                                    if header.lower() not in ('proxy-authorization', 'proxy-connection', 'connection', 
                                                             'keep-alive', 'proxy-authenticate', 'trailer', 'te', 
                                                             'content-length', 'content-type'):
                                        req.add_header(header, self.headers[header])
                                
                                # Добавляем заголовок X-Forwarded-For
                                if x_forwarded_for:
                                    req.add_header('X-Forwarded-For', f"{x_forwarded_for}, {client_ip}")
                                else:
                                    req.add_header('X-Forwarded-For', client_ip)
                                
                                body_data = None  # Сбрасываем тело запроса при перенаправлении
                                redirect_count += 1
                                continue
                        
                        # Отправляем ответ клиенту
                        self.send_response(status_code)
                        
                        # Копируем заголовки из ответа сервера
                        for header in response.info():
                            if header.lower() not in ('transfer-encoding', 'connection', 'keep-alive', 'proxy-authenticate'):
                                self.send_header(header, response.info()[header])
                        
                        self.send_header('Connection', 'close')
                        self.end_headers()
                        
                        # Копируем тело ответа
                        response_data = response.read()
                        self.wfile.write(response_data)
                        
                        # Записываем статистику
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute(
                            "INSERT INTO stats (username, url, bytes) VALUES (?, ?, ?)",
                            (username, url, len(response_data))
                        )
                        conn.commit()
                        conn.close()
                        
                        # Завершаем цикл перенаправлений
                        break
                
                except HTTPError as e:
                    # Если ошибка связана с перенаправлением, пробуем следовать перенаправлению
                    if e.code in (301, 302, 303, 307, 308) and 'location' in e.headers:
                        redirect_url = e.headers['location']
                        logger.info(f"Перенаправление на: {redirect_url}")
                        url = redirect_url
                        req = Request(url)
                        req.method = 'GET'  # При перенаправлении используем GET
                        
                        # Копируем заголовки
                        for header in self.headers:
                            if header.lower() not in ('proxy-authorization', 'proxy-connection', 'connection', 
                                                     'keep-alive', 'proxy-authenticate', 'trailer', 'te', 
                                                     'content-length', 'content-type'):
                                req.add_header(header, self.headers[header])
                        
                        # Добавляем заголовок X-Forwarded-For
                        if x_forwarded_for:
                            req.add_header('X-Forwarded-For', f"{x_forwarded_for}, {client_ip}")
                        else:
                            req.add_header('X-Forwarded-For', client_ip)
                        
                        body_data = None  # Сбрасываем тело запроса при перенаправлении
                        redirect_count += 1
                        continue
                    
                    # Иначе отправляем клиенту ошибку
                    self.send_response(e.code)
                    self.send_header('Content-Type', 'text/html')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    error_message = f"<html><body><h1>{e.code} {e.reason}</h1><p>{str(e)}</p></body></html>"
                    self.wfile.write(error_message.encode())
                    break
                
                except (URLError, socket.error) as e:
                    self.send_response(503)
                    self.send_header('Content-Type', 'text/html')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    error_message = f"<html><body><h1>503 Service Unavailable</h1><p>{str(e)}</p></body></html>"
                    self.wfile.write(error_message.encode())
                    break
            
            # Если достигли максимального количества перенаправлений
            if redirect_count >= max_redirects:
                self.send_response(310)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Connection', 'close')
                self.end_headers()
                error_message = "<html><body><h1>310 Too many redirects</h1><p>Максимальное количество перенаправлений превышено</p></body></html>"
                self.wfile.write(error_message.encode())
        
        except Exception as e:
            logger.error(f"Ошибка при обработке запроса: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()
            error_message = f"<html><body><h1>500 Internal Server Error</h1><p>{str(e)}</p></body></html>"
            self.wfile.write(error_message.encode())

# Многопоточный HTTP сервер
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# Функция для запуска прокси-сервера
def run_proxy_server(port):
    server_address = ('', port)
    httpd = ThreadingHTTPServer(server_address, ProxyHTTPRequestHandler)
    
    # Проверяем наличие сертификатов
    create_self_signed_cert()
    
    logger.info(f"Прокси-сервер запущен на порту {port}")
    logger.info(f"Настройте браузер для использования прокси: localhost:{port}")
    logger.info(f"Для подключения к веб-панели откройте: http://localhost:{DEFAULT_ADMIN_PORT}")
    
    print(f"Прокси-сервер запущен на порту {port}")
    print(f"Для подключения к веб-панели откройте: http://localhost:{DEFAULT_ADMIN_PORT}")
    
    httpd.serve_forever()

# Инициализация Flask для веб-панели
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['SECRET_KEY'] = secrets.token_hex(16)
bcrypt = Bcrypt(app)

# Маршруты Flask для веб-панели
@app.route('/')
def index():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    # Получаем список пользователей
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, active, created_at FROM users ORDER BY created_at DESC")
    users = [{'id': row[0], 'username': row[1], 'active': row[2], 'created_at': row[3]} for row in cursor.fetchall()]
    
    # Получаем статистику
    cursor.execute("""
        SELECT username, COUNT(*) as requests, SUM(bytes) as total_bytes 
        FROM stats GROUP BY username ORDER BY requests DESC
    """)
    stats = [{'username': row[0], 'requests': row[1], 'bytes': row[2] or 0} for row in cursor.fetchall()]
    
    conn.close()
    
    # Определяем текущую тему
    theme = session.get('theme', 'light')
    
    return render_template('index.html', users=users, stats=stats, theme=theme)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM admins WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and bcrypt.check_password_hash(result[0], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    
    # Определяем текущую тему
    theme = session.get('theme', 'light')
    
    return render_template('login.html', theme=theme)

@app.route('/logout')
def logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('login'))

@app.route('/toggle_theme')
def toggle_theme():
    current_theme = session.get('theme', 'light')
    session['theme'] = 'dark' if current_theme == 'light' else 'light'
    return redirect(request.referrer or url_for('index'))

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Имя пользователя и пароль обязательны', 'danger')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        flash(f'Пользователь {username} успешно добавлен', 'success')
    except sqlite3.IntegrityError:
        flash(f'Пользователь {username} уже существует', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        cursor.execute("DELETE FROM stats WHERE username = ?", (user[0],))
        conn.commit()
        flash(f'Пользователь {user[0]} удален', 'success')
    else:
        flash('Пользователь не найден', 'danger')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/toggle_user/<int:user_id>')
def toggle_user(user_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, active FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        new_status = 0 if user[1] == 1 else 1
        cursor.execute("UPDATE users SET active = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        status_text = "активирован" if new_status == 1 else "деактивирован"
        flash(f'Пользователь {user[0]} {status_text}', 'success')
    else:
        flash('Пользователь не найден', 'danger')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/change_admin_password', methods=['POST'])
def change_admin_password():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash('Все поля обязательны', 'danger')
        return redirect(url_for('index'))
    
    if new_password != confirm_password:
        flash('Новые пароли не совпадают', 'danger')
        return redirect(url_for('index'))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    username = session.get('admin_username')
    cursor.execute("SELECT password FROM admins WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if result and bcrypt.check_password_hash(result[0], current_password):
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        cursor.execute("UPDATE admins SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        flash('Пароль администратора успешно изменен', 'success')
    else:
        flash('Текущий пароль неверный', 'danger')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/clear_stats')
def clear_stats():
    if 'admin_logged_in' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM stats")
    conn.commit()
    conn.close()
    
    flash('Статистика очищена', 'success')
    return redirect(url_for('index'))

# Создание HTML шаблонов для Flask
def create_templates():
    # Создаем директорию для шаблонов, если её нет
    os.makedirs('templates', exist_ok=True)
    
    # Шаблон для страницы входа
    login_html = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в панель управления</title>
    <style>
        /* Общие стили */
        * {
            box-sizing: border-box;
            transition: background-color 0.3s, color 0.3s;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        
        /* Светлая тема */
        body.light {
            background-color: #f5f5f5;
            color: #333;
        }
        
        /* Темная тема */
        body.dark {
            background-color: #222;
            color: #f5f5f5;
        }
        
        .dark a {
            color: #00FFFF;  /* Голубой цвет для всех ссылок в темной теме */
        }
        
        .container {
            width: 400px;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .light .container {
            background-color: #fff;
        }
        
        .dark .container {
            background-color: #333;
        }
        
        h1 {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px 15px;
            border-radius: 5px;
            font-size: 16px;
        }
        
        .light input[type="text"],
        .light input[type="password"] {
            border: 1px solid #ddd;
            background-color: #fff;
            color: #333;
        }
        
        .dark input[type="text"],
        .dark input[type="password"] {
            border: 1px solid #555;
            background-color: #444;
            color: #fff;
        }
        
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        
        .light button {
            background-color: #4285f4;
            color: white;
        }
        
        .dark button {
            background-color: #2b5797;
            color: white;
        }
        
        button:hover {
            opacity: 0.9;
        }
        
        .alerts {
            margin-bottom: 20px;
        }
        
        .alert {
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .theme-switch {
            text-align: center;
            margin-top: 20px;
        }
        
        .theme-switch a {
            text-decoration: none;
            font-size: 14px;
        }
        
        .light .theme-switch a {
            color: #4285f4;  /* Синий цвет для ссылок в светлой теме */
        }
        
        .dark .theme-switch a {
            color: #00FFFF;  /* Голубой цвет для ссылок в темной теме */
        }
    </style>
</head>
<body class="{{ theme }}">
    <div class="container">
        <h1>Вход в панель управления</h1>
        
        {% if get_flashed_messages() %}
        <div class="alerts">
            {% for category, message in get_flashed_messages(with_categories=true) %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
        {% endif %}
        
        <form method="post">
            <div class="form-group">
                <label for="username">Имя пользователя</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Пароль</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Войти</button>
        </form>
        
        <div class="theme-switch">
            <a href="{{ url_for('toggle_theme') }}">
                {% if theme == 'light' %}
                    Переключить на темную тему
                {% else %}
                    Переключить на светлую тему
                {% endif %}
            </a>
        </div>
    </div>
</body>
</html>
    '''
    
    # Шаблон для главной страницы
    index_html = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Панель управления HTTP прокси</title>
    <style>
        /* Общие стили */
        * {
            box-sizing: border-box;
            transition: background-color 0.3s, color 0.3s;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }
        
        /* Светлая тема */
        body.light {
            background-color: #f5f5f5;
            color: #333;
        }
        
        /* Темная тема */
        body.dark {
            background-color: #222;
            color: #f5f5f5;
        }
        
        .dark a {
            color: #00FFFF;  /* Голубой цвет для всех ссылок в темной теме */
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
        }
        
        .light header {
            border-bottom: 1px solid #ddd;
        }
        
        .dark header {
            border-bottom: 1px solid #444;
        }
        
        h1, h2 {
            margin: 0 0 20px 0;
        }
        
        .header-actions {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .btn {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
            border: none;
            margin-left: 10px;
            margin-bottom: 5px;
        }
        
        .light .btn-primary {
            background-color: #4285f4;
            color: white;
        }
        
        .dark .btn-primary {
            background-color: #2b5797;
            color: white;
        }
        
        .light .btn-danger {
            background-color: #dc3545;
            color: white;
        }
        
        .dark .btn-danger {
            background-color: #9e2a33;
            color: white;
        }
        
        .light .btn-success {
            background-color: #28a745;
            color: white;
        }
        
        .dark .btn-success {
            background-color: #1e7e34;
            color: white;
        }
        
        .light .btn-warning {
            background-color: #ffc107;
            color: #333;
        }
        
        .dark .btn-warning {
            background-color: #d39e00;
            color: white;
        }
        
        .btn:hover {
            opacity: 0.9;
        }
        
        .alerts {
            margin-bottom: 20px;
        }
        
        .alert {
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .dark .alert-success {
            background-color: #155724;
            color: #d4edda;
            border: 1px solid #1e7e34;
        }
        
        .dark .alert-danger {
            background-color: #721c24;
            color: #f8d7da;
            border: 1px solid #9e2a33;
        }
        
        .card {
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .light .card {
            background-color: #fff;
        }
        
        .dark .card {
            background-color: #333;
        }
        
        .card-header {
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
            font-weight: 600;
            font-size: 18px;
            border-radius: 8px 8px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .light .card-header {
            border-bottom: 1px solid #ddd;
        }
        
        .dark .card-header {
            border-bottom: 1px solid #444;
        }
        
        .card-body {
            padding: 20px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
        }
        
        .light th {
            background-color: #f8f9fa;
        }
        
        .dark th {
            background-color: #444;
        }
        
        .light tr {
            border-bottom: 1px solid #ddd;
        }
        
        .dark tr {
            border-bottom: 1px solid #444;
        }
        
        .light tbody tr:hover {
            background-color: #f1f1f1;
        }
        
        .dark tbody tr:hover {
            background-color: #3a3a3a;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            border-radius: 5px;
            font-size: 16px;
        }
        
        .light input[type="text"],
        .light input[type="password"] {
            border: 1px solid #ddd;
            background-color: #fff;
            color: #333;
        }
        
        .dark input[type="text"],
        .dark input[type="password"] {
            border: 1px solid #555;
            background-color: #444;
            color: #fff;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 50px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background-color: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .dark .badge-success {
            background-color: #155724;
            color: #d4edda;
        }
        
        .dark .badge-danger {
            background-color: #721c24;
            color: #f8d7da;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            overflow: auto;
        }
        
        .modal-content {
            position: relative;
            margin: 10% auto;
            width: 50%;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        
        .light .modal-content {
            background-color: #fff;
        }
        
        .dark .modal-content {
            background-color: #333;
        }
        
        .close {
            position: absolute;
            right: 15px;
            top: 10px;
            font-size: 24px;
            font-weight: 600;
            cursor: pointer;
        }
        
        .light .close {
            color: #333;
        }
        
        .dark .close {
            color: #f5f5f5;
        }
        
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        
        .config-info {
            margin-top: 20px;
            padding: 15px;
            border-radius: 5px;
        }
        
        .light .config-info {
            background-color: #e9f5ff;
            border: 1px solid #c5e0f5;
        }
        
        .dark .config-info {
            background-color: #2c405a;
            border: 1px solid #3c5a80;
        }
        
        .config-info h3 {
            margin-top: 0;
        }
        
        .config-item {
            margin-bottom: 10px;
        }
        
        .config-label {
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            .modal-content {
                width: 90%;
            }
            
            .header-actions {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .btn {
                margin: 5px 0;
            }
        }
    </style>
</head>
<body class="{{ theme }}">
    <div class="container">
        <header>
            <h1>Панель управления HTTP/HTTPS прокси</h1>
            <div class="header-actions">
                <a href="{{ url_for('toggle_theme') }}" class="btn btn-primary">
                    {% if theme == 'light' %}
                        Темная тема
                    {% else %}
                        Светлая тема
                    {% endif %}
                </a>
                <button class="btn btn-primary" onclick="document.getElementById('changePasswordModal').style.display='block'">
                    Изменить пароль
                </button>
                <a href="{{ url_for('clear_stats') }}" class="btn btn-warning" 
                   onclick="return confirm('Вы уверены, что хотите очистить всю статистику?')">
                    Очистить статистику
                </a>
                <a href="{{ url_for('logout') }}" class="btn btn-danger">Выйти</a>
            </div>
        </header>
        
        {% if get_flashed_messages() %}
        <div class="alerts">
            {% for category, message in get_flashed_messages(with_categories=true) %}
                <div class="alert alert-{{ category }}">{{ message }}</div>
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="config-info">
            <h3>Как настроить браузер</h3>
            <div class="config-item">
                <span class="config-label">HTTP прокси:</span> IP-адрес вашего сервера, порт 8080
            </div>
            <div class="config-item">
                <span class="config-label">HTTPS прокси:</span> тот же адрес и порт (поддерживается)
            </div>
            <div class="config-item">
                <span class="config-label">Настройка Firefox:</span> В настройках сети снимите галочку "Не запрашивать аутентификацию"
            </div>
            <div class="config-item">
                <span class="config-label">Проверка работы:</span> Посетите <a href="http://ip-api.com/json" target="_blank">http://ip-api.com/json</a> для проверки IP-адреса
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <span>Управление пользователями</span>
                    <button class="btn btn-success" onclick="document.getElementById('addUserModal').style.display='block'">
                        Добавить пользователя
                    </button>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Пользователь</th>
                                <th>Статус</th>
                                <th>Дата создания</th>
                                <th>Действия</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in users %}
                            <tr>
                                <td>{{ user.username }}</td>
                                <td>
                                    {% if user.active %}
                                    <span class="badge badge-success">Активен</span>
                                    {% else %}
                                    <span class="badge badge-danger">Неактивен</span>
                                    {% endif %}
                                </td>
                                <td>{{ user.created_at }}</td>
                                <td>
                                    <a href="{{ url_for('toggle_user', user_id=user.id) }}" class="btn btn-primary">
                                        {% if user.active %}
                                        Деактивировать
                                        {% else %}
                                        Активировать
                                        {% endif %}
                                    </a>
                                    <a href="{{ url_for('delete_user', user_id=user.id) }}" class="btn btn-danger" 
                                       onclick="return confirm('Вы уверены, что хотите удалить пользователя {{ user.username }}?')">
                                        Удалить
                                    </a>
                                </td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="4" style="text-align: center;">Пользователи не найдены</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span>Статистика использования</span>
                </div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Пользователь</th>
                                <th>Запросов</th>
                                <th>Объем данных</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for stat in stats %}
                            <tr>
                                <td>{{ stat.username }}</td>
                                <td>{{ stat.requests }}</td>
                                <td>{{ (stat.bytes / 1024 / 1024) | round(2) }} МБ</td>
                            </tr>
                            {% else %}
                            <tr>
                                <td colspan="3" style="text-align: center;">Статистика отсутствует</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Модальное окно для добавления пользователя -->
    <div id="addUserModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="document.getElementById('addUserModal').style.display='none'">&times;</span>
            <h2>Добавить нового пользователя</h2>
            <form method="post" action="{{ url_for('add_user') }}">
                <div class="form-group">
                    <label for="username">Имя пользователя</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Пароль</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-success">Добавить</button>
            </form>
        </div>
    </div>
    
    <!-- Модальное окно для изменения пароля администратора -->
    <div id="changePasswordModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="document.getElementById('changePasswordModal').style.display='none'">&times;</span>
            <h2>Изменить пароль администратора</h2>
            <form method="post" action="{{ url_for('change_admin_password') }}">
                <div class="form-group">
                    <label for="current_password">Текущий пароль</label>
                    <input type="password" id="current_password" name="current_password" required>
                </div>
                <div class="form-group">
                    <label for="new_password">Новый пароль</label>
                    <input type="password" id="new_password" name="new_password" required>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Подтвердите новый пароль</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                <button type="submit" class="btn btn-success">Изменить пароль</button>
            </form>
        </div>
    </div>
    
    <script>
        // Закрытие модальных окон при клике вне их содержимого
        window.onclick = function(event) {
            if (event.target.className === 'modal') {
                event.target.style.display = "none";
            }
        }
    </script>
</body>
</html>
    '''
    
    # Сохраняем шаблоны
    with open('templates/login.html', 'w', encoding='utf-8') as f:
        f.write(login_html)
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    logger.info("HTML шаблоны созданы")

# Основная функция запуска скрипта
def main():
    parser = argparse.ArgumentParser(description='HTTP/HTTPS прокси-сервер с веб-панелью управления')
    parser.add_argument('-pp', '--proxy-port', type=int, default=DEFAULT_PROXY_PORT,
                      help=f'Порт для прокси-сервера (по умолчанию: {DEFAULT_PROXY_PORT})')
    parser.add_argument('-ap', '--admin-port', type=int, default=DEFAULT_ADMIN_PORT,
                      help=f'Порт для веб-панели администратора (по умолчанию: {DEFAULT_ADMIN_PORT})')
    args = parser.parse_args()
    
    # Создаем базу данных и шаблоны
    init_db()
    create_templates()
    
    # Запускаем прокси-сервер в отдельном потоке
    proxy_thread = threading.Thread(
        target=run_proxy_server,
        args=(args.proxy_port,),
        daemon=True
    )
    proxy_thread.start()
    
    # Запускаем веб-панель администратора
    logger.info(f"Веб-панель запущена на порту {args.admin_port}")
    app.run(host='0.0.0.0', port=args.admin_port, debug=False)

if __name__ == '__main__':
    main()
