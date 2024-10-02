import mimetypes
import socket
import logging
from pathlib import Path
from datetime import datetime
import threading
from urllib.parse import urlparse, unquote_plus
from http.server import HTTPServer, BaseHTTPRequestHandler
from multiprocessing import Process
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi


BASE_DIR = Path(__file__).parent
CHUNK_SIZE = 1024
HTTP_PORT = 3000
SOCKET_PORT = 5000
HTTP_HOST = "0.0.0.0"
SOCKET_HOST = "127.0.0.1"
uri = "mongodb://mongodb:27017"

class HttpHandler(BaseHTTPRequestHandler):
    """
    Основний клас, який обробляє HTTP-запити.
    """

    def do_GET(self):
        """
        Обробка GET-запитів.
        """
        router = urlparse(self.path).path
        self.route_request(router)

    def route_request(self, router):
        """
        Маршрутизація запиту.
        """
        match router:
            case "/":
                self.send_html("index.html")
            case "/message":
                self.send_html("message.html")
            case _:
                file = BASE_DIR.joinpath(router[1:])
                if file.exists():
                    self.send_static(file)
                else:
                    self.send_error_page()

    def send_error_page(self):
        """
        Відправка сторінки помилки.
        """
        self.send_html("error.html", 404)

    
    def do_POST(self):
        """
        Обробка POST-запитів.
        """
        size = int(self.headers["Content-Length"])
        data = self.get_post_data(size)
        self.send_data_via_socket(data)
        self.redirect_to_home()

    def get_post_data(self, size):
        """
        Отримання даних POST-запиту.
        
        :param size: Розмір даних
        :return: Дані запиту
        """
        return self.rfile.read(size)

    def send_data_via_socket(self, data):
        """
        Відправка даних через сокет.
        
        :param data: Дані для відправки
        """
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SOCKET_HOST, SOCKET_PORT))
            client_socket.sendall(data)
            client_socket.close()
        except socket.error:
            logging.error("Помилка під час відправки даних через сокет")

    def redirect_to_home(self):
        """
        Перенаправлення клієнта на головну сторінку.
        """
        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    
    def send_html(self, filename, status=200):
        """
        Відправка HTML-файлу клієнту.
        
        :param filename: Ім'я HTML-файлу
        :param status: HTTP статус відповіді
        """
        self.send_response(status)
        self.send_html_headers()
        self.send_file_contents(filename)

    def send_html_headers(self):
        """
        Відправка заголовків для HTML-файлу.
        """
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def send_file_contents(self, filename):
        """
        Читання і відправка змісту файлу.
        
        :param filename: Ім'я файлу
        """
        try:
            with open(filename, "rb") as f:
                self.wfile.write(f.read())
        except FileNotFoundError:
            logging.error(f"Файл {filename} не знайдено")


    def send_static(self, filename, status=200):
        """
        Відправка статичного файлу клієнту (CSS, JS, зображення тощо).
        
        :param filename: Ім'я файлу
        :param status: HTTP статус відповіді
        """
        self.send_response(status)
        self.send_static_headers(filename)
        self.send_file_contents(filename)

    def send_static_headers(self, filename):
        """
        Відправка заголовків для статичного файлу.
        
        :param filename: Ім'я файлу
        """
        mimetype = mimetypes.guess_type(filename)[0] or "text/plain"
        self.send_header("Content-type", mimetype)
        self.end_headers()

def start_http_server(server_class=HTTPServer, handler_class=HttpHandler):
    """
    Запуск HTTP-сервера для обробки запитів.
    """
    try:
        http = create_http_server(server_class, handler_class)
        serve_http_requests(http)
    except KeyboardInterrupt:
        logging.info('Зупинка сервера')
    except Exception as e:
        logging.error(f"Помилка сервера: {e}")
    finally:
        stop_http_server(http)

def create_http_server(server_class, handler_class):
    """
    Створення екземпляра HTTP-сервера.
    
    :param server_class: Клас HTTP-сервера
    :param handler_class: Клас обробника запитів
    :return: Екземпляр сервера
    """
    server_address = (HTTP_HOST, HTTP_PORT)
    logging.info(f"HTTP сервер запущено: http://{HTTP_HOST}:{HTTP_PORT}")
    return server_class(server_address, handler_class)

def serve_http_requests(http):
    """
    Обробка запитів на сервері.
    
    :param http: Екземпляр сервера
    """
    http.serve_forever()

def stop_http_server(http):
    """
    Зупинка сервера.
    
    :param http: Екземпляр сервера
    """
    logging.info("HTTP сервер зупинено")
    http.server_close()


def save_data_to_db(data):
    """
    Збереження даних у базу MongoDB.
    
    :param data: Дані для збереження (форматовано у вигляді ключ-значення)
    """
    client = MongoClient(uri, server_api=ServerApi("1"))
    db = client.masage_db
    parsed_data = parse_data(data)
    if parsed_data:
        insert_data_into_db(db, parsed_data)
    client.close()

def parse_data(data):
    """
    Парсинг отриманих даних з запиту.
    
    :param data: Дані з запиту
    :return: Відпарсені дані як словник
    """
    parsed_data = {}
    try:
        data = unquote_plus(data)
        for el in data.split('&'):
            parts = el.split('=', 1)
            if len(parts) == 2:
                key, value = parts
                parsed_data[key] = value
            else:
                logging.warning(f"Помилка в рядку: {el}")

        # Додаємо поточний час до словника
        parsed_data["date"] = str(datetime.now())
        return parsed_data

    except Exception as e:
        logging.error(f"Помилка при парсингу даних: {e}")
        return None

def insert_data_into_db(db, data):
    """
    Вставка даних в MongoDB.
    
    :param db: Об'єкт бази даних
    :param data: Дані для збереження
    """
    try:
        db.messages.insert_one(data)
        logging.info(f"Дані успішно збережено: {data}")
    except Exception as e:
        logging.error(f"Помилка при збереженні даних у БД: {e}")


def receive_data(conn):
    """
    Отримує дані від клієнта.
    
    :param conn: З'єднання з клієнтом
    :return: Отримані дані
    """
    data = conn.recv(CHUNK_SIZE)
    full_data = b""
    while data:
        full_data += data
        data = conn.recv(CHUNK_SIZE)
    return full_data.decode()

def process_data(data, addr):
    """
    Обробляє отримані дані та зберігає їх у базу даних.
    
    :param data: Дані для обробки
    :param addr: Адреса клієнта
    """
    logging.info(f"Отримано дані від {addr}: {data}")
    save_data_to_db(data)


def handle_client(conn, addr):
    """
    Обробка клієнтських з'єднань у окремому потоці.
    
    :param conn: З'єднання з клієнтом
    :param addr: Адреса клієнта
    """
    logging.info(f"Підключення від {addr}")
    try:
        data = receive_data(conn)  # Отримання даних
        process_data(data, addr)    # Обробка даних
    except Exception as e:
        logging.error(f"Помилка під час обробки клієнта: {e}")
    finally:
        conn.close()
        logging.info(f"З'єднання з {addr} завершено")  # Закриття з'єднання

def accept_connections(s):
    """
    Приймає нові підключення та запускає потоки для їх обробки.
    
    :param s: Сокет сервера
    """
    while True:
        conn, addr = s.accept()  # Приймає з'єднання від клієнта
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()  # Запускає новий потік для кожного клієнта

def start_socket_server():
    """
    Запуск серверу для обробки сокет-запитів (TCP) з багатопотоковою обробкою.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SOCKET_HOST, SOCKET_PORT))
    s.listen(5)  # TCP-сервер слухає з'єднання
    logging.info(f"TCP сокет сервер запущено: socket://{SOCKET_HOST}:{SOCKET_PORT}")
    try:
        accept_connections(s)  # Приймає з'єднання
    except Exception as e:
        logging.error(f"Помилка сокет-сервера: {e}")
    finally:
        s.close()
        logging.info("Сокет сервер зупинено")




if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(threadName)s - %(message)s"
    )
    http_process = Process(target=start_http_server, name="HTTP_Server")
    socket_process = Process(target=start_socket_server, name="SOCKET_Server")

    http_process.start()
    socket_process.start()

    http_process.join()
    socket_process.join()
