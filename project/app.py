from flask import Flask, request, render_template_string
from markupsafe import escape
import logging
import socket
import requests
import re
import threading
import queue

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PenTestScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.hostname = self.get_hostname()
        self.ip = self.get_ip()
        self.ports_to_check = [80, 443]
        self.open_ports = []
        self.common_paths = ['admin', 'login']
        self.found_paths = []

    def get_hostname(self):
        hostname = self.target.replace('http://', '').replace('https://', '').split('/')[0]
        logging.debug(f"Извлечен hostname: {hostname}")
        return hostname

    def get_ip(self):
        try:
            ip_address = socket.gethostbyname(self.get_hostname())
            logging.info(f"IP-адрес для {self.get_hostname()}: {ip_address}")
            return f"IP-адрес сайта: {ip_address}", ip_address
        except socket.gaierror as e:
            logging.error(f"Не удалось определить IP для {self.get_hostname()}: {e}")
            return f"Не удалось определить IP: {e}", None

    def check_site(self):
        try:
            response = requests.get(self.target, timeout=2)
            logging.info(f"Статус сайта {self.target}: {response.status_code}")
            return f"Статус сайта: {response.status_code}"
        except requests.RequestException as e:
            logging.error(f"Ошибка доступа к сайту {self.target}: {e}")
            return f"Ошибка доступа к сайту: {e}"

    def check_port(self, port, result_queue):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.get_hostname(), port))
                if result == 0:
                    logging.info(f"Порт {port} открыт на {self.get_hostname()}")
                    result_queue.put((port, True))
                else:
                    logging.debug(f"Порт {port} закрыт на {self.get_hostname()}")
                    result_queue.put((port, False))
        except Exception as e:
            logging.error(f"Ошибка при проверке порта {port} на {self.get_hostname()}: {e}")
            result_queue.put((port, False))

    def scan_ports(self):
        results = ["Сканирование портов..."]
        result_queue = queue.Queue()
        threads = []

        for port in self.ports_to_check:
            t = threading.Thread(target=self.check_port, args=(port, result_queue))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=2)

        while not result_queue.empty():
            port, is_open = result_queue.get()
            if is_open:
                results.append(f"Порт {port} открыт")
                self.open_ports.append(port)

        results.append(f"Открытые порты: {self.open_ports if self.open_ports else 'Нет открытых портов'}")
        logging.debug(f"Результаты сканирования портов: {results}")
        return results

    def scan_paths(self):
        results = ["Поиск популярных путей..."]
        for path in self.common_paths:
            url = f"{self.target}/{path}"
            try:
                resp = requests.get(url, timeout=2)
                if resp.status_code == 200:
                    logging.info(f"Обнаружен путь: {url}")
                    results.append(f"Обнаружен путь: {url}")
                    self.found_paths.append(url)
            except requests.RequestException as e:
                logging.warning(f"Ошибка при проверке пути {url}: {e}")
        if not self.found_paths:
            results.append("Популярные пути не найдены.")
        logging.debug(f"Результаты сканирования путей: {results}")
        return results

    def check_cms_versions(self):
        results = ["Проверка CMS..."]
        cms_signatures = {
            "WordPress": ["wp-login.php"],
            "Joomla": ["administrator/"]
        }
        for cms_name, paths in cms_signatures.items():
            for p in paths:
                url = f"{self.target}/{p}"
                try:
                    resp = requests.get(url, timeout=2)
                    if resp.status_code == 200:
                        logging.info(f"Обнаружена CMS {cms_name} по пути {url}")
                        results.append(f"Обнаружена CMS: {cms_name} по пути {url}")
                except requests.RequestException as e:
                    logging.warning(f"Ошибка при проверке CMS по пути {url}: {e}")
        if len(results) == 1:
            results.append("CMS не обнаружена.")
        logging.debug(f"Результаты проверки CMS: {results}")
        return results

    def attempt_sql_injection(self):
        results = ["Проверка на SQL-инъекции..."]
        test_payloads = ["' OR '1'='1"]
        test_url_base = f"{self.target}/search.php?q="
        for payload in test_payloads:
            url = test_url_base + payload
            try:
                resp = requests.get(url, timeout=2)
                if any(keyword in resp.text.lower() for keyword in ["sql syntax", "mysql", "you have an error"]):
                    logging.warning(f"Возможная уязвимость SQL Injection по адресу: {url}")
                    results.append(f"Возможная уязвимость SQL Injection по адресу: {url}")
                else:
                    results.append(f"Нет признаков SQL Injection по адресу: {url}")
            except requests.RequestException as e:
                logging.warning(f"Ошибка при проверке SQL-инъекции по адресу {url}: {e}")
        logging.debug(f"Результаты проверки SQL-инъекций: {results}")
        return results

    def attempt_admin_login(self):
        results = ["Проверка админ-панелей..."]
        admin_paths = ['admin/']
        for path in admin_paths:
            url = f"{self.target}/{path}"
            try:
                resp = requests.get(url, timeout=2)
                if resp.status_code == 200 and ("login" in resp.text.lower() or "admin" in resp.text.lower()):
                    logging.info(f"Возможен доступ к админке по адресу: {url}")
                    results.append(f"Возможен доступ к админке по адресу: {url}")
                else:
                    results.append(f"Админка по адресу {url} недоступна или требует авторизации.")
            except requests.RequestException as e:
                logging.warning(f"Ошибка при проверке админ-панели по адресу {url}: {e}")
        logging.debug(f"Результаты проверки админ-панелей: {results}")
        return results


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <title>LOL ITS SO GOOD MAYBE???</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            background: linear-gradient(135deg, #1a202c, #2d3748);
            color: #e2e8f0;
        }
        .card {
            background: #2d3748;
            border: 1px solid #4a5568;
        }
        .input-field {
            transition: all 0.3s ease;
        }
        .input-field:focus {
            border-color: #68d391;
            box-shadow: 0 0 0 3px rgba(104, 211, 145, 0.2);
        }
        .checkbox-label:hover {
            background: #4a5568;
            border-radius: 0.5rem;
        }
        .result-card {
            transition: transform 0.3s ease;
        }
        .result-card:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="card p-8 rounded-xl shadow-2xl w-full max-w-3xl">
        <h1 class="text-4xl font-extrabold text-center text-green-400 mb-8">its so good for just people lmao dont use this if u dont know about pentest man LO0OOOL</h1>
        <form method="POST" class="flex flex-col gap-6">
            <input type="text" name="target_url" placeholder="Введите URL сайта (например, https://example.com)"
                   required class="p-4 bg-gray-800 text-gray-200 border border-gray-600 rounded-lg input-field focus:outline-none focus:border-green-400"
                   value="{{ request.form.get('target_url', '') }}">
            <div class="grid grid-cols-2 gap-4">
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="check_site" checked class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Проверка статуса сайта</span>
                </label>
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="scan_ports" class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Сканирование портов</span>
                </label>
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="scan_paths" checked class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Поиск популярных путей</span>
                </label>
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="check_cms" checked class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Проверка CMS</span>
                </label>
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="sql_injection" class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Проверка SQL-инъекций</span>
                </label>
                <label class="checkbox-label flex items-center gap-3 p-3 cursor-pointer">
                    <input type="checkbox" name="tests" value="admin_login" class="h-5 w-5 text-green-400 bg-gray-700 border-gray-600 rounded focus:ring-green-400">
                    <span>Проверка админ-панелей</span>
                </label>
            </div>
            <button type="submit" class="bg-green-500 text-gray-900 p-4 rounded-lg hover:bg-green-600 transition duration-300 font-semibold">
                Запустить сканирование
            </button>
        </form>
        {% if error %}
            <div class="mt-6 p-4 bg-red-900 text-red-200 rounded-lg text-center">
                <span class="font-semibold">Ошибка:</span> {{ error }}
            </div>
        {% endif %}
        {% if results %}
            <div class="mt-6 space-y-4">
                <h2 class="text-2xl font-semibold text-green-400">Результаты сканирования:</h2>
                {% for result in results %}
                    <div class="result-card p-4 bg-gray-800 rounded-lg border border-gray-600 flex items-center gap-3">
                        <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        <span>{{ result | safe }}</span>
                    </div>
                {% endfor %}
            </div>
        {% else %}
            <div class="mt-6 p-4 bg-yellow-900 text-yellow-200 rounded-lg text-center">
                Нет результатов. Введите URL, выберите тесты и попробуйте снова.
            </div>
        {% endif %}
        {% if sqlmap_note %}
            <div class="mt-6 p-4 bg-blue-900 text-blue-200 rounded-lg text-center">
                {{ sqlmap_note | safe }}
            </div>
        {% endif %}
        {% if debug_info %}
            <div class="mt-6 p-4 bg-gray-700 text-gray-200 rounded-lg">
                <h3 class="font-semibold text-green-400">Отладочная информация:</h3>
                <pre class="text-sm">{{ debug_info }}</pre>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    error = None
    sqlmap_note = None
    debug_info = None

    logging.debug("Получен запрос на маршрут /")

    if request.method == 'POST':
        target_url = request.form.get('target_url')
        tests = request.form.getlist('tests')

        logging.debug(f"Получены данные формы: target_url={target_url}, tests={tests}")

        if not target_url:
            error = "Пожалуйста, введите URL."
            logging.warning("Пустой URL")
        elif not target_url.startswith(('http://', 'https://')):
            error = "URL должен начинать с http:// или https://"
            logging.warning(f"Некорректный URL: {target_url}")
        elif not tests:
            error = "Выберите хотя бы один тест."
            logging.warning("Тесты не выбраны")
        else:
            debug_info = f"URL: {target_url}\nВыбранные тесты: {', '.join(tests)}"
            logging.info(f"Сканирование URL: {target_url} с тестами: {tests}")
            try:
                scanner = PenTestScanner(target_url)
                if 'check_site' in tests:
                    results.append(scanner.check_site())
                if 'scan_ports' in tests:
                    results.extend(scanner.scan_ports())
                if 'scan_paths' in tests:
                    results.extend(scanner.scan_paths())
                if 'check_cms' in tests:
                    results.extend(scanner.check_cms_versions())
                if 'sql_injection' in tests:
                    results.extend(scanner.attempt_sql_injection())
                if 'admin_login' in tests:
                    results.extend(scanner.attempt_admin_login())
                sqlmap_note = "Примечание: Автоматический запуск sqlmap не поддерживается. Установите sqlmap локально и используйте: <code>sqlmap -u {}</code>".format(escape(target_url))
                logging.debug(f"Результаты сканирования: {results}")
            except Exception as e:
                error = f"Ошибка при сканировании: {str(e)}"
                logging.error(f"Ошибка при сканировании {target_url}: {e}")

    return render_template_string(HTML_TEMPLATE, results=results, error=error, sqlmap_note=sqlmap_note, debug_info=debug_info)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
