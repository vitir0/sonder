import asyncio
import os
import base64
import json
import hashlib
import time
from pywebio import start_server
from pywebio.input import *
from pywebio.output import *
from pywebio.session import run_async, local, run_js, info as session_info
from pywebio.exceptions import SessionClosedException
from collections import defaultdict
import glob

# Конфигурация файлов
USERS_FILE = "chat_users.json"
DIALOG_INDEX_FILE = "dialog_index.json"
DIALOG_DIR = "dialogs"
ONLINE_STATUS_FILE = "online_status.json"
ENCRYPTION_KEY_FILE = "chat_key.bin"

# Создаем директорию для диалогов
os.makedirs(DIALOG_DIR, exist_ok=True)

# Генерация ключа шифрования
def get_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = os.urandom(32)  # 256-bit ключ для лучшей безопасности
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)
        return key

# XOR-шифрование
def xor_encrypt(message: str, key: bytes) -> str:
    message_bytes = message.encode()
    encrypted = bytearray()
    for i in range(len(message_bytes)):
        encrypted.append(message_bytes[i] ^ key[i % len(key)])
    return base64.b64encode(encrypted).decode()

# Расшифровка XOR
def xor_decrypt(encrypted_message: str, key: bytes) -> str:
    data = base64.b64decode(encrypted_message)
    decrypted = bytearray()
    for i in range(len(data)):
        decrypted.append(data[i] ^ key[i % len(key)])
    return decrypted.decode()

# Определение типа изображения
def get_image_type(content: bytes) -> str:
    """Определяет тип изображения по магическим числам"""
    if content.startswith(b'\xFF\xD8\xFF'):
        return 'jpeg'
    elif content.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    elif content.startswith(b'GIF87a') or content.startswith(b'GIF89a'):
        return 'gif'
    elif content.startswith(b'RIFF') and content[8:12] == b'WEBP':
        return 'webp'
    return 'jpeg'  # По умолчанию

# Загрузка пользователей
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

# Сохранение пользователей
def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Регистрация нового пользователя
async def register_user():
    users = load_users()
    
    while True:
        data = await input_group("Регистрация", [
            input("Придумайте никнейм", name="nickname", required=True),
            input("Придумайте пароль", name="password", type=PASSWORD, required=True),
            input("Повторите пароль", name="password2", type=PASSWORD, required=True),
            checkbox(name="remember", options=["Запомнить меня"])
        ])
        
        if data['password'] != data['password2']:
            toast("Пароли не совпадают!", color='error')
            continue
            
        if data['nickname'] in users:
            toast("Этот ник уже занят!", color='error')
            continue
            
        if data['nickname'] == '📢':
            toast("Недопустимый ник!", color='error')
            continue
            
        users[data['nickname']] = {
            'password_hash': hash_password(data['password']),
            'created_at': time.time()
        }
        save_users(users)
        toast("Регистрация прошла успешно!", color='success')
        
        # Сохраняем аккаунт в сессии
        local.nickname = data['nickname']
        local.remember = data.get('remember', False)
            
        return data['nickname']

# Авторизация пользователя
async def login_user():
    users = load_users()
    
    while True:
        data = await input_group("Вход в чат", [
            input("Ваш никнейм", name="nickname", required=True),
            input("Ваш пароль", name="password", type=PASSWORD, required=True),
            checkbox(name="remember", options=["Запомнить меня"]),
            actions(name="action", buttons=["Войти", "Отмена"])
        ])
        
        if data['action'] == "Отмена":
            return None
            
        if data['nickname'] not in users:
            toast("Пользователь не найден!", color='error')
            continue
            
        if users[data['nickname']]['password_hash'] != hash_password(data['password']):
            toast("Неверный пароль!", color='error')
            continue
            
        # Сохраняем аккаунт в сессии
        local.nickname = data['nickname']
        local.remember = data.get('remember', False)
            
        return data['nickname']

# Функция получения ключа диалога
def get_dialog_key(user1, user2):
    return f"{min(user1, user2)}_{max(user1, user2)}"

# Загрузка индекса диалогов
def load_dialog_index():
    if os.path.exists(DIALOG_INDEX_FILE):
        try:
            with open(DIALOG_INDEX_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

# Сохранение индекса диалогов
def save_dialog_index(index):
    with open(DIALOG_INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)

# Загрузка истории диалога
def load_dialog_history(user1, user2):
    dialog_key = get_dialog_key(user1, user2)
    file_path = os.path.join(DIALOG_DIR, f"{dialog_key}.json")
    
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except:
            return []
    return []

# Сохранение истории диалога
def save_dialog_history(user1, user2, history):
    dialog_key = get_dialog_key(user1, user2)
    file_path = os.path.join(DIALOG_DIR, f"{dialog_key}.json")
    
    with open(file_path, "w") as f:
        json.dump(history, f, indent=2)
    
    # Обновляем индекс
    index = load_dialog_index()
    participants = sorted([user1, user2])
    
    index[dialog_key] = {
        "participants": participants,
        "last_message": time.time(),
        "unread": index.get(dialog_key, {}).get("unread", 0)
    }
    save_dialog_index(index)

# Загрузка статусов онлайн
def load_online_status():
    if os.path.exists(ONLINE_STATUS_FILE):
        try:
            with open(ONLINE_STATUS_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

# Сохранение статуса
def save_online_status(nickname):
    status = load_online_status()
    status[nickname] = time.time()
    with open(ONLINE_STATUS_FILE, "w") as f:
        json.dump(status, f, indent=2)

# Проверка онлайн-статуса
def is_user_online(nickname):
    """Проверка онлайн-статуса"""
    online_status = load_online_status()
    last_seen = online_status.get(nickname, 0)
    return (time.time() - last_seen) < 300  # 5 минут

# Получение времени последней активности
def get_last_seen(nickname):
    online_status = load_online_status()
    last_seen = online_status.get(nickname, 0)
    if last_seen == 0:
        return "никогда"
    
    delta = int(time.time() - last_seen)
    if delta < 60:
        return "только что"
    elif delta < 3600:
        return f"{delta // 60} мин назад"
    elif delta < 86400:
        return f"{delta // 3600} ч назад"
    else:
        return f"{delta // 86400} дн назад"

# Глобальные переменные
ENCRYPTION_KEY = get_encryption_key()
online_users = {}  # никнейм: timestamp последней активности
MAX_IMAGE_SIZE = 6 * 1024 * 1024  # 2MB

async def clean_inactive_users():
    """Очистка неактивных пользователей"""
    while True:
        await asyncio.sleep(30)  # Проверка каждые 30 секунд
        current_time = time.time()
        
        # Очищаем статусы
        status = load_online_status()
        changed = False
        for nickname, last_active in list(status.items()):
            if current_time - last_active > 300:  # 5 минут без активности
                del status[nickname]
                changed = True
                
        if changed:
            with open(ONLINE_STATUS_FILE, "w") as f:
                json.dump(status, f, indent=2)

async def main():
    # Запускаем очистку неактивных пользователей
    run_async(clean_inactive_users())
    
    # Проверяем сохраненную сессию
    nickname = getattr(local, 'nickname', None)
    remember = getattr(local, 'remember', False)
    
    if nickname:
        put_markdown(f"## 👋 Добро пожаловать обратно, {nickname}!")
    else:
        put_markdown("## 🔒 Secure Messenger")
        
        # Страница выбора действия
        action = await actions("Выберите действие", [
            {'label': 'Войти', 'value': 'login'},
            {'label': 'Зарегистрироваться', 'value': 'register'}
        ])
        
        if action == 'register':
            nickname = await register_user()
            if not nickname:
                return
        else:
            nickname = await login_user()
            if not nickname:
                return
    
    # Обновляем статус
    save_online_status(nickname)
    online_users[nickname] = time.time()

    # Главное меню
    while True:
        clear()
        put_markdown(f"## 👤 Личный кабинет: {nickname}")
        put_markdown(f"**Статус:** 🟢 онлайн")
        
        # Кнопки меню
        choice = await actions("Выберите действие", [
            {'label': '💬 Мои диалоги', 'value': 'dialogs'},
            {'label': '🔍 Найти пользователя', 'value': 'search'},
            {'label': '👥 Все пользователи', 'value': 'users'},
            {'label': '⚙️ Настройки', 'value': 'settings'},
            {'label': '🚪 Выйти', 'value': 'logout'}
        ])
        
        if choice == 'dialogs':
            await show_dialogs(nickname)
        elif choice == 'search':
            await find_user(nickname)
        elif choice == 'users':
            await show_all_users(nickname)
        elif choice == 'settings':
            await show_settings(nickname)
        elif choice == 'logout':
            # Только выход из системы, не удаление аккаунта
            if nickname in online_users:
                del online_users[nickname]
            # Очищаем только сессию, сохраняем пользователя в базе
            local.nickname = None
            toast("Вы вышли из системы!")
            reload_page()
            return

async def show_dialogs(nickname):
    """Показать список диалогов"""
    clear()
    put_markdown(f"### 💬 Мои диалоги")
    
    index = load_dialog_index()
    user_dialogs = []
    
    # Собираем диалоги пользователя
    for dialog_key, data in index.items():
        if nickname in data["participants"]:
            other_user = data["participants"][0] if data["participants"][1] == nickname else data["participants"][1]
            last_message_time = time.strftime("%d.%m.%Y %H:%M", time.localtime(data["last_message"]))
            user_dialogs.append({
                "user": other_user,
                "last_active": data["last_message"],
                "unread": data.get("unread", 0),
                "last_message_time": last_message_time
            })
    
    # Сортируем по последней активности
    user_dialogs.sort(key=lambda x: x["last_active"], reverse=True)
    
    # Показываем диалоги
    if not user_dialogs:
        put_text("У вас пока нет диалогов")
        choice = await actions("", ['Начать новый диалог', 'Назад'])
        if choice == 'Начать новый диалог':
            await find_user(nickname)
        else:
            return
    else:
        options = []
        for dialog in user_dialogs:
            status = "🟢" if is_user_online(dialog["user"]) else "⚪️"
            unread_badge = f" 🔔({dialog['unread']})" if dialog['unread'] > 0 else ""
            label = f"{status} {dialog['user']} {unread_badge} | {dialog['last_message_time']}"
            options.append({'label': label, 'value': dialog["user"]})
        
        options.append({'label': 'Назад', 'value': 'back'})
        
        choice = await actions("Выберите диалог:", buttons=options)
        
        if choice == 'back':
            return
        else:
            await show_dialog(nickname, choice)

async def show_all_users(nickname):
    """Показать всех пользователей"""
    clear()
    put_markdown("### 👥 Все пользователи")
    
    users = load_users()
    online_status = load_online_status()
    
    # Исключаем текущего пользователя
    user_list = [u for u in users.keys() if u != nickname]
    
    if not user_list:
        put_text("Других пользователей не найдено")
        put_button("Назад", onclick=lambda: run_async(main()))
        return
    
    # Сортируем по онлайн-статусу
    user_list.sort(key=lambda u: online_status.get(u, 0), reverse=True)
    
    # Показываем результаты
    options = []
    for user in user_list:
        status = "🟢 онлайн" if is_user_online(user) else f"⚪️ {get_last_seen(user)}"
        options.append({'label': f"👤 {user} | {status}", 'value': user})
    
    options.append({'label': 'Назад', 'value': 'back'})
    
    choice = await actions("Выберите пользователя:", buttons=options)
    
    if choice == 'back':
        return
    else:
        await show_dialog(nickname, choice)

async def find_user(nickname):
    """Поиск пользователя"""
    clear()
    put_markdown("### 🔍 Поиск пользователя")
    
    users = load_users()
    online_status = load_online_status()
    
    # Исключаем текущего пользователя
    user_list = [u for u in users.keys() if u != nickname]
    
    # Исправлено: убрали параметр name
    search = await input("Введите никнейм")
    
    # Фильтрация по поиску
    if search:
        user_list = [u for u in user_list if search.lower() in u.lower()]
    
    if not user_list:
        put_text("Пользователи не найдены")
        put_button("Назад", onclick=lambda: run_async(main()))
        return
    
    # Показываем результаты
    options = []
    for user in user_list:
        status = "🟢 онлайн" if is_user_online(user) else f"⚪️ {get_last_seen(user)}"
        options.append({'label': f"👤 {user} | {status}", 'value': user})
    
    options.append({'label': 'Назад', 'value': 'back'})
    
    choice = await actions("Выберите пользователя:", buttons=options)
    
    if choice == 'back':
        return
    else:
        await show_dialog(nickname, choice)

async def show_dialog(nickname, contact):
    """Показать диалог с пользователем с автообновлением"""
    # Обновляем статус
    save_online_status(nickname)
    
    # Загружаем историю
    history = load_dialog_history(nickname, contact)
    
    # Сбрасываем счетчик непрочитанных
    dialog_key = get_dialog_key(nickname, contact)
    index = load_dialog_index()
    if dialog_key in index:
        index[dialog_key]["unread"] = 0
        save_dialog_index(index)
    
    clear()
    
    # Заголовок диалога
    status = "🟢 онлайн" if is_user_online(contact) else f"⚪️ {get_last_seen(contact)}"
    put_markdown(f"### 💬 Диалог с {contact} ({status})")
    
    # История сообщений
    msg_box = output()
    put_scrollable(msg_box, height=300, keep_bottom=True)
    
    # Показать историю
    for msg in history:
        if msg['type'] == 'text':
            try:
                decrypted = xor_decrypt(msg['content'], ENCRYPTION_KEY)
                sender = "Вы" if msg['sender'] == nickname else contact
                timestamp = time.strftime("%H:%M", time.localtime(msg['timestamp']))
                msg_box.append(put_markdown(f"**{sender}** ({timestamp}): {decrypted}"))
            except:
                msg_box.append(put_markdown(f"**Ошибка расшифровки сообщения**"))
        elif msg['type'] == 'image':
            sender = "Вы" if msg['sender'] == nickname else contact
            timestamp = time.strftime("%H:%M", time.localtime(msg['timestamp']))
            msg_box.append(put_markdown(f"**{sender}** ({timestamp}) отправил(а) изображение:"))
            msg_box.append(put_image(msg['data']))
    
    # Флаг для контроля обновления
    local.active_dialog = True

    async def check_for_updates():
        """Фоновая задача для проверки новых сообщений"""
        last_count = len(history)
        while getattr(local, 'active_dialog', False):
            await asyncio.sleep(2)  # Проверка каждые 2 секунды
            current_history = load_dialog_history(nickname, contact)
            
            # Если появились новые сообщения
            if len(current_history) > last_count:
                # Показываем только новые сообщения (от контакта)
                for msg in current_history[last_count:]:
                    if msg['sender'] == contact:  # Только сообщения от собеседника
                        if msg['type'] == 'text':
                            try:
                                decrypted = xor_decrypt(msg['content'], ENCRYPTION_KEY)
                                timestamp = time.strftime("%H:%M", time.localtime(msg['timestamp']))
                                msg_box.append(put_markdown(f"**{contact}** ({timestamp}): {decrypted}"))
                            except:
                                msg_box.append(put_markdown(f"**Ошибка расшифровки сообщения**"))
                        elif msg['type'] == 'image':
                            timestamp = time.strftime("%H:%M", time.localtime(msg['timestamp']))
                            msg_box.append(put_markdown(f"**{contact}** ({timestamp}) отправил(а) изображение:"))
                            msg_box.append(put_image(msg['data']))
                
                last_count = len(current_history)

    # Запускаем фоновую задачу
    run_async(check_for_updates())
    
    # Поле ввода сообщения всегда видимо
    try:
        while True:
            # Группа с полем ввода и кнопками
            data = await input_group("💬 Новое сообщение", [
                input(placeholder="Введите сообщение...", name="msg"),
                actions(name="cmd", buttons=[
                    "Отправить", 
                    {'label': "📷 Фото", 'value': 'photo'},
                    {'label': "🗑️ Очистить историю", 'value': 'clear'},
                    {'label': "⬅️ Назад", 'type': 'cancel'}
                ])
            ])
            
            if data is None:  # Нажата кнопка "Назад"
                break
                
            if data['cmd'] == 'clear':
                save_dialog_history(nickname, contact, [])
                toast("История диалога очищена!", color='success')
                # Перезагружаем диалог
                await show_dialog(nickname, contact)
                return
                
            elif data['cmd'] == 'photo':
                # Загрузка изображения
                try:
                    img_info = await file_upload(
                        "Загрузите изображение (JPG, PNG, GIF)", 
                        accept="image/*", 
                        max_size=MAX_IMAGE_SIZE
                    )
                    
                    if img_info:
                        # Определяем тип изображения
                        img_type = get_image_type(img_info['content'])
                        
                        # Формируем base64 строку для изображения
                        img_data = base64.b64encode(img_info['content']).decode('utf-8')
                        img_src = f"data:image/{img_type};base64,{img_data}"
                        
                        # Сохраняем в историю
                        new_message = {
                            'type': 'image',
                            'sender': nickname,
                            'data': img_src,
                            'timestamp': time.time()
                        }
                        
                        history.append(new_message)
                        save_dialog_history(nickname, contact, history)
                        
                        # Показываем сообщение
                        timestamp = time.strftime("%H:%M", time.localtime())
                        msg_box.append(put_markdown(f"**Вы** ({timestamp}) отправили изображение:"))
                        msg_box.append(put_image(img_src))
                except Exception as e:
                    toast(f"Ошибка загрузки изображения: {str(e)}", color='error')
                    
            elif data['cmd'] == "Отправить" and data['msg'].strip():
                # Шифруем и сохраняем сообщение
                encrypted = xor_encrypt(data['msg'], ENCRYPTION_KEY)
                new_message = {
                    'type': 'text',
                    'sender': nickname,
                    'content': encrypted,
                    'timestamp': time.time()
                }
                
                history.append(new_message)
                save_dialog_history(nickname, contact, history)
                
                # Показываем сообщение
                timestamp = time.strftime("%H:%M", time.localtime())
                msg_box.append(put_markdown(f"**Вы** ({timestamp}): {data['msg']}"))
    finally:
        # Останавливаем фоновую задачу при выходе
        local.active_dialog = False
    
    # Возврат к списку диалогов
    await show_dialogs(nickname)

async def show_settings(nickname):
    """Настройки аккаунта"""
    clear()
    put_markdown(f"### ⚙️ Настройки аккаунта")
    
    action = await actions("Выберите действие", [
        {'label': '✏️ Изменить пароль', 'value': 'password'},
        {'label': '⬅️ Назад', 'value': 'back'}
    ])
    
    if action == 'back':
        return
    
    if action == 'password':
        await change_password(nickname)

async def change_password(nickname):
    """Изменение пароля"""
    users = load_users()
    
    data = await input_group("Изменение пароля", [
        input("Текущий пароль", name="current", type=PASSWORD, required=True),
        input("Новый пароль", name="new", type=PASSWORD, required=True),
        input("Повторите новый пароль", name="new2", type=PASSWORD, required=True)
    ])
    
    if users[nickname]['password_hash'] != hash_password(data['current']):
        toast("Неверный текущий пароль!", color='error')
        return
        
    if data['new'] != data['new2']:
        toast("Новые пароли не совпадают!", color='error')
        return
        
    users[nickname]['password_hash'] = hash_password(data['new'])
    save_users(users)
    toast("Пароль успешно изменен!", color='success')
    put_button("Назад", onclick=lambda: run_async(show_settings(nickname)))

def reload_page():
    """Функция для безопасной перезагрузки страницы"""
    try:
        run_js('window.location.reload()')
    except:
        toast("Пожалуйста, обновите страницу вручную", color='error')

if __name__ == "__main__":
    start_server(
        main, 
        port=8080, 
        host='0.0.0.0',
        debug=True,
        cdn=False,
        allowed_origins="*",
        session_expire_seconds=3600 * 24 * 7,  # 1 неделя
        reconnect_timeout=60,
    )
