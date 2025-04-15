import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash # Используем для хеширования паролей в Flask
from dotenv import load_dotenv
import plotly.graph_objects as go
import plotly.io as pio
import pandas as pd
from functools import wraps

# Импортируем наш API базы данных
from db_api import DatabaseAPI, _hash_password, _list_to_str, _str_to_list, OP_INCOME, OP_SPEND, create_test_sample 

# Загрузка переменных окружения (для SECRET_KEY)
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-fallback-secret-key') # Важно для сессий

# --- Настройка Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Страница, на которую перенаправлять неавторизованных пользователей
login_manager.login_message = "Пожалуйста, войдите, чтобы получить доступ к этой странице."
login_manager.login_message_category = "warning"

# --- Инициализация API БД ---
# Убедись, что имя файла БД совпадает с тем, что используется в db_api.py
db = DatabaseAPI("app_database.db")

# --- Модель пользователя для Flask-Login ---
class User(UserMixin):
    def __init__(self, id, login, admin, friends):
        self.id = id
        self.login = login
        self.admin = bool(admin)
        self.friends = friends # Список ID друзей

    @staticmethod
    def get(user_id):
        user_data = db.get_user_by_id(user_id, user_id) # Используем user_id как acting_user_id для самопроверки
        if user_data:
            # Преобразуем строку друзей обратно в список int для объекта User
            friends_list = _str_to_list(db._get_user_info(user_id)['friends']) if db._get_user_info(user_id) else []
            return User(user_data['user_id'], user_data['login'], user_data['admin'], friends_list)
        return None

@login_manager.user_loader
def load_user(user_id):
    """Загружает пользователя по ID для Flask-Login."""
    return User.get(int(user_id))

# --- Декоратор для проверки прав администратора ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.admin:
            flash("Требуются права администратора для доступа к этой странице.", "danger")
            return redirect(url_for('index'))
        # Дополнительно проверим, не пытается ли админ просматривать несуществующего пользователя
        if 'user_id' in kwargs and 'selected_user_id' in session:
             if kwargs['user_id'] != session['selected_user_id']:
                 # Если админ перешел по прямой ссылке на ресурс другого пользователя,
                 # не выбрав его через /admin/view_as, сбросим сессию просмотра
                 session.pop('selected_user_id', None)
                 session.pop('selected_user_login', None)

        return f(*args, **kwargs)
    return decorated_function

# --- Хелпер для определения ID пользователя для запросов к API ---
def get_effective_user_id():
    """Возвращает ID пользователя, от имени которого выполняются действия."""
    if current_user.is_authenticated and current_user.admin and 'selected_user_id' in session:
        # Админ просматривает как другой пользователь
        return session['selected_user_id']
    elif current_user.is_authenticated:
        # Обычный пользователь или админ действует от своего имени
        return current_user.id
    else:
        # Неавторизованный пользователь (не должно происходить на защищенных роутах)
        return None

def get_effective_user_login():
     """Возвращает логин пользователя, от имени которого выполняются действия."""
     if current_user.is_authenticated and current_user.admin and 'selected_user_login' in session:
        return session['selected_user_login']
     elif current_user.is_authenticated:
        return current_user.login
     else:
        return None

# --- Маршруты (Routes) ---

@app.route('/')
def index():
    """Главная страница."""
    return render_template('index.html')

# --- Аутентификация ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Страница регистрации."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        description = request.form.get('description')

        if not login or not password or not password_confirm:
            flash('Необходимо заполнить логин и оба поля пароля.', 'warning')
            return redirect(url_for('register'))

        if password != password_confirm:
            flash('Пароли не совпадают.', 'warning')
            return redirect(url_for('register'))

        # Проверка, существует ли пользователь с таким логином
        existing_user = db.get_user_by_login(login)
        if existing_user:
            flash('Пользователь с таким логином уже существует.', 'warning')
            return redirect(url_for('register'))

        # Добавляем пользователя (acting_user_id=None для саморегистрации)
        # Используем werkzeug для хеширования пароля перед сохранением через наш API
        # Наш API ожидает уже хешированный пароль, но в веб-приложении лучше хешировать здесь.
        # Поэтому, изменим db_api.py add_user, чтобы он ПРИНИМАЛ хеш, а не хешировал сам
        # Или создадим новую функцию в API или передадим пароль как есть, а API будет хешировать?
        # Давайте сделаем так, чтобы API хешировал пароль. Так безопаснее.
        # В db_api.py: _hash_password используется внутри add_user. Все ОК.

        new_user_id = db.add_user(acting_user_id=None, # Разрешаем саморегистрацию
                                  login=login,
                                  password=password, # API сам захэширует
                                  admin=False, # Обычные пользователи не могут регистрироваться как админы
                                  description=description)

        if new_user_id:
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Произошла ошибка при регистрации. Попробуйте снова.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Уже вошел - на дашборд

    if request.method == 'POST':
        login_form = request.form.get('login')
        password_form = request.form.get('password')
        remember = True if request.form.get('remember') else False

        if not login_form or not password_form:
            flash('Введите логин и пароль.', 'warning')
            return redirect(url_for('login'))

        user_data = db.get_user_by_login(login_form)

        # Проверяем пользователя и пароль
        # Используем _hash_password из db_api для сравнения
        if user_data and user_data['password'] == _hash_password(password_form):
            # Пароль верный, создаем объект User для Flask-Login
            user = User.get(user_data['user_id'])
            if user:
                login_user(user, remember=remember)
                # Сбрасываем режим просмотра другого пользователя при логине
                session.pop('selected_user_id', None)
                session.pop('selected_user_login', None)
                flash(f'Добро пожаловать, {user.login}!', 'success')
                # Перенаправляем на страницу, куда пользователь хотел попасть, или на дашборд
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                 flash('Не удалось загрузить данные пользователя после входа.', 'danger')
        else:
            flash('Неверный логин или пароль.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Выход пользователя."""
    logout_user()
    session.pop('selected_user_id', None) # Очищаем просмотр от имени другого пользователя
    session.pop('selected_user_login', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

# --- Основные разделы приложения ---

@app.route('/dashboard')
@login_required
def dashboard():
    """Главная панель пользователя со сводкой."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    records = db.get_accounting_records_for_user(eff_user_id, limit=10000) # Получаем все для расчета

    total_sum = 0
    sphere_sums = {}
    location_sums = {}

    # Получаем имена сфер и локаций для пользователя один раз
    user_spheres = {s['sphere_id']: s['name'] for s in db.get_spheres_for_user(eff_user_id)}
    user_locations = {l['location_id']: l['name'] for l in db.get_locations_for_user(eff_user_id)}

    for record in records:
        amount = record['sum']
        if record['operation_type'] == 'Spend':
            amount = -amount # Расходы вычитаем

        # Добавляем к общей сумме (трансферы не влияют на общую сумму)
        if not record['is_transfer']:
            total_sum += amount

        # Суммы по сферам (считаем только не-трансферы)
        sphere_id = record.get('sphere_id')
        if sphere_id and not record['is_transfer']:
            sphere_name = user_spheres.get(sphere_id, f"Сфера {sphere_id}") # Используем имя, если есть
            sphere_sums[sphere_name] = sphere_sums.get(sphere_name, 0) + amount

        # Суммы по локациям (считаем баланс на каждой локации)
        # Трансферы влияют на баланс локаций
        location_id = record.get('location_id')
        if location_id:
            location_name = user_locations.get(location_id, f"Локация {location_id}") # Используем имя
            location_sums[location_name] = location_sums.get(location_name, 0) + amount


    # --- Генерация Графиков ---
    sphere_chart_html = None
    location_chart_html = None

    # График по сферам (только положительные балансы для наглядности пирога)
    positive_sphere_sums = {name: val for name, val in sphere_sums.items() if val > 0}
    if positive_sphere_sums:
        total_positive_spheres = sum(positive_sphere_sums.values())
        sphere_labels = [f"{name} ({val:.2f} ₽ - {val/total_positive_spheres:.1%})" for name, val in positive_sphere_sums.items()]
        sphere_values = list(positive_sphere_sums.values())
        fig_sphere = go.Figure(data=[go.Pie(labels=sphere_labels, values=sphere_values, hole=.3)])
        fig_sphere.update_layout(title_text='Распределение средств по сферам (доходы > расходы)')
        sphere_chart_html = pio.to_html(fig_sphere, full_html=False, include_plotlyjs='cdn')

    # График по локациям (только положительные балансы)
    positive_location_sums = {name: val for name, val in location_sums.items() if val > 0}
    if positive_location_sums:
        total_positive_locations = sum(positive_location_sums.values())
        location_labels = [f"{name} ({val:.2f} ₽ - {val/total_positive_locations:.1%})" for name, val in positive_location_sums.items()]
        location_values = list(positive_location_sums.values())
        fig_location = go.Figure(data=[go.Pie(labels=location_labels, values=location_values, hole=.3)])
        fig_location.update_layout(title_text='Распределение средств по локациям')
        location_chart_html = pio.to_html(fig_location, full_html=False, include_plotlyjs='cdn')


    return render_template('dashboard.html',
                           total_sum=total_sum,
                           sphere_chart=sphere_chart_html,
                           location_chart=location_chart_html,
                           eff_user_login=get_effective_user_login())


@app.route('/history')
@login_required
def history():
    """Просмотр хронологии операций."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    # Пагинация (простая)
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    records = db.get_accounting_records_for_user(eff_user_id, limit=per_page, offset=offset)
    # TODO: Добавить получение общего количества записей для расчета страниц

    # Получаем имена для отображения
    user_spheres = {s['sphere_id']: s['name'] for s in db.get_spheres_for_user(eff_user_id)}
    user_locations = {l['location_id']: l['name'] for l in db.get_locations_for_user(eff_user_id)}

    for record in records:
        record['sphere_name'] = user_spheres.get(record['sphere_id'], 'N/A')
        record['location_name'] = user_locations.get(record['location_id'], 'N/A')
        # Добавляем отформатированную дату для шаблона
        try:
            # Форматируем дату: заменяем T и обрезаем до минут
            record['formatted_date'] = record['date'].replace('T', ' ')[:16]
        except Exception:
             # На случай, если с датой что-то не так
            record['formatted_date'] = record.get('date', 'Invalid Date')

    return render_template('accounting_history.html',
                            records=records,
                            page=page,
                            eff_user_login=get_effective_user_login())

@app.route('/add_record', methods=['GET', 'POST'])
@login_required
def add_record():
    """Добавление новой записи (Income, Spend, Transfer)."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    # Получаем сферы и локации, которые пользователь может РЕДАКТИРОВАТЬ
    # (т.к. он создает запись, он должен иметь право влиять на баланс)
    editable_spheres = []
    for s in db.get_spheres_for_user(eff_user_id):
         # Проверяем права через API (хотя get_spheres_for_user уже фильтрует)
         # Надежнее проверить явно права на редактирование
         raw_sphere = db._get_sphere_raw(s['sphere_id'])
         if raw_sphere and db._check_ownership_and_permissions(eff_user_id, raw_sphere, 'edit'):
             editable_spheres.append(s)

    editable_locations = []
    for l in db.get_locations_for_user(eff_user_id):
         raw_loc = db._get_location_raw(l['location_id'])
         if raw_loc and db._check_ownership_and_permissions(eff_user_id, raw_loc, 'edit'):
              editable_locations.append(l)


    if request.method == 'POST':
        operation_type = request.form.get('operation_type') # 'Income', 'Spend', 'Transfer'
        sum_str = request.form.get('sum')
        location_id_str = request.form.get('location_id')
        sphere_id_str = request.form.get('sphere_id')
        description = request.form.get('description')
        date_str = request.form.get('date') # Пока не используем кастомную дату

        # Валидация
        if not operation_type or not sum_str or not location_id_str:
            flash('Необходимо выбрать тип операции, указать сумму и локацию.', 'warning')
            return redirect(url_for('add_record'))

        try:
            sum_val = float(sum_str)
            if sum_val <= 0: raise ValueError("Сумма должна быть положительной.")
            location_id = int(location_id_str)
            sphere_id = int(sphere_id_str) if sphere_id_str else None
        except ValueError as e:
            flash(f'Ошибка в данных: {e}', 'danger')
            return redirect(url_for('add_record'))

        # --- Логика добавления ---
        result_acc_id = None
        if operation_type == 'Income' or operation_type == 'Spend':
            if sphere_id is None:
                 flash('Необходимо выбрать сферу для Дохода/Расхода.', 'warning')
                 return redirect(url_for('add_record'))
            result_acc_id = db.add_accounting_record(
                acting_user_id=eff_user_id,
                operation_type_str=operation_type,
                sum_val=sum_val,
                location_id=location_id,
                sphere_id=sphere_id,
                description=description,
                user_read_ids=[], # По умолчанию только владелец
                user_edit_ids=[]  # По умолчанию только владелец
                # date=date_str # TODO: Добавить обработку даты
            )
        elif operation_type == 'Transfer':
            transfer_type = request.form.get('transfer_type') # 'location' or 'sphere'
            peer_location_id_str = request.form.get('peer_location_id')
            peer_sphere_id_str = request.form.get('peer_sphere_id')

            peer_location_id = None
            peer_sphere_id = None

            if transfer_type == 'location':
                if not peer_location_id_str or sphere_id is None:
                     flash('Для перевода между локациями нужно выбрать вторую локацию и сферу.', 'warning')
                     return redirect(url_for('add_record'))
                try:
                    peer_location_id = int(peer_location_id_str)
                    if location_id == peer_location_id:
                         flash('Исходная и конечная локации не должны совпадать.', 'warning')
                         return redirect(url_for('add_record'))
                except ValueError:
                     flash('Некорректный ID конечной локации.', 'danger')
                     return redirect(url_for('add_record'))

                result_acc_id = db.add_accounting_record(
                    acting_user_id=eff_user_id,
                    operation_type_str='Spend', # Не используется напрямую API для Transfer
                    sum_val=sum_val,
                    location_id=location_id, # Откуда
                    sphere_id=sphere_id,
                    is_transfer=True,
                    transfer_peer_location_id=peer_location_id, # Куда
                    description=description,
                    user_read_ids=[], user_edit_ids=[]
                )

            elif transfer_type == 'sphere':
                if not peer_sphere_id_str:
                     flash('Для перевода между сферами нужно выбрать вторую сферу.', 'warning')
                     return redirect(url_for('add_record'))
                try:
                    peer_sphere_id = int(peer_sphere_id_str)
                    if sphere_id == peer_sphere_id:
                         flash('Исходная и конечная сферы не должны совпадать.', 'warning')
                         return redirect(url_for('add_record'))
                except ValueError:
                     flash('Некорректный ID конечной сферы.', 'danger')
                     return redirect(url_for('add_record'))

                result_acc_id = db.add_accounting_record(
                    acting_user_id=eff_user_id,
                    operation_type_str='Spend', # Не используется напрямую API для Transfer
                    sum_val=sum_val,
                    location_id=location_id,
                    sphere_id=sphere_id, # Откуда
                    is_transfer=True,
                    transfer_peer_sphere_id=peer_sphere_id, # Куда
                    description=description,
                    user_read_ids=[], user_edit_ids=[]
                )
            else:
                 flash('Не выбран тип перевода (между локациями или сферами).', 'warning')
                 return redirect(url_for('add_record'))
        else:
            flash('Неизвестный тип операции.', 'danger')
            return redirect(url_for('add_record'))

        # Результат
        if result_acc_id:
            flash('Запись успешно добавлена.', 'success')
            return redirect(url_for('history'))
        else:
            # Сообщение об ошибке должно было быть выведено в консоль из db_api
            flash('Не удалось добавить запись. Проверьте данные или обратитесь к администратору.', 'danger')
            # Остаемся на той же странице, чтобы пользователь видел введенные данные
            return render_template('add_record.html',
                                   spheres=editable_spheres,
                                   locations=editable_locations,
                                   eff_user_login=get_effective_user_login())


    # GET-запрос
    return render_template('add_record.html',
                           spheres=editable_spheres,
                           locations=editable_locations,
                           eff_user_login=get_effective_user_login())


# --- Управление Сферами ---

@app.route('/spheres', methods=['GET', 'POST'])
@login_required
def spheres():
    """Управление сферами (просмотр, добавление)."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    user_friends = db.get_user_friends(eff_user_id)
    # Получаем друзей как словарь {id: login} для отображения в <select>
    friends_dict = {}
    if user_friends:
        # Можно оптимизировать, сделав запрос к БД для получения логинов по списку ID
        for friend_id in user_friends:
            friend_info = db.get_user_by_id(eff_user_id, friend_id) # Используем eff_user_id для прав
            if friend_info:
                friends_dict[friend_id] = friend_info['login']


    if request.method == 'POST': # Добавление новой сферы
        name = request.form.get('name')
        description = request.form.get('description')
        read_ids = request.form.getlist('read_ids', type=int) # Получаем список ID
        edit_ids = request.form.getlist('edit_ids', type=int)

        if not name:
            flash('Название сферы обязательно.', 'warning')
        else:
            # Проверяем, что выбранные пользователи действительно друзья
            valid_read = all(fid in user_friends for fid in read_ids)
            valid_edit = all(fid in user_friends for fid in edit_ids)

            if not valid_read or not valid_edit:
                flash('Можно делиться только с друзьями!', 'danger')
            else:
                sphere_id = db.add_sphere(eff_user_id, name, read_ids, edit_ids, description)
                if sphere_id:
                    flash(f'Сфера "{name}" успешно добавлена.', 'success')
                else:
                    flash('Ошибка при добавлении сферы.', 'danger')
        # Перенаправляем на GET-запрос этой же страницы в любом случае
        return redirect(url_for('spheres'))

    # GET-запрос: отображаем список сфер
    user_spheres_raw = db.get_spheres_for_user(eff_user_id)
    user_spheres_processed = []
    for sphere in user_spheres_raw:
        # Получаем "сырые" данные для проверки прав
        raw_sphere_data = db._get_sphere_raw(sphere['sphere_id'])
        if raw_sphere_data:
            # Проверяем права на редактирование во Flask, а не в шаблоне
            can_edit = db._check_ownership_and_permissions(eff_user_id, raw_sphere_data, 'edit')
            sphere['can_edit'] = can_edit # Добавляем флаг в словарь
        else:
            sphere['can_edit'] = False # Если не нашли сырые данные, то редактировать нельзя
        user_spheres_processed.append(sphere)

    return render_template('spheres.html',
                           # Передаем обработанный список
                           spheres=user_spheres_processed,
                           friends=friends_dict,
                           eff_user_login=get_effective_user_login())

@app.route('/spheres/edit/<int:sphere_id>', methods=['GET', 'POST'])
@login_required
def edit_sphere(sphere_id):
    """Редактирование сферы."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    # Получаем сферу, проверяя права доступа
    sphere = db.get_sphere(eff_user_id, sphere_id)
    if not sphere:
        flash('Сфера не найдена или у вас нет доступа.', 'danger')
        return redirect(url_for('spheres'))

    # Проверяем права на редактирование (get_sphere проверяет только чтение)
    raw_sphere = db._get_sphere_raw(sphere_id)
    if not db._check_ownership_and_permissions(eff_user_id, raw_sphere, 'edit'):
         flash('У вас нет прав на редактирование этой сферы.', 'danger')
         return redirect(url_for('spheres'))

    owner_id = sphere['user_id'] # Владелец сферы
    owner_friends = db.get_user_friends(owner_id) # Друзья владельца
    friends_dict = {}
    if owner_friends:
        for friend_id in owner_friends:
            friend_info = db.get_user_by_id(eff_user_id, friend_id) # Текущий пользователь запрашивает инфо
            if friend_info:
                friends_dict[friend_id] = friend_info['login']


    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        read_ids = request.form.getlist('read_ids', type=int)
        edit_ids = request.form.getlist('edit_ids', type=int)

        if not name:
            flash('Название сферы не может быть пустым.', 'warning')
            # Остаемся на странице редактирования
            return render_template('edit_sphere.html', sphere=sphere, friends=friends_dict, eff_user_login=get_effective_user_login())

        # Проверяем, что выбранные пользователи друзья владельца
        valid_read = all(fid in owner_friends for fid in read_ids)
        valid_edit = all(fid in owner_friends for fid in edit_ids)

        if not valid_read or not valid_edit:
             flash('Можно делиться только с друзьями владельца!', 'danger')
        else:
            updates = {
                'name': name,
                'description': description,
                'user_read_ids': read_ids,
                'user_edit_ids': edit_ids
            }
            if db.update_sphere(eff_user_id, sphere_id, updates):
                flash(f'Сфера "{name}" успешно обновлена.', 'success')
                return redirect(url_for('spheres'))
            else:
                flash('Ошибка при обновлении сферы.', 'danger')
                # Остаемся на странице редактирования

    # GET-запрос
    return render_template('edit_sphere.html', sphere=sphere, friends=friends_dict, eff_user_login=get_effective_user_login())


@app.route('/spheres/delete/<int:sphere_id>', methods=['POST'])
@login_required
def delete_sphere(sphere_id):
    """Удаление сферы."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    # Проверка прав выполняется внутри delete_sphere
    if db.delete_sphere(eff_user_id, sphere_id):
        flash('Сфера успешно удалена.', 'success')
    else:
        flash('Ошибка при удалении сферы или недостаточно прав.', 'danger')
    return redirect(url_for('spheres'))


# --- Управление Локациями (Аналогично Сферам) ---

@app.route('/locations', methods=['GET', 'POST'])
@login_required
def locations():
    """Управление локациями (просмотр, добавление)."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    user_friends = db.get_user_friends(eff_user_id)
    friends_dict = {}
    if user_friends:
        for friend_id in user_friends:
            friend_info = db.get_user_by_id(eff_user_id, friend_id)
            if friend_info:
                friends_dict[friend_id] = friend_info['login']

    if request.method == 'POST': # Добавление новой локации
        name = request.form.get('name')
        description = request.form.get('description')
        read_ids = request.form.getlist('read_ids', type=int)
        edit_ids = request.form.getlist('edit_ids', type=int)

        if not name:
            flash('Название локации обязательно.', 'warning')
        else:
            valid_read = all(fid in user_friends for fid in read_ids)
            valid_edit = all(fid in user_friends for fid in edit_ids)

            if not valid_read or not valid_edit:
                flash('Можно делиться только с друзьями!', 'danger')
            else:
                loc_id = db.add_location(eff_user_id, name, read_ids, edit_ids, description)
                if loc_id:
                    flash(f'Локация "{name}" успешно добавлена.', 'success')
                else:
                    flash('Ошибка при добавлении локации.', 'danger')
        return redirect(url_for('locations'))

    # GET-запрос
    user_locations_raw = db.get_locations_for_user(eff_user_id)
    user_locations_processed = []
    for loc in user_locations_raw:
        raw_loc_data = db._get_location_raw(loc['location_id'])
        if raw_loc_data:
            can_edit = db._check_ownership_and_permissions(eff_user_id, raw_loc_data, 'edit')
            loc['can_edit'] = can_edit
        else:
            loc['can_edit'] = False
        user_locations_processed.append(loc)

    return render_template('locations.html',
                        # Передаем обработанный список
                        locations=user_locations_processed,
                        friends=friends_dict,
                        eff_user_login=get_effective_user_login())

@app.route('/locations/edit/<int:location_id>', methods=['GET', 'POST'])
@login_required
def edit_location(location_id):
    """Редактирование локации."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    location = db.get_location(eff_user_id, location_id)
    if not location:
        flash('Локация не найдена или у вас нет доступа.', 'danger')
        return redirect(url_for('locations'))

    raw_loc = db._get_location_raw(location_id)
    if not db._check_ownership_and_permissions(eff_user_id, raw_loc, 'edit'):
         flash('У вас нет прав на редактирование этой локации.', 'danger')
         return redirect(url_for('locations'))

    owner_id = location['user_id']
    owner_friends = db.get_user_friends(owner_id)
    friends_dict = {}
    if owner_friends:
        for friend_id in owner_friends:
            friend_info = db.get_user_by_id(eff_user_id, friend_id)
            if friend_info:
                friends_dict[friend_id] = friend_info['login']

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        read_ids = request.form.getlist('read_ids', type=int)
        edit_ids = request.form.getlist('edit_ids', type=int)

        if not name:
            flash('Название локации не может быть пустым.', 'warning')
            return render_template('edit_location.html', location=location, friends=friends_dict, eff_user_login=get_effective_user_login())

        valid_read = all(fid in owner_friends for fid in read_ids)
        valid_edit = all(fid in owner_friends for fid in edit_ids)

        if not valid_read or not valid_edit:
             flash('Можно делиться только с друзьями владельца!', 'danger')
        else:
            updates = {
                'name': name,
                'description': description,
                'user_read_ids': read_ids,
                'user_edit_ids': edit_ids
            }
            if db.update_location(eff_user_id, location_id, updates):
                flash(f'Локация "{name}" успешно обновлена.', 'success')
                return redirect(url_for('locations'))
            else:
                flash('Ошибка при обновлении локации.', 'danger')

    # GET-запрос
    return render_template('edit_location.html', location=location, friends=friends_dict, eff_user_login=get_effective_user_login())


@app.route('/locations/delete/<int:location_id>', methods=['POST'])
@login_required
def delete_location(location_id):
    """Удаление локации."""
    eff_user_id = get_effective_user_id()
    if not eff_user_id: abort(401)

    if db.delete_location(eff_user_id, location_id):
        flash('Локация успешно удалена.', 'success')
    else:
        flash('Ошибка при удалении локации или недостаточно прав.', 'danger')
    return redirect(url_for('locations'))


# --- Администрирование ---

@app.route('/admin/select_user')
@login_required
@admin_required
def admin_select_user():
    """Страница выбора пользователя для просмотра администратором."""
    users = db.get_all_users(current_user.id) # Админ запрашивает от своего имени
    return render_template('admin_select_user.html', users=users)

@app.route('/admin/view_as/<int:user_id>')
@login_required
@admin_required
def admin_view_as(user_id):
    """Переключение на просмотр от имени выбранного пользователя."""
    # Проверяем, существует ли пользователь
    user_to_view = User.get(user_id)
    if user_to_view:
        session['selected_user_id'] = user_id
        session['selected_user_login'] = user_to_view.login
        flash(f'Вы теперь просматриваете систему как пользователь {user_to_view.login} (ID: {user_id}).', 'info')
    else:
        flash(f'Пользователь с ID {user_id} не найден.', 'warning')
        session.pop('selected_user_id', None) # Сбрасываем, если пользователь не найден
        session.pop('selected_user_login', None)
    return redirect(url_for('dashboard')) # Переходим на дашборд от имени выбранного пользователя

@app.route('/admin/view_as_self')
@login_required
@admin_required
def admin_view_as_self():
    """Возврат к просмотру от своего имени (администратора)."""
    session.pop('selected_user_id', None)
    session.pop('selected_user_login', None)
    flash('Вы вернулись к просмотру от своего имени.', 'info')
    return redirect(url_for('dashboard'))


# --- Запуск приложения ---
if __name__ == '__main__':
    # Убедимся, что экземпляр API создан перед вызовом create_test_sample
    # Имя файла должно совпадать с тем, что используется в __init__ DatabaseAPI
    db_instance = DatabaseAPI("app_database.db")

    # Вызываем функцию для создания/проверки тестовых данных
    create_test_sample(db_instance)

    app.run(debug=True) # debug=True для разработки, убери в production