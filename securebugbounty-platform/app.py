import os
import uuid
import logging
import functools
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import (
    init_db, get_db_connection, hash_password, check_password,
    calculate_dynamic_points, recalculate_user_points
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production-!@#$%^&*()')
JWT_EXPIRY_HOURS = int(os.environ.get('JWT_EXPIRY_HOURS', '24'))
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='dist', static_url_path='')

app.config['SECRET_KEY'] = SECRET_KEY

CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize DB on startup
init_db()

# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------
def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        'sub': user_id,
        'username': username,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def require_auth(f):
    """Require a valid JWT token."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Требуется авторизация'}), 401
        token = auth_header.split(' ', 1)[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Токен недействителен или истёк'}), 401
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Require admin role (must be used after @require_auth)."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'ADMIN':
            return jsonify({'error': 'Доступ запрещён'}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
def validate_required(data: dict, fields: list[str]) -> str | None:
    """Returns error message if any required field is missing/empty."""
    for field in fields:
        val = data.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            return f'Поле "{field}" обязательно'
    return None


def sanitize_string(s: str, max_length: int = 1000) -> str:
    """Trim and limit string length."""
    if not isinstance(s, str):
        return ''
    return s.strip()[:max_length]


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Не найдено'}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({'error': 'Внутренняя ошибка сервера'}), 500


@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({'error': 'Слишком много запросов, подождите'}), 429


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
@app.route('/')
def serve():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/manager.html')
def serve_manager():
    return send_from_directory(app.static_folder, 'manager.html')


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = sanitize_string(data.get('username', ''), 100)
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Логин и пароль обязательны'}), 400

    with get_db_connection() as conn:
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

    if not user or not check_password(password, user['password']):
        return jsonify({'error': 'Неверные учётные данные'}), 401

    token = create_token(user['id'], user['username'], user['role'])

    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'fullName': user['full_name'],
            'totalPoints': user['total_points'],
        }
    })


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------
@app.route('/api/users', methods=['GET'])
@require_auth
@require_admin
def get_users():
    with get_db_connection() as conn:
        users = conn.execute('SELECT * FROM users').fetchall()

    return jsonify([{
        'id': u['id'],
        'username': u['username'],
        'role': u['role'],
        'fullName': u['full_name'],
        'totalPoints': u['total_points'],
        # Passwords are NEVER returned
    } for u in users])


@app.route('/api/users', methods=['POST'])
@require_auth
@require_admin
def create_user():
    data = request.get_json(silent=True) or {}
    err = validate_required(data, ['username', 'password', 'role', 'fullName'])
    if err:
        return jsonify({'error': err}), 400

    username = sanitize_string(data['username'], 50)
    password = data['password']
    role = data['role'].upper()
    full_name = sanitize_string(data['fullName'], 200)

    if role not in ('USER', 'ADMIN'):
        return jsonify({'error': 'Роль должна быть USER или ADMIN'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Пароль должен быть минимум 4 символа'}), 400

    new_id = str(uuid.uuid4())
    hashed = hash_password(password)

    with get_db_connection() as conn:
        try:
            conn.execute('''
                INSERT INTO users (id, username, password, role, full_name, total_points)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (new_id, username, hashed, role, full_name, 0))
            conn.commit()
        except Exception:
            return jsonify({'error': 'Пользователь уже существует'}), 400

    logger.info(f"User created: {username} ({role})")
    return jsonify({'success': True, 'id': new_id}), 201


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_user(user_id):
    user_id = sanitize_string(user_id, 50)

    with get_db_connection() as conn:
        user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Пользователь не найден'}), 404
        if user['username'] == 'csadmin':
            return jsonify({'error': 'Нельзя удалить главного администратора'}), 403

        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        # CASCADE will handle solves and reports

    logger.info(f"User deleted: {user_id}")
    return jsonify({'success': True})


@app.route('/api/users/<user_id>/penalty', methods=['POST'])
@require_auth
@require_admin
def penalize_user(user_id):
    data = request.get_json(silent=True) or {}
    try:
        amount = int(data.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Некорректная сумма штрафа'}), 400

    if amount <= 0:
        return jsonify({'error': 'Сумма штрафа должна быть положительной'}), 400

    user_id = sanitize_string(user_id, 50)

    with get_db_connection() as conn:
        conn.execute(
            'UPDATE users SET total_points = MAX(0, total_points - ?) WHERE id = ?',
            (amount, user_id)
        )
        conn.commit()

    logger.info(f"User {user_id} penalized: -{amount} points")
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# REPORTS
# ---------------------------------------------------------------------------
@app.route('/api/reports', methods=['GET'])
@require_auth
def get_reports():
    with get_db_connection() as conn:
        # Admins see all reports, users see only their own
        if g.current_user.get('role') == 'ADMIN':
            reports = conn.execute('SELECT * FROM reports ORDER BY created_at DESC').fetchall()
        else:
            reports = conn.execute(
                'SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC',
                (g.current_user['sub'],)
            ).fetchall()

    return jsonify([{
        'id': r['id'],
        'userId': r['user_id'],
        'userName': r['user_name'],
        'title': r['title'],
        'criticality': r['criticality'],
        'description': r['description'],
        'steps': r['steps'],
        'impact': r['impact'],
        'recommendations': r['recommendations'],
        'imageUrl': r['image_url'],
        'status': r['status'],
        'pointsAwarded': r['points_awarded'],
        'createdAt': r['created_at'],
    } for r in reports])


@app.route('/api/reports', methods=['POST'])
@require_auth
def add_report():
    data = request.get_json(silent=True) or {}
    err = validate_required(data, ['title', 'criticality', 'description', 'steps', 'impact', 'recommendations'])
    if err:
        return jsonify({'error': err}), 400

    report_id = str(uuid.uuid4())
    created_at = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')

    with get_db_connection() as conn:
        # Get user info from token
        user = conn.execute(
            'SELECT full_name FROM users WHERE id = ?', (g.current_user['sub'],)
        ).fetchone()
        user_name = user['full_name'] if user else g.current_user['username']

        conn.execute('''
            INSERT INTO reports (id, user_id, user_name, title, criticality,
                                description, steps, impact, recommendations,
                                image_url, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_id,
            g.current_user['sub'],
            user_name,
            sanitize_string(data['title'], 200),
            sanitize_string(data['criticality'], 50),
            sanitize_string(data['description'], 5000),
            sanitize_string(data['steps'], 5000),
            sanitize_string(data['impact'], 2000),
            sanitize_string(data['recommendations'], 2000),
            sanitize_string(data.get('imageUrl', ''), 500),
            'В ожидании',
            created_at
        ))
        conn.commit()

    logger.info(f"Report created: {report_id}")
    return jsonify({'success': True, 'id': report_id}), 201


@app.route('/api/reports/<report_id>', methods=['PATCH'])
@require_auth
@require_admin
def update_report(report_id):
    data = request.get_json(silent=True) or {}
    status = sanitize_string(data.get('status', ''), 50)
    points = data.get('pointsAwarded')

    if not status:
        return jsonify({'error': 'Статус обязателен'}), 400

    valid_statuses = ['В ожидании', 'Принято', 'Отклонено']
    if status not in valid_statuses:
        return jsonify({'error': f'Статус должен быть одним из: {", ".join(valid_statuses)}'}), 400

    report_id = sanitize_string(report_id, 50)

    with get_db_connection() as conn:
        report = conn.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
        if not report:
            return jsonify({'error': 'Отчёт не найден'}), 404

        # Build update
        params = [status]
        query = 'UPDATE reports SET status = ?'

        if points is not None:
            try:
                points = int(points)
            except (ValueError, TypeError):
                return jsonify({'error': 'Некорректное количество баллов'}), 400
            query += ', points_awarded = ?'
            params.append(points)

        query += ' WHERE id = ?'
        params.append(report_id)

        conn.execute(query, params)

        # Recalculate user points globally
        recalculate_user_points(conn)

    logger.info(f"Report {report_id} updated: status={status}, points={points}")
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# CHALLENGES (CTF dynamic scoring)
# ---------------------------------------------------------------------------
@app.route('/api/challenges', methods=['GET'])
@require_auth
def get_challenges():
    with get_db_connection() as conn:
        challenges = conn.execute(
            'SELECT * FROM challenges ORDER BY created_at DESC'
        ).fetchall()

        result = []
        for ch in challenges:
            current_points = calculate_dynamic_points(
                ch['max_points'], ch['min_points'], ch['decay'], ch['solve_count']
            )
            # Check if current user solved this challenge
            solved = conn.execute(
                'SELECT id FROM solves WHERE user_id = ? AND challenge_id = ?',
                (g.current_user['sub'], ch['id'])
            ).fetchone()

            result.append({
                'id': ch['id'],
                'title': ch['title'],
                'category': ch['category'],
                'description': ch['description'],
                'maxPoints': ch['max_points'],
                'minPoints': ch['min_points'],
                'currentPoints': current_points,
                'solveCount': ch['solve_count'],
                'solved': solved is not None,
                'createdAt': ch['created_at'],
            })

    return jsonify(result)


@app.route('/api/challenges', methods=['POST'])
@require_auth
@require_admin
def create_challenge():
    data = request.get_json(silent=True) or {}
    err = validate_required(data, ['title', 'category', 'description', 'flag'])
    if err:
        return jsonify({'error': err}), 400

    try:
        max_points = int(data.get('maxPoints', 500))
        min_points = int(data.get('minPoints', 100))
        decay = int(data.get('decay', 20))
    except (ValueError, TypeError):
        return jsonify({'error': 'Некорректные параметры скоринга'}), 400

    if max_points <= min_points:
        return jsonify({'error': 'maxPoints должен быть больше minPoints'}), 400
    if decay <= 0:
        return jsonify({'error': 'decay должен быть положительным'}), 400

    challenge_id = str(uuid.uuid4())
    created_at = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')

    with get_db_connection() as conn:
        conn.execute('''
            INSERT INTO challenges (id, title, category, description,
                                     max_points, min_points, decay, flag,
                                     solve_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            challenge_id,
            sanitize_string(data['title'], 200),
            sanitize_string(data['category'], 50),
            sanitize_string(data['description'], 5000),
            max_points,
            min_points,
            decay,
            data['flag'].strip(),
            0,
            created_at
        ))
        conn.commit()

    logger.info(f"Challenge created: {challenge_id}")
    return jsonify({'success': True, 'id': challenge_id}), 201


@app.route('/api/challenges/<challenge_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_challenge(challenge_id):
    challenge_id = sanitize_string(challenge_id, 50)

    with get_db_connection() as conn:
        ch = conn.execute('SELECT id FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
        if not ch:
            return jsonify({'error': 'Задание не найдено'}), 404

        conn.execute('DELETE FROM challenges WHERE id = ?', (challenge_id,))
        # Recalculate points since solves for this challenge are deleted via CASCADE
        recalculate_user_points(conn)

    logger.info(f"Challenge deleted: {challenge_id}")
    return jsonify({'success': True})


@app.route('/api/challenges/<challenge_id>/solve', methods=['POST'])
@require_auth
@limiter.limit("30 per minute")
def solve_challenge(challenge_id):
    data = request.get_json(silent=True) or {}
    submitted_flag = data.get('flag', '').strip()

    if not submitted_flag:
        return jsonify({'error': 'Флаг обязателен'}), 400

    challenge_id = sanitize_string(challenge_id, 50)
    user_id = g.current_user['sub']

    with get_db_connection() as conn:
        # Get challenge
        challenge = conn.execute(
            'SELECT * FROM challenges WHERE id = ?', (challenge_id,)
        ).fetchone()
        if not challenge:
            return jsonify({'error': 'Задание не найдено'}), 404

        # Check if already solved
        existing = conn.execute(
            'SELECT id FROM solves WHERE user_id = ? AND challenge_id = ?',
            (user_id, challenge_id)
        ).fetchone()
        if existing:
            return jsonify({'error': 'Вы уже решили это задание'}), 400

        # Check flag
        if submitted_flag != challenge['flag']:
            logger.info(f"Wrong flag from user {user_id} for challenge {challenge_id}")
            return jsonify({'error': 'Неверный флаг'}), 400

        # Correct! Increment solve count
        new_solve_count = challenge['solve_count'] + 1
        conn.execute(
            'UPDATE challenges SET solve_count = ? WHERE id = ?',
            (new_solve_count, challenge_id)
        )

        # Calculate current points
        current_points = calculate_dynamic_points(
            challenge['max_points'], challenge['min_points'],
            challenge['decay'], new_solve_count
        )

        # Record the solve
        solve_id = str(uuid.uuid4())
        solved_at = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')
        conn.execute('''
            INSERT INTO solves (id, user_id, challenge_id, points_awarded, solved_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (solve_id, user_id, challenge_id, current_points, solved_at))

        # Recalculate ALL user points (dynamic scoring affects everyone)
        recalculate_user_points(conn)

    logger.info(f"Challenge {challenge_id} solved by user {user_id}, points={current_points}")
    return jsonify({
        'success': True,
        'pointsAwarded': current_points,
        'message': f'Верно! Вы получили {current_points} баллов.'
    })


# ---------------------------------------------------------------------------
# SCOREBOARD
# ---------------------------------------------------------------------------
@app.route('/api/scoreboard', methods=['GET'])
@require_auth
def get_scoreboard():
    with get_db_connection() as conn:
        users = conn.execute('''
            SELECT id, username, full_name, total_points, role
            FROM users
            WHERE role != 'ADMIN'
            ORDER BY total_points DESC
        ''').fetchall()

    return jsonify([{
        'rank': idx + 1,
        'id': u['id'],
        'username': u['username'],
        'fullName': u['full_name'],
        'totalPoints': u['total_points'],
    } for idx, u in enumerate(users)])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=DEBUG)
