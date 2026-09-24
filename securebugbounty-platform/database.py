import sqlite3
import bcrypt
import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_NAME = os.environ.get('DB_PATH', 'database.db')


@contextmanager
def get_db_connection():
    """Context manager for DB connections — auto-closes on exit."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def init_db():
    """Initialize database schema and seed admin user."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            full_name TEXT NOT NULL,
            total_points INTEGER DEFAULT 0
        )
    ''')

    # Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            title TEXT NOT NULL,
            criticality TEXT NOT NULL,
            description TEXT NOT NULL,
            steps TEXT NOT NULL,
            impact TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            image_url TEXT,
            status TEXT NOT NULL DEFAULT 'В ожидании',
            points_awarded INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Challenges table — CTF tasks with dynamic scoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            max_points INTEGER NOT NULL DEFAULT 500,
            min_points INTEGER NOT NULL DEFAULT 100,
            decay INTEGER NOT NULL DEFAULT 20,
            flag TEXT NOT NULL,
            solve_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    # Solves table — who solved which challenge
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solves (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            challenge_id TEXT NOT NULL,
            points_awarded INTEGER NOT NULL,
            solved_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (challenge_id) REFERENCES challenges (id) ON DELETE CASCADE,
            UNIQUE(user_id, challenge_id)
        )
    ''')

    # Seed admin user
    cursor.execute('SELECT * FROM users WHERE username = ?', ('csadmin',))
    if not cursor.fetchone():
        admin_password = hash_password('csadmin_kwq&3jf0$#57')
        cursor.execute('''
            INSERT INTO users (id, username, password, role, full_name, total_points)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('1', 'csadmin', admin_password, 'ADMIN', 'Главный Администратор', 0))
        logger.info("Admin user 'csadmin' created.")

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def calculate_dynamic_points(max_points: int, min_points: int, decay: int, solve_count: int) -> int:
    """CTF-style dynamic scoring: points decrease as more teams solve."""
    points = max(min_points, max_points - decay * (solve_count - 1))
    return points


def recalculate_user_points(conn):
    """Recalculate total_points for ALL users based on current dynamic scores + reports."""
    cursor = conn.cursor()

    # Reset all user points to 0
    cursor.execute('UPDATE users SET total_points = 0')

    # Add points from solves (dynamic — recalculated per challenge)
    challenges = cursor.execute('SELECT * FROM challenges').fetchall()
    for ch in challenges:
        current_points = calculate_dynamic_points(
            ch['max_points'], ch['min_points'], ch['decay'], ch['solve_count']
        )
        # Update all solves for this challenge to reflect current points
        cursor.execute(
            'UPDATE solves SET points_awarded = ? WHERE challenge_id = ?',
            (current_points, ch['id'])
        )

    # Sum up solve points per user
    cursor.execute('''
        UPDATE users SET total_points = (
            SELECT COALESCE(SUM(s.points_awarded), 0)
            FROM solves s WHERE s.user_id = users.id
        )
    ''')

    # Add points from accepted reports
    cursor.execute('''
        UPDATE users SET total_points = total_points + (
            SELECT COALESCE(SUM(r.points_awarded), 0)
            FROM reports r WHERE r.user_id = users.id AND r.status = 'Принято'
        )
    ''')

    conn.commit()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    init_db()
