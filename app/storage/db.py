"""MySQL users table + salted hashing (no chat storage)."""

import os
import sys
import pymysql
from dotenv import load_dotenv
from app.common.utils import sha256_hex

load_dotenv()


def get_db_connection():
    """Get MySQL database connection."""
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'scuser'),
        password=os.getenv('DB_PASSWORD', 'scpass'),
        database=os.getenv('DB_NAME', 'securechat'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def init_db():
    """Initialize database tables."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        conn.commit()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise
    finally:
        conn.close()


def register_user(email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
    """Register a new user. Returns True if successful, False if email already exists."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return False
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error registering user: {e}")
        return False
    finally:
        conn.close()


def get_user(email: str) -> dict | None:
    """Get user by email. Returns user dict or None if not found."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, email, username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            return cursor.fetchone()
    except Exception as e:
        print(f"Error getting user: {e}")
        return None
    finally:
        conn.close()


def verify_user(email: str, salted_hash: str) -> bool:
    """Verify user credentials. Returns True if password hash matches."""
    user = get_user(email)
    if not user:
        return False
    return user['pwd_hash'] == salted_hash


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")
