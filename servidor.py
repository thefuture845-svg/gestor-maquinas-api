import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


DATABASE = "gestor_maquinas.db"
PORT = int(os.environ.get("PORT", "8080"))

ADMIN_USER = os.environ.get("GESTOR_ADMIN_USER", "julio")
ADMIN_PASSWORD = os.environ.get(
    "GESTOR_ADMIN_PASSWORD",
    "change-this-password"
)
TOKEN_SECRET = os.environ.get(
    "GESTOR_TOKEN_SECRET",
    "change-this-token-secret"
)

USERS = {
    ADMIN_USER: {
        "name": "Júlio Francisco",
        "role": "Administrador",
        "password": ADMIN_PASSWORD,
        "client": ""
    },
    "celso": {
        "name": "Celso",
        "role": "Técnico",
        "password": os.environ.get(
            "GESTOR_CELSO_PASSWORD",
            "Celso-temporario-2026"
        ),
        "client": ""
    },
    "daniel": {
        "name": "Daniel",
        "role": "Técnico",
        "password": os.environ.get(
            "GESTOR_DANIEL_PASSWORD",
            "Daniel-temporario-2026"
        ),
        "client": ""
    },
    "nuno": {
        "name": "Nuno Voabil",
        "role": "Cliente",
        "password": os.environ.get(
            "GESTOR_NUNO_PASSWORD",
            "Nuno-temporario-2026"
        ),
        "client": "Nuno Voabil"
    },
    "cinderella": {
        "name": "Colégio Cinderella",
        "role": "Cliente",
        "password": os.environ.get(
            "GESTOR_CINDERELLA_PASSWORD",
            "Cinderella-temporario-2026"
        ),
        "client": "Colégio Cinderella"
    }
}

FIELDS = {
    "machines": [
        "model",
        "serial",
        "client",
        "counter",
        "status",
        "tech",
        "toner",
        "notes"
    ],
    "clients": [
        "name",
        "phone",
        "location"
    ],
    "maintenance": [
        "date",
        "machine",
        "service",
        "tech",
        "status",
        "notes"
    ],
    "stock": [
        "name",
        "compatibility",
        "quantity",
        "minimum"
    ]
}


def get_database():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    connection.executescript("""
        CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT,
            serial TEXT,
            client TEXT,
            counter INTEGER DEFAULT 0,
            status TEXT,
            tech TEXT,
            toner TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            location TEXT
        );

        CREATE TABLE IF NOT EXISTS maintenance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            machine TEXT,
            service TEXT,
            tech TEXT,
            status TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            compatibility TEXT,
            quantity INTEGER DEFAULT 0,
            minimum INTEGER DEFAULT 0
        );
    """)

    add_missing_columns(
        connection,
        "machines",
        {
            "tech": "TEXT",
            "toner": "TEXT",
            "notes": "TEXT"
        }
    )

    connection.commit()
    return connection


def add_missing_columns(connection, table, columns):
    existing = connection.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    existing_names = {
        row["name"] for row in existing
    }

    for column, data_type in columns.items():
        if column not in existing_names:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {data_type}"
            )


def create_token(username):
    expires = int(time.time()) + 86400
    payload = f"{username}:{expires}"

    signature = hmac.new(
        TOKEN_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    value = f"{payload}:{signature}"

    return base64.urlsafe_b64encode(
        value.encode()
    ).decode()


def get_username_from_token(token):
    try:
        decoded = base64.urlsafe_b64decode(
            token.encode()
        ).decode()

        username, expires, signature = decoded.rsplit(":", 2)

        payload = f"{username}:{expires}"

        expected = hmac.new(
            TOKEN_SECRET.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if int(expires) <= int(time.time()):
            return None

        if not hmac.compare_digest(signature, expected):
            return None

        if username not in USERS:
            return None

        return username

    except Exception:
        return None


class GestorAPI(BaseHTTPRequestHandler):

    def send_headers(self):
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )
        self.send_header(
            "Access-Control-Allow-Origin",
            "*"
        )
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization"
        )
        self.send_header(
            "Access-Control-Allow-Methods",
            "GET, POST, OPTIONS"
        )

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_headers()
        self.end_headers()

        self.wfile.write(
            json.dumps(
                data,
                ensure_ascii=False
            ).encode()
        )

    def read_body(self):
        try:
            size = int(
                self.headers.get("Content-Length", "0")
            )

            content = self.rfile.read(size)

            if not content:
                return {}

            return json.loads(content.decode())

        except Exception:
            return {}

    def get_logged_user(self):
        authorization = self.headers.get(
            "Authorization",
            ""
        )

        if not authorization.startswith("Bearer "):
            return None

        token = authorization[7:]
        return get_username_from_token(token)

    def require_login(self):
        username = self.get_logged_user()

        if not username:
            self.send_json(
                {
                    "error": "Acesso não autorizado"
                },
                401
            )
            return None

        return username

    def require_admin(self):
        username = self.require_login()

        if not username:
            return None

        if USERS[username]["role"] != "Administrador":
            self.send_json(
                {
                    "error": "Apenas o administrador pode executar esta ação"
                },
                403
            )
            return None

        return username

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_headers()
        self.end_headers()

    def do_GET(self):
        route = urlparse(self.path).path.strip("/")

        if route == "":
            self.send_json(
                {
                    "status": "ok",
                    "app": "Gestor Máquinas API"
                }
            )
            return

        username = self.require_login()

        if not username:
            return

        if route == "me":
            user = USERS[username]

            self.send_json(
                {
                    "username": username,
                    "name": user["name"],
                    "role": user["role"],
                    "client": user["client"]
                }
            )
            return

        if route == "users":
            if USERS[username]["role"] != "Administrador":
                self.send_json(
                    {
                        "error": "Acesso não autorizado"
                    },
                    403
                )
                return

            result = []

            for user_id, user in USERS.items():
                result.append(
                    {
                        "username": user_id,
                        "name": user["name"],
                        "role": user["role"],
                        "client": user["client"],
                        "status": "Ativo"
                    }
                )

            self.send_json(result)
            return

        if route not in FIELDS:
            self.send_json(
                {
                    "error": "Rota não encontrada"
                },
                404
            )
            return

        connection = get_database()

        rows = connection.execute(
            f"SELECT * FROM {route} ORDER BY id DESC"
        ).fetchall()

        connection.close()

        result = [dict(row) for row in rows]

        user = USERS[username]

        if user["role"] == "Cliente":
            if route == "machines":
                result = [
                    item for item in result
                    if item.get("client") == user["client"]
                ]

            elif route == "clients":
                result = [
                    item for item in result
                    if item.get("name") == user["client"]
                ]

            elif route == "maintenance":
                result = []

            elif route == "stock":
                result = []

        self.send_json(result)

    def do_POST(self):
        route = urlparse(self.path).path.strip("/")
        data = self.read_body()

        if route == "login":
            username = str(
                data.get("user", "")
            ).strip().lower()

            password = str(
                data.get("password", "")
            )

            user = USERS.get(username)

            if not user:
                self.send_json(
                    {
                        "error": "Credenciais incorretas"
                    },
                    401
                )
                return

            if not hmac.compare_digest(
                password,
                str(user["password"])
            ):
                self.send_json(
                    {
                        "error": "Credenciais incorretas"
                    },
                    401
                )
                return

            self.send_json(
                {
                    "token": create_token(username),
                    "username": username,
                    "name": user["name"],
                    "role": user["role"],
                    "client": user["client"]
                }
            )
            return

        username = self.require_admin()

        if not username:
            return

        if route not in FIELDS:
            self.send_json(
                {
                    "error": "Rota não encontrada"
                },
                404
            )
            return

        values = {}

        for field in FIELDS[route]:
            value = data.get(field, "")

            if field in ["counter", "quantity", "minimum"]:
                try:
                    value = int(value or 0)
                except Exception:
                    value = 0

            values[field] = value

        columns = ",".join(values.keys())
        placeholders = ",".join(
            ["?"] * len(values)
        )

        connection = get_database()

        cursor = connection.execute(
            f"""
            INSERT INTO {route}
            ({columns})
            VALUES ({placeholders})
            """,
            list(values.values())
        )

        connection.commit()

        new_id = cursor.lastrowid
        connection.close()

        values["id"] = new_id

        self.send_json(values, 201)

    def log_message(self, format_string, *args):
        print(format_string % args)


if __name__ == "__main__":
    get_database().close()

    print(
        f"Gestor Máquinas API iniciada na porta {PORT}"
    )

    server = HTTPServer(
        ("0.0.0.0", PORT),
        GestorAPI
    )

    server.serve_forever()

