import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


DB_FILE = "gestor_maquinas.db"

API_PORT = int(os.environ.get("PORT", "8080"))

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

TABLES = {
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


def database():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row

    connection.executescript(
        """
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
        """
    )

    connection.commit()
    return connection


def create_token(username):
    expiration = int(time.time()) + 86400
    payload = f"{username}:{expiration}"

    signature = hmac.new(
        TOKEN_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    raw_token = f"{payload}:{signature}"

    return base64.urlsafe_b64encode(
        raw_token.encode("utf-8")
    ).decode("utf-8")


def read_token(token):
    try:
        decoded = base64.urlsafe_b64decode(
            token.encode("utf-8")
        ).decode("utf-8")

        username, expiration, signature = decoded.rsplit(":", 2)

        payload = f"{username}:{expiration}"

        expected_signature = hmac.new(
            TOKEN_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if int(expiration) <= int(time.time()):
            return None

        if not hmac.compare_digest(
            signature,
            expected_signature
        ):
            return None

        if username not in USERS:
            return None

        return username

    except Exception:
        return None


class GestorAPI(BaseHTTPRequestHandler):

    def set_headers(self, content_type=True):
        if content_type:
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
        self.set_headers()
        self.end_headers()

        response = json.dumps(
            data,
            ensure_ascii=False
        ).encode("utf-8")

        self.wfile.write(response)

    def get_json_body(self):
        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            raw_body = self.rfile.read(content_length)

            if not raw_body:
                return {}

            return json.loads(raw_body.decode("utf-8"))

        except Exception:
            return {}

    def current_user(self):
        authorization = self.headers.get(
            "Authorization",
            ""
        )

        if not authorization.startswith("Bearer "):
            return None

        token = authorization.replace(
            "Bearer ",
            "",
            1
        ).strip()

        return read_token(token)

    def require_login(self):
        username = self.current_user()

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

    def visible_rows(self, table, username):
        connection = database()

        rows = connection.execute(
            f"SELECT * FROM {table} ORDER BY id DESC"
        ).fetchall()

        connection.close()

        data = [dict(row) for row in rows]

        user = USERS[username]

        if user["role"] == "Cliente":
            if table == "machines":
                data = [
                    item for item in data
                    if item.get("client") == user["client"]
                ]

            elif table == "maintenance":
                data = [
                    item for item in data
                    if item.get("client") == user["client"]
                    or item.get("machine") == user["client"]
                ]

            elif table == "clients":
                data = [
                    item for item in data
                    if item.get("name") == user["client"]
                ]

            elif table == "stock":
                data = []

        return data

    def do_OPTIONS(self):
        self.send_response(204)
        self.set_headers(content_type=False)
        self.end_headers()

    def do_GET(self):
        route = urlparse(self.path).path.strip("/")

        if route == "":
            self.send_json(
                {
                    "status": "ok",
                    "app": "Gestor Máquinas API",
                    "version": "2.0"
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

            users_response = []

            for user_id, user_data in USERS.items():
                users_response.append(
                    {
                        "username": user_id,
                        "name": user_data["name"],
                        "role": user_data["role"],
                        "client": user_data["client"],
                        "status": "Ativo"
                    }
                )

            self.send_json(users_response)
            return

        if route not in TABLES:
            self.send_json(
                {
                    "error": "Rota não encontrada"
                },
                404
            )

            return

        self.send_json(
            self.visible_rows(route, username)
        )

    def do_POST(self):
        route = urlparse(self.path).path.strip("/")
        data = self.get_json_body()

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

        if route not in TABLES:
            self.send_json(
                {
                    "error": "Rota não encontrada"
                },
                404
            )

            return

        allowed_fields = TABLES[route]

        clean_data = {}

        for field in allowed_fields:
            value = data.get(field, "")

            if field in ["counter", "quantity", "minimum"]:
                try:
                    value = int(value or 0)
                except Exception:
                    value = 0

            clean_data[field] = value

        columns = ",".join(clean_data.keys())
        placeholders = ",".join(
            ["?"] * len(clean_data)
        )
        values = list(clean_data.values())

        connection = database()

        cursor = connection.execute(
            f"""
            INSERT INTO {route}
            ({columns})
            VALUES ({placeholders})
            """,
            values
        )

        connection.commit()

        new_id = cursor.lastrowid

        connection.close()

        clean_data["id"] = new_id

        self.send_json(
            clean_data,
            201
        )

    def log_message(self, format_string, *args):
        print(
            f"{self.address_string()} - "
            f"{format_string % args}"
        )


if __name__ == "__main__":
    database().close()

    if ADMIN_PASSWORD == "change-this-password":
        print(
            "AVISO: configure GESTOR_ADMIN_PASSWORD no Render."
        )

    if TOKEN_SECRET == "change-this-token-secret":
        print(
            "AVISO: configure GESTOR_TOKEN_SECRET no Render."
        )

    print(
        f"Gestor Máquinas API iniciado na porta {API_PORT}"
    )

    server = HTTPServer(
        ("0.0.0.0", API_PORT),
        GestorAPI
    )

    server.serve_forever()

