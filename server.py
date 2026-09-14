import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DB = "gestor_maquinas.db"

TABLES = [
    "machines",
    "clients",
    "maintenance",
    "stock"
]

USERS = {
    "julio": {
        "name": "Júlio Francisco",
        "role": "Administrador",
        "password": os.environ.get(
            "GESTOR_ADMIN_PASSWORD",
            "change-this-password"
        )
    },
    "celso": {
        "name": "Celso",
        "role": "Técnico",
        "password": os.environ.get(
            "GESTOR_CELSO_PASSWORD",
            "Celso-temporario-2026"
        )
    },
    "daniel": {
        "name": "Daniel",
        "role": "Técnico",
        "password": os.environ.get(
            "GESTOR_DANIEL_PASSWORD",
            "Daniel-temporario-2026"
        )
    },
    "nuno": {
        "name": "Nuno Voabil",
        "role": "Cliente",
        "password": os.environ.get(
            "GESTOR_NUNO_PASSWORD",
            "Nuno-temporario-2026"
        )
    },
    "cinderella": {
        "name": "Colégio Cinderella",
        "role": "Cliente",
        "password": os.environ.get(
            "GESTOR_CINDERELLA_PASSWORD",
            "Cinderella-temporario-2026"
        )
    }
}

TOKEN_SECRET = os.environ.get(
    "GESTOR_TOKEN_SECRET",
    "change-this-token-secret"
)


def db():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row

    connection.executescript("""
        CREATE TABLE IF NOT EXISTS machines(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT,
            serial TEXT,
            client TEXT,
            counter INTEGER,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS clients(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            location TEXT
        );

        CREATE TABLE IF NOT EXISTS maintenance(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            machine TEXT,
            service TEXT,
            tech TEXT,
            status TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS stock(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            compatibility TEXT,
            quantity INTEGER,
            minimum INTEGER
        );
    """)

    return connection


def create_token(username, role):
    payload = {
        "user": username,
        "role": role,
        "expires": int(time.time()) + 86400
    }

    encoded = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode()

    signature = hmac.new(
        TOKEN_SECRET.encode(),
        encoded.encode(),
        hashlib.sha256
    ).hexdigest()

    return encoded + "." + signature


def read_token(token):
    try:
        encoded, signature = token.split(".", 1)

        expected = hmac.new(
            TOKEN_SECRET.encode(),
            encoded.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected):
            return None

        payload = json.loads(
            base64.urlsafe_b64decode(encoded.encode()).decode()
        )

        if payload["expires"] < time.time():
            return None

        return payload

    except Exception:
        return None


class API(BaseHTTPRequestHandler):

    def set_headers(self):
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
        self.wfile.write(
            json.dumps(data, ensure_ascii=False).encode()
        )

    def current_user(self):
        authorization = self.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return None

        return read_token(authorization[7:])

    def allowed(self, user, action, table):
        if not user:
            return False

        role = user["role"]

        if role == "Administrador":
            return True

        if role == "Técnico":
            return table in [
                "machines",
                "maintenance",
                "stock"
            ]

        if role == "Cliente":
            return action == "GET" and table in [
                "machines",
                "maintenance"
            ]

        return False

    def do_OPTIONS(self):
        self.send_response(204)
        self.set_headers()
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.strip("/")

        if path == "":
            return self.send_json({
                "status": "ok",
                "app": "Gestor Máquinas API"
            })

        user = self.current_user()

        if path == "me":
            if not user:
                return self.send_json(
                    {"error": "Acesso não autorizado"},
                    401
                )

            account = USERS.get(user["user"])

            return self.send_json({
                "username": user["user"],
                "name": account["name"],
                "role": user["role"]
            })

        if path == "users":
            if not user or user["role"] != "Administrador":
                return self.send_json(
                    {"error": "Apenas o administrador tem acesso"},
                    403
                )

            result = []

            for username, account in USERS.items():
                result.append({
                    "username": username,
                    "name": account["name"],
                    "role": account["role"],
                    "active": True
                })

            return self.send_json(result)

        table = path.split("/")[-1]

        if table not in TABLES:
            return self.send_json(
                {"error": "Rota não encontrada"},
                404
            )

        if not self.allowed(user, "GET", table):
            return self.send_json(
                {"error": "Sem permissão para esta área"},
                403
            )

        connection = db()

        rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} ORDER BY id DESC"
            )
        ]

        connection.close()

        return self.send_json(rows)

    def do_POST(self):
        path = urlparse(self.path).path.strip("/")

        length = int(
            self.headers.get("Content-Length", 0) or 0
        )

        body = self.rfile.read(length)
        data = json.loads(body or "{}")

        if path == "login":
            username = str(data.get("user", "")).lower()
            password = str(data.get("password", ""))

            account = USERS.get(username)

            if not account:
                return self.send_json(
                    {"error": "Credenciais incorretas"},
                    401
                )

            if not hmac.compare_digest(
                password,
                account["password"]
            ):
                return self.send_json(
                    {"error": "Credenciais incorretas"},
                    401
                )

            token = create_token(
                username,
                account["role"]
            )

            return self.send_json({
                "token": token,
                "username": username,
                "name": account["name"],
                "role": account["role"]
            })

        user = self.current_user()

        table = path.split("/")[-1]

        if table not in TABLES:
            return self.send_json(
                {"error": "Rota não encontrada"},
                404
            )

        if not self.allowed(user, "POST", table):
            return self.send_json(
                {"error": "Sem permissão para esta área"},
                403
            )

        allowed_fields = {
            "machines": [
                "model",
                "serial",
                "client",
                "counter",
                "status"
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
        }[table]

        clean_data = {
            field: data.get(field, "")
            for field in allowed_fields
        }

        columns = ",".join(clean_data.keys())
        values = list(clean_data.values())
        marks = ",".join("?" * len(values))

        connection = db()

        cursor = connection.execute(
            f"""
            INSERT INTO {table} ({columns})
            VALUES ({marks})
            """,
            values
        )

        connection.commit()

        clean_data["id"] = cursor.lastrowid

        connection.close()

        return self.send_json(clean_data, 201)


if __name__ == "__main__":
    port = int(
        os.environ.get("PORT", "8080")
    )

    db().close()

    print(
        f"Gestor Máquinas API na porta {port}"
    )

    HTTPServer(
        ("0.0.0.0", port),
        API
    ).serve_forever()
