import base64, hashlib, hmac, json, os, sqlite3, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DB = "gestor_maquinas.db"
TABLES = ["machines", "clients", "maintenance", "stock"]

ADMIN_USER = os.environ.get("GESTOR_ADMIN_USER", "julio")
ADMIN_PASSWORD = os.environ.get(
    "GESTOR_ADMIN_PASSWORD",
    "change-this-password"
)
TOKEN_SECRET = os.environ.get(
    "GESTOR_TOKEN_SECRET",
    "change-this-token-secret"
)


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript("""
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
    return c


def make_token(user):
    payload = f"{user}:{int(time.time()) + 86400}"
    signature = hmac.new(
        TOKEN_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    token = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token.encode()).decode()


def valid_token(value):
    try:
        raw = base64.urlsafe_b64decode(value.encode()).decode()
        user, expires, signature = raw.rsplit(":", 2)

        payload = f"{user}:{expires}"
        expected = hmac.new(
            TOKEN_SECRET.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        return (
            int(expires) > time.time()
            and hmac.compare_digest(signature, expected)
        )
    except Exception:
        return False


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

    def send_json(self, data, code=200):
        self.send_response(code)
        self.set_headers()
        self.end_headers()
        self.wfile.write(
            json.dumps(data, ensure_ascii=False).encode()
        )

    def authorized(self):
        authorization = self.headers.get("Authorization", "")

        if (
            not authorization.startswith("Bearer ")
            or not valid_token(authorization[7:])
        ):
            self.send_json(
                {"error": "Acesso não autorizado"},
                401
            )
            return False

        return True

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

        if not self.authorized():
            return

        table = path.split("/")[-1]

        if table not in TABLES:
            return self.send_json(
                {"error": "Rota não encontrada"},
                404
            )

        connection = db()
        rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} ORDER BY id DESC"
            )
        ]
        connection.close()

        self.send_json(rows)

    def do_POST(self):
        route = urlparse(self.path).path.strip("/")
        content_length = int(
            self.headers.get("Content-Length", 0) or 0
        )

        body = self.rfile.read(content_length)
        data = json.loads(body or "{}")

        if route == "login":
            valid_user = hmac.compare_digest(
                str(data.get("user", "")),
                ADMIN_USER
            )
            valid_password = hmac.compare_digest(
                str(data.get("password", "")),
                ADMIN_PASSWORD
            )

            if valid_user and valid_password:
                return self.send_json({
                    "token": make_token(ADMIN_USER)
                })

            return self.send_json(
                {"error": "Credenciais incorretas"},
                401
            )

        if not self.authorized():
            return

        table = route.split("/")[-1]

        if table not in TABLES:
            return self.send_json(
                {"error": "Rota não encontrada"},
                404
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
            key: data.get(key, "")
            for key in allowed_fields
        }

        columns = ",".join(clean_data.keys())
        values = list(clean_data.values())
        placeholders = ",".join("?" * len(values))

        connection = db()
        cursor = connection.execute(
            f"""
            INSERT INTO {table} ({columns})
            VALUES ({placeholders})
            """,
            values
        )
        connection.commit()

        clean_data["id"] = cursor.lastrowid
        connection.close()

        self.send_json(clean_data, 201)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))

    db().close()

    print(f"Gestor Máquinas API na porta {port}")

    HTTPServer(
        ("0.0.0.0", port),
        API
    ).serve_forever()
