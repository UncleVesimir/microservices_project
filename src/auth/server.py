import os
import datetime
import jwt
import psycopg2
from flask import Flask, request

server = Flask(__name__)


def get_db_connection():
    conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        database=os.environ["DB_NAME"],
        user=os.environ['DB_USERNAME'],
        password=os.environ['DB_PASSWORD']
    )

    return conn


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credential", 401

    # check db for username and password

    conn = get_db_connection()
    cur = conn.cursor()
    res = cur.execute(
        "SELECT email, pword FROM users WHERE email=%s", (auth.username)).fetchone()

    if res is not None:
        email = res[0]
        password = res[1]

        if auth.username != email or auth.password != password:
            return "invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ["JWT_SECRET"], True)
    else:
        return "invalid credentials", 401


def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256"
    )


@server.route("/validate", method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing jwt credentials", 401

    encoded_jwt = encoded_jwt.split(" ")
    auth_scheme = encoded_jwt[0]
    credentials = encoded_jwt[1]

    if auth_scheme != "Basic":
        return "not authorized", 401

    try:
        decoded = jwt.decode(
            credentials,
            os.environ["JWT_SECRET"],
            algorithm=["HS256"]
        )
    except SystemError:
        return "forbidden", 403

    return decoded, 200


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
