#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mail.ari.lt signup page

protections :

- image captcha
- end-to-end encryption
- rate limiting"""

import base64
import json
import os
import secrets
import smtplib
import typing as t
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from warnings import filterwarnings as filter_warnings

import better_profanity
import flask
import flask_ishuman
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response

better_profanity.profanity.load_censor_words()

app: flask.Flask = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # type: ignore

h: flask_ishuman.IsHuman = flask_ishuman.IsHuman()
limiter: Limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["30 per minute", "6 per second"],
    storage_uri="memory://",
    strategy="fixed-window",
)

# local_part, name, password, and password2 get replaced automatically
# https://mail.ari.lt/api/#/Mailboxes/Create%20mailbox

DOMAIN: str = "ari.lt"
MDOMAIN: str = "mail.ari.lt"
ADMIN: str = "ari@ari.lt"

DEFAULT_REQUEST: t.Final[t.Dict[str, t.Any]] = {
    "active": "1",
    "domain": DOMAIN,
    "quota": "4096",
    "force_pw_update": "0",
    "tls_enforce_in": "0",
    "tls_enforce_out": "0",
    "force_pw_update": "0",
    "tags": ["signup"],
}

RAND: secrets.SystemRandom = secrets.SystemRandom()

app.config["SECRET_KEY"] = RAND.randbytes(2048)

app.config["PREFERRED_URL_SCHEME"] = "https"

app.config["CAPTCHA_PEPPER_FILE"] = "captcha.key"
app.config["CAPTCHA_EXPIRY"] = 60 * 10
app.config["CAPTCHA_CHARSET"] = "abdefghmnqrtyABDEFGHLMNRTY2345689#@%?!"
app.config["CAPTCHA_RANGE"] = (4, 6)

app.config["USE_SESSION_FOR_NEXT"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "strict"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

API_KEY: str = os.environ["MAILCOW_API_KEY"]

MIN_USERNAME: int = 3

h.init_app(app)


def ee2e_form() -> t.Union[int, t.Dict[str, t.Any]]:
    """ee2e form"""

    if flask.request.headers.get("Content-Type") != "application/octet-stream":
        flask.flash("Invalid content type")
        return 406

    try:
        cipher: Cipher[modes.CBC] = Cipher(
            algorithms.AES(flask.session["k"]),
            modes.CBC(flask.session["v"]),
            backend=default_backend(),
        )

        decryptor: t.Any = cipher.decryptor()
        padded_message: bytes = (
            decryptor.update(flask.request.data) + decryptor.finalize()
        )
        unpadder: t.Any = PKCS7(128).unpadder()

        form = json.loads(
            (unpadder.update(padded_message) + unpadder.finalize()).decode()
        )
    except Exception:
        flask.flash("E2EE failure")
        return 400

    if not h.verify(form.get("code")):
        flask.flash("Invalid CAPTCHA")
        return 403

    return form


@app.get("/")
@app.get("/signup")
@app.get("/signup/")
def index() -> str:
    """index"""

    k, v = RAND.randbytes(32), RAND.randbytes(16)

    flask.session["k"] = k
    flask.session["v"] = v

    return flask.render_template(
        "index.j2",
        c=h.new().image(),
        k=base64.b64encode(k).decode(),
        v=base64.b64encode(v).decode(),
        domain=DOMAIN,
        mdomain=MDOMAIN,
        min_username=MIN_USERNAME,
        admin=ADMIN,
    )


@app.post("/")
@app.post("/signup")
@app.post("/signup/")
@limiter.limit("5 per hour")
def create() -> str:
    """create an email"""

    form: t.Union[int, t.Dict[str, t.Any]] = ee2e_form()

    if type(form) is int:
        return flask.abort(form)

    if form.get("terms") != "on":
        flask.flash("Terms were not accepted")
        return flask.abort(403)

    if not form.get("reason") or not form["reason"].strip():
        flask.flash("No join reason supplied")
        return flask.abort(400)

    request = DEFAULT_REQUEST.copy()

    for k in ("local_part", "name", "password", "password2"):
        if k not in form:
            flask.flash(f"Missing data: {k}")
            return flask.abort(400)

        request[k] = form[k]

    request["local_part"] = request["local_part"].lower()

    if len(request["local_part"]) < MIN_USERNAME:
        flask.flash("Username too short")
        return flask.abort(400)

    reason: str = form["reason"].replace("\n", "  ")

    if (
        better_profanity.profanity.contains_profanity(request["local_part"])
        or better_profanity.profanity.contains_profanity(request["name"])
        or better_profanity.profanity.contains_profanity(reason)
    ):
        flask.flash("Public data contains profanity")
        return flask.abort(400)

    r: requests.Response = requests.post(
        f"https://{MDOMAIN}/api/v1/add/mailbox",
        json=request,
        headers={
            "X-Api-Key": API_KEY,
        },
    )

    if r.ok:
        email_id: str = f"{request['local_part']}@{DOMAIN}"
        message: MIMEMultipart = MIMEMultipart()

        message["From"] = email_id
        message["To"] = ADMIN
        message["X-Priority"] = "1"
        message["Subject"] = (
            f"[IMPORTANT] New mailbox: {request['local_part']} ({request['name']})"
        )

        message.attach(
            MIMEText(
                f"""Hello, {ADMIN}!

This is an email notifying you of this new mailbox by the name of {request['name']} <{email_id}> existence to make moderation easier. \
Please see https://{MDOMAIN}/ if you think something is wrong and that action needs to be taken. \
The user has, in fact, agreed to this.

The following part has the user-supplied signup reason:

    {reason}

Best wishes,

The https://{DOMAIN}/ e-mail signup system on behalf of {request['local_part']}@{DOMAIN}

{datetime.now()}""",
                "plain",
            )
        )

        server: smtplib.SMTP = smtplib.SMTP(MDOMAIN, 587)

        try:
            server.ehlo()
            server.starttls()
            server.login(email_id, request["password"])
            server.sendmail(email_id, ADMIN, message.as_string())
        except Exception:
            flask.flash("Failed to create the mailbox")
            return flask.flash(403)
        finally:
            server.quit()

    flask.flash("Mailbox created")

    return flask.render_template(
        "done.j2",
        c=r.status_code,
        j=json.dumps(r.json(), indent=4),
    )


@app.get("/delete")
@app.get("/delete/")
@app.get("/signup/delete")
@app.get("/signup/delete/")
def delete() -> str:
    """delete a mailbox"""

    k, v = RAND.randbytes(32), RAND.randbytes(16)

    flask.session["k"] = k
    flask.session["v"] = v

    return flask.render_template(
        "delete.j2",
        c=h.new().image(),
        k=base64.b64encode(k).decode(),
        v=base64.b64encode(v).decode(),
        domain=DOMAIN,
        mdomain=MDOMAIN,
        min_username=MIN_USERNAME,
    )


@app.post("/delete")
@app.post("/delete/")
@app.post("/signup/delete")
@app.post("/signup/delete/")
@limiter.limit("5 per hour")
def delete_mailbox() -> str:
    """delete mailbox"""

    form: t.Union[int, t.Dict[str, t.Any]] = ee2e_form()

    if type(form) is int:
        return flask.abort(form)

    if form.get("sure") != "on":
        flask.flash("Person was not sure")
        return flask.abort(403)

    if "local_part" not in form or "password" not in form:
        flask.flash("Missing credentials")
        return flask.abort(400)

    email_id: str = f"{form['local_part'].lower()}@{DOMAIN}"

    server: smtplib.SMTP = smtplib.SMTP(MDOMAIN, 587)

    try:
        server.ehlo()
        server.starttls()
        server.login(email_id, form["password"])
    except Exception:
        flask.flash("Invalid mailbox credentials")
        return flask.abort(403)
    finally:
        server.quit()

    r: requests.Response = requests.post(
        f"https://{MDOMAIN}/api/v1/delete/mailbox",
        json=[email],
        headers={
            "X-Api-Key": API_KEY,
        },
    )

    flask.flash("Mailbox deleted")

    return flask.render_template(
        "done.j2",
        c=r.status_code,
        j=json.dumps(r.json(), indent=4),
    )


@app.route("/favicon.ico", methods=["GET", "POST"])
@app.route("/signup/favicon.ico", methods=["GET", "POST"])
def favicon() -> Response:
    """favicon"""
    return flask.redirect("https://ari.lt/favicon.ico")


@app.route("/robots.txt", methods=["GET", "POST"])
@app.route("/signup/robots.txt", methods=["GET", "POST"])
def robots() -> Response:
    """robots.txt"""
    return flask.Response(
        "User-agent: *\nAllow: *\n",
        mimetype="text/plain",
    )


@app.after_request
def headers(response: flask.Response) -> flask.Response:
    """update headers, allow all origins, hsts"""

    response.headers.extend(getattr(flask.g, "headers", {}))

    if not app.debug:
        response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

    response.headers["X-Frame-Options"] = "none"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@app.errorhandler(HTTPException)
def http_handler(e: HTTPException) -> t.Tuple[t.Any, int]:
    """handle http errors"""

    if e.code == 429:
        return (
            flask.Response(
                f"Too many requests: {e.description or '<limit>'}",
                mimetype="text/plain",
            ),
            429,
        )

    return (
        flask.render_template(
            "http.j2",
            code=e.code,
            summary=e.name,
            description=e.description or f"HTTP error code {e.code}",
        ),
        e.code or 200,
    )


def main() -> int:
    """entry / main function"""

    app.run("127.0.0.1", 13912, True)

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
