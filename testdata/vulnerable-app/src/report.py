"""Deliberately vulnerable Flask/reporting helpers.

Every function here exists to trip exactly one bundled Opengrep rule. Do not
"fix" anything in this file; see ../README.md for the expected findings.

There is intentionally no requirements.txt: adding one would give Trivy and
OSV-Scanner a new dependency source and change their golden finding counts.
"""

import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)


# Trips py-sql-string-formatting.
def orders_for(customer_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE customer_id = {customer_id}")
    return cur.fetchall()


# The safe form of the same call, which must NOT be reported.
def orders_for_safely(customer_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE customer_id = ?", (customer_id,))
    return cur.fetchall()


# Trips py-subprocess-shell-true.
@app.route("/export")
def export():
    name = request.args.get("name")
    subprocess.run("pg_dump " + name + " > /tmp/dump.sql", shell=True, check=False)
    return "ok"


# A literal command line, which must NOT be reported: nothing an attacker
# controls reaches the shell.
def rotate_logs():
    subprocess.run("logrotate -f /etc/logrotate.conf", shell=True, check=False)


# Trips py-yaml-unsafe-load.
def load_config(raw):
    return yaml.load(raw)


# The safe form, which must NOT be reported.
def load_config_safely(raw):
    return yaml.safe_load(raw)


# Trips py-flask-debug-enabled.
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
