"""Reasoning-cache probe via PR: fresh CWE-639 IDOR route (guaranteed org-DB MISS)."""
from flask import Blueprint, request, jsonify
import sqlite3

bp = Blueprint("rc_pr_probe_143552", __name__)


@bp.route("/rc_pr_probe/order")
def get_order():
    order_id = request.args.get("order_id")  # IDOR: no ownership check
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT buyer, total FROM orders WHERE id = ?", (order_id,))
    r = cur.fetchone()
    return jsonify({"buyer": r[0], "total": r[1]} if r else {})
