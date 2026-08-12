"""Reasoning-cache probe: a fresh CWE-639 (IDOR) route so sink_type_reasoning must
LLM-reason it -> guaranteed org-DB MISS on this first scan."""
from flask import Blueprint, request, jsonify
import sqlite3

rc_probe_bp = Blueprint("rc_probe_rc_probe_142713", __name__)


@rc_probe_bp.route("/rc_probe/invoice")
def get_invoice():
    # IDOR: invoice_id comes straight from the request and is used to fetch a
    # record with no ownership/authorization check on the current user.
    invoice_id = request.args.get("invoice_id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT customer, amount FROM invoices WHERE id = ?", (invoice_id,))
    row = cur.fetchone()
    return jsonify({"customer": row[0], "amount": row[1]} if row else {})
