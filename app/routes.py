from flask import Blueprint, request, jsonify
from . import db
from .models import User
import sqlite3, os

main = Blueprint('main', __name__)

@main.route('/health')
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

# ⚠️ VULNÉRABILITÉ INTENTIONNELLE — SQL Injection (pour Phase 5 SAST)
@main.route('/users')
def get_users():
    search = request.args.get('search', '')
    conn = sqlite3.connect('instance/lab.db')
    cursor = conn.cursor()
    # NE JAMAIS FAIRE CECI EN PRODUCTION
    query = f"SELECT * FROM user WHERE name LIKE '%{search}%'"
    cursor.execute(query)
    users = cursor.fetchall()
    conn.close()
    return jsonify({"users": users})

@main.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    if not data or 'name' not in data or 'email' not in data:
        return jsonify({"error": "name and email required"}), 400
    user = User(name=data['name'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created", "id": user.id}), 201
# BACKDOOR - code malveillant injecté sans review
# test push direct apres protection
