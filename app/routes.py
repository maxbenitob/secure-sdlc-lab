from flask import Blueprint, request, jsonify
from . import db
from .models import User
import sqlite3, os

main = Blueprint('main', __name__)

@main.route('/health')
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

# ⚠️ VULNÉRABILITÉ INTENTIONNELLE — SQL Injection (pour Phase 5 SAST)
# ✅ CORRIGÉ — Requête paramétrée + validation + ORM
@main.route('/users')
def get_users():
    search = request.args.get('search', '').strip()

    # Validation de l'entrée
    if len(search) > 100:
        return jsonify({"error": "Search term too long"}), 400

    # ORM SQLAlchemy — paramétisation automatique, pas de SQL injection possible
    users = User.query.filter(User.name.like(f'%{search}%')).all()
    return jsonify({"users": [{"id": u.id, "name": u.name, "email": u.email} for u in users]})

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
