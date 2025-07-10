from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from models.estatus import db, Estatus

estatus_bp = Blueprint('estatus', __name__)

@estatus_bp.route('/estatus', methods=['GET'])
@jwt_required()
def listar_estatus():
    estatus = Estatus.query.all()
    return jsonify([{'id_estatus': e.id_estatus, 'nombre': e.nombre} for e in estatus]), 200