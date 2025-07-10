from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import db, GrupoTrabajo

grupos_bp = Blueprint('grupos', __name__)

@grupos_bp.route('/grupos', methods=['POST'])
@jwt_required()
def crear_grupo():
    datos = request.get_json()
    if not datos.get('nombre'):
        return jsonify({'mensaje': 'El nombre es obligatorio'}), 400
    nuevo_grupo = GrupoTrabajo(
        nombre=datos['nombre'],
        id_usuario_creador=get_jwt_identity()
    )
    db.session.add(nuevo_grupo)
    db.session.commit()
    return jsonify({'id_grupo': nuevo_grupo.id_grupo, 'nombre': nuevo_grupo.nombre}), 201

@grupos_bp.route('/grupos', methods=['GET'])
@jwt_required()
def listar_grupos():
    grupos = GrupoTrabajo.query.filter_by(id_usuario_creador=get_jwt_identity()).all()
    return jsonify([{'id_grupo': g.id_grupo, 'nombre': g.nombre} for g in grupos]), 200

@grupos_bp.route('/grupos/<int:id_grupo>', methods=['GET'])
@jwt_required()
def obtener_grupo(id_grupo):
    grupo = GrupoTrabajo.query.get_or_404(id_grupo)
    if grupo.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    return jsonify({'id_grupo': grupo.id_grupo, 'nombre': grupo.nombre}), 200

@grupos_bp.route('/grupos/<int:id_grupo>', methods=['PUT'])
@jwt_required()
def actualizar_grupo(id_grupo):
    grupo = GrupoTrabajo.query.get_or_404(id_grupo)
    if grupo.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    datos = request.get_json()
    if not datos.get('nombre'):
        return jsonify({'mensaje': 'El nombre es obligatorio'}), 400
    grupo.nombre = datos['nombre']
    db.session.commit()
    return jsonify({'mensaje': 'Grupo actualizado'}), 200

@grupos_bp.route('/grupos/<int:id_grupo>', methods=['DELETE'])
@jwt_required()
def eliminar_grupo(id_grupo):
    grupo = GrupoTrabajo.query.get_or_404(id_grupo)
    if grupo.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    db.session.delete(grupo)
    db.session.commit()
    return jsonify({'mensaje': 'Grupo eliminado'}), 200