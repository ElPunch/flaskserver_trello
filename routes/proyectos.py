from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import db, Proyecto, GrupoTrabajo, Categoria

proyectos_bp = Blueprint('proyectos', __name__)

@proyectos_bp.route('/proyectos', methods=['POST'])
@jwt_required()
def crear_proyecto():
    datos = request.get_json()
    if not all(k in datos for k in ['id_grupo', 'nombre']):
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    grupo = GrupoTrabajo.query.get_or_404(datos['id_grupo'])
    if grupo.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    nuevo_proyecto = Proyecto(
        id_grupo=datos['id_grupo'],
        nombre=datos['nombre'],
        id_usuario_creador=get_jwt_identity()
    )
    db.session.add(nuevo_proyecto)
    db.session.flush()
    categorias_predeterminadas = ['Por Hacer', 'En Progreso', 'Corrección Urgente', 'Completado']
    for nombre in categorias_predeterminadas:
        db.session.add(Categoria(id_proyecto=nuevo_proyecto.id_proyecto, nombre=nombre))
    db.session.commit()
    return jsonify({'id_proyecto': nuevo_proyecto.id_proyecto, 'nombre': nuevo_proyecto.nombre}), 201

@proyectos_bp.route('/proyectos', methods=['GET'])
@jwt_required()
def listar_proyectos():
    proyectos = Proyecto.query.filter_by(id_usuario_creador=get_jwt_identity()).all()
    return jsonify([{'id_proyecto': p.id_proyecto, 'nombre': p.nombre, 'id_grupo': p.id_grupo} for p in proyectos]), 200

@proyectos_bp.route('/proyectos/<int:id_proyecto>', methods=['GET'])
@jwt_required()
def obtener_proyecto(id_proyecto):
    proyecto = Proyecto.query.get_or_404(id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    return jsonify({'id_proyecto': proyecto.id_proyecto, 'nombre': proyecto.nombre, 'id_grupo': proyecto.id_grupo}), 200

@proyectos_bp.route('/proyectos/<int:id_proyecto>', methods=['PUT'])
@jwt_required()
def actualizar_proyecto(id_proyecto):
    proyecto = Proyecto.query.get_or_404(id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    datos = request.get_json()
    if not datos.get('nombre'):
        return jsonify({'mensaje': 'El nombre es obligatorio'}), 400
    proyecto.nombre = datos['nombre']
    db.session.commit()
    return jsonify({'mensaje': 'Proyecto actualizado'}), 200

@proyectos_bp.route('/proyectos/<int:id_proyecto>', methods=['DELETE'])
@jwt_required()
def eliminar_proyecto(id_proyecto):
    proyecto = Proyecto.query.get_or_404(id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    db.session.delete(proyecto)
    db.session.commit()
    return jsonify({'mensaje': 'Proyecto eliminado'}), 200