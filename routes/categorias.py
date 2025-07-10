from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.categoria import db, Categoria
from models.proyecto import Proyecto

categorias_bp = Blueprint('categorias', __name__)

@categorias_bp.route('/categorias', methods=['POST'])
@jwt_required()
def agregar_categoria():
    datos = request.get_json()
    if not all(k in datos for k in ['id_proyecto', 'nombre']):
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    proyecto = Proyecto.query.get_or_404(datos['id_proyecto'])
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    nueva_categoria = Categoria(id_proyecto=datos['id_proyecto'], nombre=datos['nombre'])
    db.session.add(nueva_categoria)
    db.session.commit()
    return jsonify({'id_categoria': nueva_categoria.id_categoria, 'nombre': nueva_categoria.nombre}), 201

@categorias_bp.route('/categorias', methods=['GET'])
@jwt_required()
def listar_categorias():
    id_proyecto = request.args.get('id_proyecto', type=int)
    if not id_proyecto:
        return jsonify({'mensaje': 'Se requiere id_proyecto'}), 400
    proyecto = Proyecto.query.get_or_404(id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    categorias = Categoria.query.filter_by(id_proyecto=id_proyecto).all()
    return jsonify([{'id_categoria': c.id_categoria, 'nombre': c.nombre} for c in categorias]), 200

@categorias_bp.route('/categorias/<int:id_categoria>', methods=['DELETE'])
@jwt_required()
def eliminar_categoria(id_categoria):
    categoria = Categoria.query.get_or_404(id_categoria)
    proyecto = Proyecto.query.get_or_404(categoria.id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    db.session.delete(categoria)
    db.session.commit()
    return jsonify({'mensaje': 'Categoría eliminada'}), 200