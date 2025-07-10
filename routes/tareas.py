from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.tarea import db, Tarea
from models.proyecto import Proyecto
from models.categoria import Categoria
from models.estatus import Estatus
from models.tarea_usuario import TareaUsuario
from models.usuario import Usuario

tareas_bp = Blueprint('tareas', __name__)

@tareas_bp.route('/tareas', methods=['POST'])
@jwt_required()
def crear_tarea():
    datos = request.get_json()
    required_fields = ['id_proyecto', 'id_categoria', 'id_estatus', 'titulo']
    if not all(k in datos for k in required_fields):
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    proyecto = Proyecto.query.get_or_404(datos['id_proyecto'])
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    if not Categoria.query.get(datos['id_categoria']):
        return jsonify({'mensaje': 'Categoría no encontrada'}), 404
    if not Estatus.query.get(datos['id_estatus']):
        return jsonify({'mensaje': 'Estatus no encontrado'}), 404
    nueva_tarea = Tarea(
        id_proyecto=datos['id_proyecto'],
        id_categoria=datos['id_categoria'],
        id_estatus=datos['id_estatus'],
        titulo=datos['titulo'],
        descripcion=datos.get('descripcion'),
        fecha_vencimiento=datos.get('fecha_vencimiento'),
        prioridad=datos.get('prioridad')
    )
    db.session.add(nueva_tarea)
    db.session.flush()
    for id_usuario in datos.get('usuarios_asignados', []):
        if not Usuario.query.get(id_usuario):
            return jsonify({'mensaje': f'Usuario {id_usuario} no encontrado'}), 404
        db.session.add(TareaUsuario(id_tarea=nueva_tarea.id_tarea, id_usuario=id_usuario))
    db.session.commit()
    return jsonify({'id_tarea': nueva_tarea.id_tarea, 'titulo': nueva_tarea.titulo}), 201

@tareas_bp.route('/tareas', methods=['GET'])
@jwt_required()
def listar_tareas():
    id_proyecto = request.args.get('id_proyecto', type=int)
    if not id_proyecto:
        return jsonify({'mensaje': 'Se requiere id_proyecto'}), 400
    proyecto = Proyecto.query.get_or_404(id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    tareas = Tarea.query.filter_by(id_proyecto=id_proyecto).all()
    return jsonify([{
        'id_tarea': t.id_tarea,
        'titulo': t.titulo,
        'id_categoria': t.id_categoria,
        'id_estatus': t.id_estatus,
        'descripcion': t.descripcion,
        'prioridad': t.prioridad,
        'fecha_vencimiento': t.fecha_vencimiento,
        'usuarios_asignados': [tu.id_usuario for tu in TareaUsuario.query.filter_by(id_tarea=t.id_tarea).all()]
    } for t in tareas]), 200

@tareas_bp.route('/tareas/<int:id_tarea>', methods=['PUT'])
@jwt_required()
def actualizar_tarea(id_tarea):
    tarea = Tarea.query.get_or_404(id_tarea)
    proyecto = Proyecto.query.get_or_404(tarea.id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    datos = request.get_json()
    tarea.titulo = datos.get('titulo', tarea.titulo)
    tarea.descripcion = datos.get('descripcion', tarea.descripcion)
    tarea.id_categoria = datos.get('id_categoria', tarea.id_categoria)
    tarea.id_estatus = datos.get('id_estatus', tarea.id_estatus)
    tarea.fecha_vencimiento = datos.get('fecha_vencimiento', tarea.fecha_vencimiento)
    tarea.prioridad = datos.get('prioridad', tarea.prioridad)
    if 'usuarios_asignados' in datos:
        TareaUsuario.query.filter_by(id_tarea=id_tarea).delete()
        for id_usuario in datos['usuarios_asignados']:
            if not Usuario.query.get(id_usuario):
                return jsonify({'mensaje': f'Usuario {id_usuario} no encontrado'}), 404
            db.session.add(TareaUsuario(id_tarea=id_tarea, id_usuario=id_usuario))
    db.session.commit()
    return jsonify({'mensaje': 'Tarea actualizada'}), 200

@tareas_bp.route('/tareas/<int:id_tarea>', methods=['DELETE'])
@jwt_required()
def eliminar_tarea(id_tarea):
    tarea = Tarea.query.get_or_404(id_tarea)
    proyecto = Proyecto.query.get_or_404(tarea.id_proyecto)
    if proyecto.id_usuario_creador != get_jwt_identity():
        return jsonify({'mensaje': 'No autorizado'}), 403
    db.session.delete(tarea)
    db.session.commit()
    return jsonify({'mensaje': 'Tarea eliminada'}), 200