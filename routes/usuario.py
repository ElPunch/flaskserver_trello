from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Usuario

usuarios_bp = Blueprint('usuarios', __name__)

@usuarios_bp.route('/registrar', methods=['POST'])
def registrar():
    datos = request.get_json()
    if not all(k in datos for k in ['nombre', 'email', 'contrasena']):
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    if Usuario.query.filter_by(email=datos['email']).first():
        return jsonify({'mensaje': 'El correo ya está registrado'}), 400
    contrasena_hash = generate_password_hash(datos['contrasena'], method='sha256')
    nuevo_usuario = Usuario(
        nombre=datos['nombre'],
        email=datos['email'],
        contrasena=contrasena_hash,
        es_admin=False
    )
    db.session.add(nuevo_usuario)
    db.session.commit()
    return jsonify({'mensaje': 'Usuario registrado exitosamente'}), 201

@usuarios_bp.route('/iniciar_sesion', methods=['POST'])
def iniciar_sesion():
    datos = request.get_json()
    if not all(k in datos for k in ['email', 'contrasena']):
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    usuario = Usuario.query.filter_by(email=datos['email']).first()
    if usuario and check_password_hash(usuario.contrasena, datos['contrasena']):
        token_acceso = create_access_token(identity=usuario.id_usuario)
        return jsonify({'token_acceso': token_acceso, 'id_usuario': usuario.id_usuario}), 200
    return jsonify({'mensaje': 'Credenciales inválidas'}), 401

@usuarios_bp.route('/admin/usuarios', methods=['GET'])
@jwt_required()
def listar_usuarios_admin():
    usuario = Usuario.query.get_or_404(get_jwt_identity())
    if not usuario.es_admin:
        return jsonify({'mensaje': 'Se requiere acceso de administrador'}), 403
    usuarios = Usuario.query.all()
    return jsonify([{
        'id_usuario': u.id_usuario,
        'nombre': u.nombre,
        'email': u.email,
        'es_admin': u.es_admin
    } for u in usuarios]), 200

@usuarios_bp.route('/admin/usuarios/<int:id_usuario>', methods=['PUT'])
@jwt_required()
def actualizar_usuario_admin(id_usuario):
    admin = Usuario.query.get_or_404(get_jwt_identity())
    if not admin.es_admin:
        return jsonify({'mensaje': 'Se requiere acceso de administrador'}), 403
    usuario = Usuario.query.get_or_404(id_usuario)
    datos = request.get_json()
    usuario.nombre = datos.get('nombre', usuario.nombre)
    usuario.email = datos.get('email', usuario.email)
    usuario.es_admin = datos.get('es_admin', usuario.es_admin)
    if datos.get('contrasena'):
        usuario.contrasena = generate_password_hash(datos['contrasena'], method='sha256')
    db.session.commit()
    return jsonify({'mensaje': 'Usuario actualizado'}), 200

@usuarios_bp.route('/admin/usuarios/<int:id_usuario>', methods=['DELETE'])
@jwt_required()
def eliminar_usuario_admin(id_usuario):
    admin = Usuario.query.get_or_404(get_jwt_identity())
    if not admin.es_admin:
        return jsonify({'mensaje': 'Se requiere acceso de administrador'}), 403
    usuario = Usuario.query.get_or_404(id_usuario)
    db.session.delete(usuario)
    db.session.commit()
    return jsonify({'mensaje': 'Usuario eliminado'}), 200