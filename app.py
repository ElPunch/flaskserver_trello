from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from supabase import create_client, Client
import re

# Configuración de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'tu-clave-secreta-super-segura')
CORS(app)

# Configuración de Supabase
DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_KEY = os.getenv("DATABASE_KEY")
supabase: Client = create_client(DATABASE_URL, DATABASE_KEY)

# Función para validar email
def validar_email(email):
    patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, email) is not None

# Decorator para rutas protegidas
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token es requerido'}), 401
        
        try:
            # Remover 'Bearer ' del token si existe
            if token.startswith('Bearer '):
                token = token[7:]
            
            # Decodificar el token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            usuario_id = data['usuario_id']
            
            # Verificar que el usuario existe
            resultado = supabase.table('usuarios').select('*').eq('id_usuario', usuario_id).execute()
            if not resultado.data:
                return jsonify({'error': 'Usuario no encontrado'}), 401
            
            # Pasar el usuario actual a la función
            return f(usuario_id, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token ha expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        except Exception as e:
            return jsonify({'error': 'Error al validar token'}), 401
    
    return decorated

# Ruta de registro
@app.route('/registro', methods=['POST'])
def registro():
    try:
        datos = request.get_json()
        
        # Validar datos requeridos
        if not datos or not datos.get('nombre') or not datos.get('email') or not datos.get('contrasena'):
            return jsonify({'error': 'Nombre, email y contraseña son requeridos'}), 400
        
        nombre = datos['nombre'].strip()
        email = datos['email'].strip().lower()
        contrasena = datos['contrasena']
        
        # Validaciones
        if len(nombre) < 2:
            return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
        
        if not validar_email(email):
            return jsonify({'error': 'Email inválido'}), 400
        
        if len(contrasena) < 6:
            return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400
        
        # Verificar si el email ya existe
        resultado = supabase.table('usuarios').select('id_usuario').eq('email', email).execute()
        if resultado.data:
            return jsonify({'error': 'El email ya está registrado'}), 400
        
        # Cifrar contraseña
        contrasena_cifrada = generate_password_hash(contrasena)
        
        # Crear usuario
        nuevo_usuario = {
            'nombre': nombre,
            'email': email,
            'contrasena': contrasena_cifrada,
            'es_admin': False
        }
        
        resultado = supabase.table('usuarios').insert(nuevo_usuario).execute()
        
        if resultado.data:
            usuario_creado = resultado.data[0]
            return jsonify({
                'mensaje': 'Usuario registrado exitosamente',
                'usuario': {
                    'id_usuario': usuario_creado['id_usuario'],
                    'nombre': usuario_creado['nombre'],
                    'email': usuario_creado['email'],
                    'fecha_registro': usuario_creado['fecha_registro']
                }
            }), 201
        else:
            return jsonify({'error': 'Error al crear usuario'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta de inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    try:
        datos = request.get_json()
        
        # Validar datos requeridos
        if not datos or not datos.get('email') or not datos.get('contrasena'):
            return jsonify({'error': 'Email y contraseña son requeridos'}), 400
        
        email = datos['email'].strip().lower()
        contrasena = datos['contrasena']
        
        # Buscar usuario por email
        resultado = supabase.table('usuarios').select('*').eq('email', email).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        usuario = resultado.data[0]
        
        # Verificar contraseña
        if not check_password_hash(usuario['contrasena'], contrasena):
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        # Generar token JWT
        token_payload = {
            'usuario_id': usuario['id_usuario'],
            'email': usuario['email'],
            'exp': datetime.utcnow() + timedelta(hours=24)  # Token válido por 24 horas
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'mensaje': 'Inicio de sesión exitoso',
            'token': token,
            'usuario': {
                'id_usuario': usuario['id_usuario'],
                'nombre': usuario['nombre'],
                'email': usuario['email'],
                'es_admin': usuario['es_admin']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para obtener perfil del usuario autenticado
@app.route('/perfil', methods=['GET'])
@token_required
def perfil(usuario_id):
    try:
        # Obtener datos del usuario
        resultado = supabase.table('usuarios').select('id_usuario, nombre, email, es_admin, fecha_registro').eq('id_usuario', usuario_id).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        usuario = resultado.data[0]
        
        return jsonify({
            'usuario': usuario
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para actualizar perfil del usuario
@app.route('/perfil', methods=['PUT'])
@token_required
def actualizar_perfil(usuario_id):
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se proporcionaron datos para actualizar'}), 400
        
        # Campos permitidos para actualizar
        campos_actualizables = {}
        
        if 'nombre' in datos:
            nombre = datos['nombre'].strip()
            if len(nombre) < 2:
                return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
            campos_actualizables['nombre'] = nombre
        
        if 'email' in datos:
            email = datos['email'].strip().lower()
            if not validar_email(email):
                return jsonify({'error': 'Email inválido'}), 400
            
            # Verificar si el email ya existe (excluyendo el usuario actual)
            resultado = supabase.table('usuarios').select('id_usuario').eq('email', email).neq('id_usuario', usuario_id).execute()
            if resultado.data:
                return jsonify({'error': 'El email ya está en uso por otro usuario'}), 400
            
            campos_actualizables['email'] = email
        
        if not campos_actualizables:
            return jsonify({'error': 'No se proporcionaron campos válidos para actualizar'}), 400
        
        # Actualizar usuario
        resultado = supabase.table('usuarios').update(campos_actualizables).eq('id_usuario', usuario_id).execute()
        
        if resultado.data:
            usuario_actualizado = resultado.data[0]
            return jsonify({
                'mensaje': 'Perfil actualizado exitosamente',
                'usuario': {
                    'id_usuario': usuario_actualizado['id_usuario'],
                    'nombre': usuario_actualizado['nombre'],
                    'email': usuario_actualizado['email'],
                    'es_admin': usuario_actualizado['es_admin'],
                    'fecha_registro': usuario_actualizado['fecha_registro']
                }
            }), 200
        else:
            return jsonify({'error': 'Error al actualizar perfil'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para cambiar contraseña
@app.route('/cambiar-contrasena', methods=['PUT'])
@token_required
def cambiar_contrasena(usuario_id):
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('contrasena_actual') or not datos.get('contrasena_nueva'):
            return jsonify({'error': 'Contraseña actual y nueva son requeridas'}), 400
        
        contrasena_actual = datos['contrasena_actual']
        contrasena_nueva = datos['contrasena_nueva']
        
        # Validar nueva contraseña
        if len(contrasena_nueva) < 6:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres'}), 400
        
        # Obtener usuario actual
        resultado = supabase.table('usuarios').select('contrasena').eq('id_usuario', usuario_id).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        usuario = resultado.data[0]
        
        # Verificar contraseña actual
        if not check_password_hash(usuario['contrasena'], contrasena_actual):
            return jsonify({'error': 'Contraseña actual incorrecta'}), 401
        
        # Cifrar nueva contraseña
        contrasena_cifrada = generate_password_hash(contrasena_nueva)
        
        # Actualizar contraseña
        resultado = supabase.table('usuarios').update({'contrasena': contrasena_cifrada}).eq('id_usuario', usuario_id).execute()
        
        if resultado.data:
            return jsonify({'mensaje': 'Contraseña actualizada exitosamente'}), 200
        else:
            return jsonify({'error': 'Error al actualizar contraseña'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta de salud del servidor
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Servidor Flask funcionando correctamente'
    }), 200

# Manejo de errores
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Ruta no encontrada'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Método no permitido'}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Error interno del servidor'}), 500

# ==============================
# MÓDULO DE PROYECTOS
# ==============================

@app.route('/proyectos', methods=['GET'])
@token_required
def listar_proyectos(usuario_id):
    try:
        # Obtener proyectos del usuario (usando id_usuario_creador)
        resultado = supabase.table('proyectos').select('*').eq('id_usuario_creador', usuario_id).execute()
        
        proyectos = resultado.data if resultado.data else []
        
        return jsonify({
            'proyectos': proyectos
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/proyectos', methods=['POST'])
@token_required
def crear_proyecto(usuario_id):
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('nombre'):
            return jsonify({'error': 'El nombre del proyecto es requerido'}), 400
        
        nombre = datos['nombre'].strip()
        
        if len(nombre) < 2:
            return jsonify({'error': 'El nombre del proyecto debe tener al menos 2 caracteres'}), 400
        
        # Primero, crear un grupo de trabajo personal para el usuario
        grupo_data = {
            'nombre': f'Proyecto Personal - {nombre}',
            'id_usuario_creador': usuario_id
        }
        
        resultado_grupo = supabase.table('grupos_trabajo').insert(grupo_data).execute()
        
        if not resultado_grupo.data:
            return jsonify({'error': 'Error al crear grupo de trabajo'}), 500
        
        id_grupo = resultado_grupo.data[0]['id_grupo']
        
        # Crear el proyecto
        proyecto_data = {
            'nombre': nombre,
            'id_grupo': id_grupo,
            'id_usuario_creador': usuario_id
        }
        
        resultado_proyecto = supabase.table('proyectos').insert(proyecto_data).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Error al crear proyecto'}), 500
        
        proyecto_creado = resultado_proyecto.data[0]
        id_proyecto = proyecto_creado['id_proyecto']
        
        # Crear categorías predeterminadas
        categorias_predeterminadas = [
            {'nombre': 'To Do', 'id_proyecto': id_proyecto},
            {'nombre': 'In Progress', 'id_proyecto': id_proyecto},
            {'nombre': 'Hot Fix', 'id_proyecto': id_proyecto},
            {'nombre': 'Done', 'id_proyecto': id_proyecto}
        ]
        
        resultado_categorias = supabase.table('categorias').insert(categorias_predeterminadas).execute()
        
        if not resultado_categorias.data:
            # Si falla la creación de categorías, eliminar el proyecto
            supabase.table('proyectos').delete().eq('id_proyecto', id_proyecto).execute()
            supabase.table('grupos_trabajo').delete().eq('id_grupo', id_grupo).execute()
            return jsonify({'error': 'Error al crear categorías predeterminadas'}), 500
        
        return jsonify({
            'mensaje': 'Proyecto creado exitosamente',
            'proyecto': proyecto_creado,
            'categorias': resultado_categorias.data
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/proyectos/<int:id_proyecto>', methods=['DELETE'])
@token_required
def eliminar_proyecto(usuario_id, id_proyecto):
    try:
        # Verificar que el proyecto existe y pertenece al usuario
        resultado = supabase.table('proyectos').select('*').eq('id_proyecto', id_proyecto).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        proyecto = resultado.data[0]
        id_grupo = proyecto['id_grupo']
        
        # Eliminar tareas asociadas (las relaciones en tareas_usuarios se eliminarán automáticamente)
        supabase.table('tareas_usuarios').delete().eq('id_tarea', 'in', 
            f"(SELECT id_tarea FROM tareas WHERE id_proyecto = {id_proyecto})").execute()
        
        supabase.table('tareas').delete().eq('id_proyecto', id_proyecto).execute()
        
        # Eliminar categorías del proyecto
        supabase.table('categorias').delete().eq('id_proyecto', id_proyecto).execute()
        
        # Eliminar el proyecto
        supabase.table('proyectos').delete().eq('id_proyecto', id_proyecto).execute()
        
        # Eliminar el grupo de trabajo
        supabase.table('grupos_trabajo').delete().eq('id_grupo', id_grupo).execute()
        
        return jsonify({'mensaje': 'Proyecto eliminado exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ==============================
# MÓDULO DE CATEGORÍAS (OPCIONAL)
# ==============================

@app.route('/categorias', methods=['GET'])
@token_required
def listar_categorias(usuario_id):
    try:
        proyecto_id = request.args.get('proyecto_id')
        
        if not proyecto_id:
            return jsonify({'error': 'proyecto_id es requerido'}), 400
        
        # Verificar que el proyecto pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        # Obtener categorías del proyecto
        resultado = supabase.table('categorias').select('*').eq('id_proyecto', proyecto_id).execute()
        
        categorias = resultado.data if resultado.data else []
        
        return jsonify({
            'categorias': categorias
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/categorias', methods=['POST'])
@token_required
def crear_categoria(usuario_id):
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('nombre') or not datos.get('proyecto_id'):
            return jsonify({'error': 'Nombre y proyecto_id son requeridos'}), 400
        
        nombre = datos['nombre'].strip()
        proyecto_id = datos['proyecto_id']
        
        if len(nombre) < 2:
            return jsonify({'error': 'El nombre de la categoría debe tener al menos 2 caracteres'}), 400
        
        # Verificar que el proyecto pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        # Verificar que no existe una categoría con el mismo nombre en el proyecto
        resultado_existe = supabase.table('categorias').select('id_categoria').eq('nombre', nombre).eq('id_proyecto', proyecto_id).execute()
        
        if resultado_existe.data:
            return jsonify({'error': 'Ya existe una categoría con ese nombre en el proyecto'}), 400
        
        # Crear la categoría
        categoria_data = {
            'nombre': nombre,
            'id_proyecto': proyecto_id
        }
        
        resultado = supabase.table('categorias').insert(categoria_data).execute()
        
        if resultado.data:
            return jsonify({
                'mensaje': 'Categoría creada exitosamente',
                'categoria': resultado.data[0]
            }), 201
        else:
            return jsonify({'error': 'Error al crear categoría'}), 500
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/categorias/<int:id_categoria>', methods=['DELETE'])
@token_required
def eliminar_categoria(usuario_id, id_categoria):
    try:
        # Verificar que la categoría existe y el usuario tiene permisos
        resultado = supabase.table('categorias').select('*, proyectos!inner(id_usuario_creador)').eq('id_categoria', id_categoria).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Categoría no encontrada'}), 404
        
        categoria = resultado.data[0]
        
        # Verificar que el usuario es el creador del proyecto
        if categoria['proyectos']['id_usuario_creador'] != usuario_id:
            return jsonify({'error': 'No tienes permisos para eliminar esta categoría'}), 403
        
        # Verificar que no hay tareas asociadas a esta categoría
        resultado_tareas = supabase.table('tareas').select('id_tarea').eq('id_categoria', id_categoria).execute()
        
        if resultado_tareas.data:
            return jsonify({'error': 'No se puede eliminar la categoría porque tiene tareas asociadas'}), 400
        
        # Eliminar la categoría
        supabase.table('categorias').delete().eq('id_categoria', id_categoria).execute()
        
        return jsonify({'mensaje': 'Categoría eliminada exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ==============================
# MÓDULO DE TAREAS
# ==============================

@app.route('/tareas/<int:id_proyecto>', methods=['GET'])
@token_required
def listar_tareas(usuario_id, id_proyecto):
    try:
        # Verificar que el proyecto pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', id_proyecto).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        # Obtener tareas del proyecto con información de categoría y estatus
        resultado = supabase.table('tareas').select('''
            *,
            categorias!inner(nombre),
            estatus!inner(nombre)
        ''').eq('id_proyecto', id_proyecto).execute()
        
        tareas = []
        for tarea in resultado.data if resultado.data else []:
            tarea_info = {
                'id_tarea': tarea['id_tarea'],
                'titulo': tarea['titulo'],
                'descripcion': tarea['descripcion'],
                'prioridad': tarea['prioridad'],
                'fecha_creacion': tarea['fecha_creacion'],
                'fecha_vencimiento': tarea['fecha_vencimiento'],
                'categoria': tarea['categorias']['nombre'],
                'estatus': tarea['estatus']['nombre']
            }
            tareas.append(tarea_info)
        
        return jsonify({
            'tareas': tareas
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/tareas', methods=['POST'])
@token_required
def crear_tarea(usuario_id):
    try:
        datos = request.get_json()
        
        # Validar datos requeridos
        campos_requeridos = ['titulo', 'id_proyecto', 'nombre_categoria', 'nombre_estatus']
        for campo in campos_requeridos:
            if not datos or not datos.get(campo):
                return jsonify({'error': f'{campo} es requerido'}), 400
        
        titulo = datos['titulo'].strip()
        descripcion = datos.get('descripcion', '').strip()
        nombre_categoria = datos['nombre_categoria'].strip()
        nombre_estatus = datos['nombre_estatus'].strip()
        prioridad = datos.get('prioridad', 3)
        fecha_vencimiento = datos.get('fecha_vencimiento')
        id_proyecto = datos['id_proyecto']
        
        # Validaciones
        if len(titulo) < 2:
            return jsonify({'error': 'El título debe tener al menos 2 caracteres'}), 400
        
        if not isinstance(prioridad, int) or prioridad < 1 or prioridad > 5:
            return jsonify({'error': 'La prioridad debe ser un número entre 1 y 5'}), 400
        
        # Verificar que el proyecto pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', id_proyecto).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        # Obtener ID de categoría
        resultado_categoria = supabase.table('categorias').select('id_categoria').eq('nombre', nombre_categoria).eq('id_proyecto', id_proyecto).execute()
        
        if not resultado_categoria.data:
            return jsonify({'error': 'Categoría no encontrada en el proyecto'}), 400
        
        id_categoria = resultado_categoria.data[0]['id_categoria']
        
        # Obtener ID de estatus
        resultado_estatus = supabase.table('estatus').select('id_estatus').eq('nombre', nombre_estatus).execute()
        
        if not resultado_estatus.data:
            return jsonify({'error': 'Estatus no encontrado'}), 400
        
        id_estatus = resultado_estatus.data[0]['id_estatus']
        
        # Crear la tarea
        tarea_data = {
            'titulo': titulo,
            'descripcion': descripcion,
            'id_proyecto': id_proyecto,
            'id_categoria': id_categoria,
            'id_estatus': id_estatus,
            'prioridad': prioridad,
            'fecha_vencimiento': fecha_vencimiento
        }
        
        resultado_tarea = supabase.table('tareas').insert(tarea_data).execute()
        
        if not resultado_tarea.data:
            return jsonify({'error': 'Error al crear tarea'}), 500
        
        tarea_creada = resultado_tarea.data[0]
        id_tarea = tarea_creada['id_tarea']
        
        # Asignar la tarea al usuario
        asignacion_data = {
            'id_tarea': id_tarea,
            'id_usuario': usuario_id
        }
        
        resultado_asignacion = supabase.table('tareas_usuarios').insert(asignacion_data).execute()
        
        if not resultado_asignacion.data:
            # Si falla la asignación, eliminar la tarea
            supabase.table('tareas').delete().eq('id_tarea', id_tarea).execute()
            return jsonify({'error': 'Error al asignar tarea al usuario'}), 500
        
        return jsonify({
            'mensaje': 'Tarea creada exitosamente',
            'tarea': tarea_creada
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/tareas/<int:id_tarea>', methods=['PUT'])
@token_required
def editar_tarea(usuario_id, id_tarea):
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se proporcionaron datos para actualizar'}), 400
        
        # Verificar que la tarea existe y está asignada al usuario
        resultado_tarea = supabase.table('tareas').select('''
            *,
            proyectos!inner(id_usuario_creador)
        ''').eq('id_tarea', id_tarea).execute()
        
        if not resultado_tarea.data:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        
        tarea = resultado_tarea.data[0]
        
        # Verificar que el usuario es el creador del proyecto
        if tarea['proyectos']['id_usuario_creador'] != usuario_id:
            return jsonify({'error': 'No tienes permisos para editar esta tarea'}), 403
        
        # Campos actualizables
        campos_actualizables = {}
        
        if 'titulo' in datos:
            titulo = datos['titulo'].strip()
            if len(titulo) < 2:
                return jsonify({'error': 'El título debe tener al menos 2 caracteres'}), 400
            campos_actualizables['titulo'] = titulo
        
        if 'descripcion' in datos:
            campos_actualizables['descripcion'] = datos['descripcion'].strip()
        
        if 'prioridad' in datos:
            prioridad = datos['prioridad']
            if not isinstance(prioridad, int) or prioridad < 1 or prioridad > 5:
                return jsonify({'error': 'La prioridad debe ser un número entre 1 y 5'}), 400
            campos_actualizables['prioridad'] = prioridad
        
        if 'fecha_vencimiento' in datos:
            campos_actualizables['fecha_vencimiento'] = datos['fecha_vencimiento']
        
        if 'nombre_estatus' in datos:
            nombre_estatus = datos['nombre_estatus'].strip()
            resultado_estatus = supabase.table('estatus').select('id_estatus').eq('nombre', nombre_estatus).execute()
            
            if not resultado_estatus.data:
                return jsonify({'error': 'Estatus no encontrado'}), 400
            
            campos_actualizables['id_estatus'] = resultado_estatus.data[0]['id_estatus']
        
        if 'nombre_categoria' in datos:
            nombre_categoria = datos['nombre_categoria'].strip()
            resultado_categoria = supabase.table('categorias').select('id_categoria').eq('nombre', nombre_categoria).eq('id_proyecto', tarea['id_proyecto']).execute()
            
            if not resultado_categoria.data:
                return jsonify({'error': 'Categoría no encontrada en el proyecto'}), 400
            
            campos_actualizables['id_categoria'] = resultado_categoria.data[0]['id_categoria']
        
        if not campos_actualizables:
            return jsonify({'error': 'No se proporcionaron campos válidos para actualizar'}), 400
        
        # Actualizar la tarea
        resultado = supabase.table('tareas').update(campos_actualizables).eq('id_tarea', id_tarea).execute()
        
        if resultado.data:
            return jsonify({
                'mensaje': 'Tarea actualizada exitosamente',
                'tarea': resultado.data[0]
            }), 200
        else:
            return jsonify({'error': 'Error al actualizar tarea'}), 500
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

@app.route('/tareas/<int:id_tarea>', methods=['DELETE'])
@token_required
def eliminar_tarea(usuario_id, id_tarea):
    try:
        # Verificar que la tarea existe y el usuario tiene permisos
        resultado_tarea = supabase.table('tareas').select('''
            *,
            proyectos!inner(id_usuario_creador)
        ''').eq('id_tarea', id_tarea).execute()
        
        if not resultado_tarea.data:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        
        tarea = resultado_tarea.data[0]
        
        # Verificar que el usuario es el creador del proyecto
        if tarea['proyectos']['id_usuario_creador'] != usuario_id:
            return jsonify({'error': 'No tienes permisos para eliminar esta tarea'}), 403
        
        # Eliminar relación en tareas_usuarios
        supabase.table('tareas_usuarios').delete().eq('id_tarea', id_tarea).execute()
        
        # Eliminar la tarea
        supabase.table('tareas').delete().eq('id_tarea', id_tarea).execute()
        
        return jsonify({'mensaje': 'Tarea eliminada exitosamente'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ==============================
# MÓDULO DE TABLERO PERSONAL
# ==============================

@app.route('/tablero/<int:id_proyecto>', methods=['GET'])
@token_required
def obtener_tablero(usuario_id, id_proyecto):
    try:
        # Verificar que el proyecto pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('*').eq('id_proyecto', id_proyecto).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no tienes permisos'}), 404
        
        proyecto = resultado_proyecto.data[0]
        
        # Obtener resumen de tareas por categoría
        resultado_tareas = supabase.table('tareas').select('''
            id_tarea,
            titulo,
            descripcion,
            prioridad,
            fecha_creacion,
            fecha_vencimiento,
            categorias!inner(nombre),
            estatus!inner(nombre)
        ''').eq('id_proyecto', id_proyecto).execute()
        
        # Organizar tareas por categoría
        tablero = {
            'proyecto': proyecto,
            'categorias': {
                'To Do': [],
                'In Progress': [],
                'Hot Fix': [],
                'Done': []
            },
            'resumen': {
                'total_tareas': 0,
                'por_categoria': {
                    'To Do': 0,
                    'In Progress': 0,
                    'Hot Fix': 0,
                    'Done': 0
                },
                'por_prioridad': {
                    '1': 0, '2': 0, '3': 0, '4': 0, '5': 0
                }
            }
        }
        
        for tarea in resultado_tareas.data if resultado_tareas.data else []:
            categoria = tarea['categorias']['nombre']
            
            tarea_info = {
                'id_tarea': tarea['id_tarea'],
                'titulo': tarea['titulo'],
                'descripcion': tarea['descripcion'],
                'prioridad': tarea['prioridad'],
                'fecha_creacion': tarea['fecha_creacion'],
                'fecha_vencimiento': tarea['fecha_vencimiento'],
                'estatus': tarea['estatus']['nombre']
            }
            
            if categoria in tablero['categorias']:
                tablero['categorias'][categoria].append(tarea_info)
                tablero['resumen']['por_categoria'][categoria] += 1
            
            tablero['resumen']['total_tareas'] += 1
            tablero['resumen']['por_prioridad'][str(tarea['prioridad'])] += 1
        
        return jsonify(tablero), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)