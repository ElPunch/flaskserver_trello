from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from supabase import create_client, Client
from dotenv import load_dotenv
import re

# Configuración de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

# Configuración mejorada de CORS
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:4200", "http://127.0.0.1:4200"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Credentials"],
        "supports_credentials": True
    }
})

# Configuración de Supabase
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_KEY = os.getenv("DATABASE_KEY")
supabase: Client = create_client(DATABASE_URL, DATABASE_KEY)

# Añadir manejador explícito para OPTIONS
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

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

# ========================== RUTAS DE AUTENTICACIÓN ==========================

# Ruta de registro
@app.route('/registro', methods=['POST', 'OPTIONS'])
def registro():
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
        
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
            'es_admin': False,
            'id_grupo': 1,  # Grupo por defecto
            'id_usuario_creador': 1  # Usuario creador por defecto
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
                    'es_admin': usuario_creado['es_admin'],
                    'fecha_registro': usuario_creado['fecha_registro'],
                    'id_grupo': usuario_creado['id_grupo'],
                    'id_usuario_creador': usuario_creado['id_usuario_creador']
                }
            }), 201
        else:
            return jsonify({'error': 'Error al crear usuario'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta de inicio de sesión
@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
        
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
                'es_admin': usuario['es_admin'],
                'fecha_registro': usuario['fecha_registro'],
                'id_grupo': usuario['id_grupo'],
                'id_usuario_creador': usuario['id_usuario_creador']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para obtener perfil del usuario autenticado
@app.route('/perfil', methods=['GET', 'OPTIONS'])
@token_required
def perfil(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
        
    try:
        # Obtener datos del usuario
        resultado = supabase.table('usuarios').select('*').eq('id_usuario', usuario_id).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        usuario = resultado.data[0]
        
        return jsonify({
            'usuario': {
                'id_usuario': usuario['id_usuario'],
                'nombre': usuario['nombre'],
                'email': usuario['email'],
                'es_admin': usuario['es_admin'],
                'fecha_registro': usuario['fecha_registro'],
                'id_grupo': usuario['id_grupo'],
                'id_usuario_creador': usuario['id_usuario_creador']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para actualizar perfil
@app.route('/perfil', methods=['PUT', 'OPTIONS'])
@token_required
def actualizar_perfil(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "PUT,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se enviaron datos'}), 400
        
        # Preparar datos para actualizar
        datos_actualizacion = {}
        
        if 'nombre' in datos:
            nombre = datos['nombre'].strip()
            if len(nombre) < 2:
                return jsonify({'error': 'El nombre debe tener al menos 2 caracteres'}), 400
            datos_actualizacion['nombre'] = nombre
        
        if 'email' in datos:
            email = datos['email'].strip().lower()
            if not validar_email(email):
                return jsonify({'error': 'Email inválido'}), 400
            
            # Verificar si el email ya existe (excluyendo el usuario actual)
            resultado = supabase.table('usuarios').select('id_usuario').eq('email', email).neq('id_usuario', usuario_id).execute()
            if resultado.data:
                return jsonify({'error': 'El email ya está registrado'}), 400
            
            datos_actualizacion['email'] = email
        
        if not datos_actualizacion:
            return jsonify({'error': 'No se enviaron datos válidos para actualizar'}), 400
        
        # Actualizar usuario
        resultado = supabase.table('usuarios').update(datos_actualizacion).eq('id_usuario', usuario_id).execute()
        
        if resultado.data:
            usuario_actualizado = resultado.data[0]
            return jsonify({
                'mensaje': 'Perfil actualizado exitosamente',
                'usuario': {
                    'id_usuario': usuario_actualizado['id_usuario'],
                    'nombre': usuario_actualizado['nombre'],
                    'email': usuario_actualizado['email'],
                    'es_admin': usuario_actualizado['es_admin'],
                    'fecha_registro': usuario_actualizado['fecha_registro'],
                    'id_grupo': usuario_actualizado['id_grupo'],
                    'id_usuario_creador': usuario_actualizado['id_usuario_creador']
                }
            }), 200
        else:
            return jsonify({'error': 'Error al actualizar perfil'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Ruta para cambiar contraseña
@app.route('/cambiar-contrasena', methods=['PUT', 'OPTIONS'])
@token_required
def cambiar_contrasena(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "PUT,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('contrasena_actual') or not datos.get('contrasena_nueva'):
            return jsonify({'error': 'Contraseña actual y nueva son requeridas'}), 400
        
        contrasena_actual = datos['contrasena_actual']
        contrasena_nueva = datos['contrasena_nueva']
        
        # Validar nueva contraseña
        if len(contrasena_nueva) < 6:
            return jsonify({'error': 'La nueva contraseña debe tener al menos 6 caracteres'}), 400
        
        # Obtener usuario
        resultado = supabase.table('usuarios').select('contrasena').eq('id_usuario', usuario_id).execute()
        
        if not resultado.data:
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        usuario = resultado.data[0]
        
        # Verificar contraseña actual
        if not check_password_hash(usuario['contrasena'], contrasena_actual):
            return jsonify({'error': 'Contraseña actual incorrecta'}), 401
        
        # Cifrar nueva contraseña
        nueva_contrasena_cifrada = generate_password_hash(contrasena_nueva)
        
        # Actualizar contraseña
        resultado = supabase.table('usuarios').update({
            'contrasena': nueva_contrasena_cifrada
        }).eq('id_usuario', usuario_id).execute()
        
        if resultado.data:
            return jsonify({
                'mensaje': 'Contraseña actualizada exitosamente'
            }), 200
        else:
            return jsonify({'error': 'Error al actualizar contraseña'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ========================== RUTAS DE PROYECTOS ==========================

# Crear proyecto
@app.route('/proyectos', methods=['POST', 'OPTIONS'])
@token_required
def crear_proyecto(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('nombre'):
            return jsonify({'error': 'Nombre del proyecto es requerido'}), 400
        
        nombre = datos['nombre'].strip()
        
        if len(nombre) < 2:
            return jsonify({'error': 'El nombre del proyecto debe tener al menos 2 caracteres'}), 400
        
        # Crear proyecto
        nuevo_proyecto = {
            'nombre': nombre,
            'id_grupo': 1,  # Grupo por defecto
            'id_usuario_creador': usuario_id
        }
        
        resultado = supabase.table('proyectos').insert(nuevo_proyecto).execute()
        
        if resultado.data:
            proyecto_creado = resultado.data[0]
            
            # Crear categorías por defecto
            categorias_default = ['To Do', 'In Progress', 'Hot Fix', 'Done']
            categorias_creadas = []
            
            for categoria_nombre in categorias_default:
                categoria = {
                    'nombre': categoria_nombre,
                    'id_proyecto': proyecto_creado['id_proyecto']
                }
                resultado_categoria = supabase.table('categorias').insert(categoria).execute()
                if resultado_categoria.data:
                    categorias_creadas.append(resultado_categoria.data[0])
            
            return jsonify({
                'mensaje': 'Proyecto creado exitosamente',
                'proyecto': {
                    'id_proyecto': proyecto_creado['id_proyecto'],
                    'nombre': proyecto_creado['nombre'],
                    'id_grupo': proyecto_creado['id_grupo'],
                    'id_usuario_creador': proyecto_creado['id_usuario_creador'],
                    'fecha_creacion': proyecto_creado['fecha_creacion']
                },
                'categorias': categorias_creadas
            }), 201
        else:
            return jsonify({'error': 'Error al crear proyecto'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Listar proyectos
@app.route('/proyectos', methods=['GET', 'OPTIONS'])
@token_required
def listar_proyectos(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
        
    try:
        # Obtener proyectos del usuario
        resultado = supabase.table('proyectos').select('*').eq('id_usuario_creador', usuario_id).execute()
        
        proyectos = []
        if resultado.data:
            for proyecto in resultado.data:
                proyectos.append({
                    'id_proyecto': proyecto['id_proyecto'],
                    'nombre': proyecto['nombre'],
                    'id_grupo': proyecto['id_grupo'],
                    'id_usuario_creador': proyecto['id_usuario_creador'],
                    'fecha_creacion': proyecto['fecha_creacion']
                })
        
        return jsonify({
            'proyectos': proyectos
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ========================== RUTAS DE CATEGORÍAS ==========================

# Crear categoría
@app.route('/categorias', methods=['POST', 'OPTIONS'])
@token_required
def crear_categoria(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('nombre') or not datos.get('proyecto_id'):
            return jsonify({'error': 'Nombre y proyecto_id son requeridos'}), 400
        
        nombre = datos['nombre'].strip()
        proyecto_id = datos['proyecto_id']
        
        if len(nombre) < 2:
            return jsonify({'error': 'El nombre de la categoría debe tener al menos 2 caracteres'}), 400
        
        # Verificar que el proyecto existe y pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no autorizado'}), 404
        
        # Crear categoría
        nueva_categoria = {
            'nombre': nombre,
            'id_proyecto': proyecto_id
        }
        
        resultado = supabase.table('categorias').insert(nueva_categoria).execute()
        
        if resultado.data:
            categoria_creada = resultado.data[0]
            return jsonify({
                'mensaje': 'Categoría creada exitosamente',
                'categoria': {
                    'id_categoria': categoria_creada['id_categoria'],
                    'nombre': categoria_creada['nombre'],
                    'id_proyecto': categoria_creada['id_proyecto']
                }
            }), 201
        else:
            return jsonify({'error': 'Error al crear categoría'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Listar categorías por proyecto
@app.route('/proyectos/<int:proyecto_id>/categorias', methods=['GET', 'OPTIONS'])
@token_required
def listar_categorias(usuario_id, proyecto_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
        
    try:
        # Verificar que el proyecto existe y pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no autorizado'}), 404
        
        # Obtener categorías del proyecto
        resultado = supabase.table('categorias').select('*').eq('id_proyecto', proyecto_id).execute()
        
        categorias = []
        if resultado.data:
            for categoria in resultado.data:
                categorias.append({
                    'id_categoria': categoria['id_categoria'],
                    'nombre': categoria['nombre'],
                    'id_proyecto': categoria['id_proyecto']
                })
        
        return jsonify({
            'categorias': categorias
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ========================== RUTAS DE TAREAS ==========================

# Crear tarea
@app.route('/tareas', methods=['POST', 'OPTIONS'])
@token_required
def crear_tarea(usuario_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos or not datos.get('titulo') or not datos.get('id_proyecto') or not datos.get('nombre_categoria') or not datos.get('nombre_estatus'):
            return jsonify({'error': 'Título, id_proyecto, nombre_categoria y nombre_estatus son requeridos'}), 400
        
        titulo = datos['titulo'].strip()
        descripcion = datos.get('descripcion', '').strip()
        id_proyecto = datos['id_proyecto']
        nombre_categoria = datos['nombre_categoria'].strip()
        nombre_estatus = datos['nombre_estatus'].strip()
        prioridad = datos.get('prioridad', 3)
        fecha_vencimiento = datos.get('fecha_vencimiento')
        
        if len(titulo) < 2:
            return jsonify({'error': 'El título debe tener al menos 2 caracteres'}), 400
        
        # Verificar que el proyecto existe y pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', id_proyecto).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no autorizado'}), 404
        
        # Buscar o crear categoría
        resultado_categoria = supabase.table('categorias').select('id_categoria').eq('nombre', nombre_categoria).eq('id_proyecto', id_proyecto).execute()
        
        if not resultado_categoria.data:
            # Crear categoría
            nueva_categoria = {
                'nombre': nombre_categoria,
                'id_proyecto': id_proyecto
            }
            resultado_categoria = supabase.table('categorias').insert(nueva_categoria).execute()
            if resultado_categoria.data:
                id_categoria = resultado_categoria.data[0]['id_categoria']
            else:
                return jsonify({'error': 'Error al crear categoría'}), 500
        else:
            id_categoria = resultado_categoria.data[0]['id_categoria']
        
        # Buscar o crear estatus
        resultado_estatus = supabase.table('estatus').select('id_estatus').eq('nombre', nombre_estatus).execute()
        
        if not resultado_estatus.data:
            # Crear estatus
            nuevo_estatus = {
                'nombre': nombre_estatus
            }
            resultado_estatus = supabase.table('estatus').insert(nuevo_estatus).execute()
            if resultado_estatus.data:
                id_estatus = resultado_estatus.data[0]['id_estatus']
            else:
                return jsonify({'error': 'Error al crear estatus'}), 500
        else:
            id_estatus = resultado_estatus.data[0]['id_estatus']
        
        # Crear tarea
        nueva_tarea = {
            'titulo': titulo,
            'descripcion': descripcion,
            'id_proyecto': id_proyecto,
            'id_categoria': id_categoria,
            'id_estatus': id_estatus,
            'prioridad': prioridad,
            'fecha_vencimiento': fecha_vencimiento
        }
        
        resultado = supabase.table('tareas').insert(nueva_tarea).execute()
        
        if resultado.data:
            tarea_creada = resultado.data[0]
            return jsonify({
                'mensaje': 'Tarea creada exitosamente',
                'tarea': {
                    'id_tarea': tarea_creada['id_tarea'],
                    'titulo': tarea_creada['titulo'],
                    'descripcion': tarea_creada['descripcion'],
                    'prioridad': tarea_creada['prioridad'],
                    'fecha_creacion': tarea_creada['fecha_creacion'],
                    'fecha_vencimiento': tarea_creada['fecha_vencimiento'],
                    'categoria': nombre_categoria,
                    'estatus': nombre_estatus,
                    'id_proyecto': tarea_creada['id_proyecto'],
                    'id_categoria': tarea_creada['id_categoria'],
                    'id_estatus': tarea_creada['id_estatus']
                }
            }), 201
        else:
            return jsonify({'error': 'Error al crear tarea'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Listar tareas por proyecto
@app.route('/proyectos/<int:proyecto_id>/tareas', methods=['GET', 'OPTIONS'])
@token_required
def listar_tareas(usuario_id, proyecto_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
        
    try:
        # Verificar que el proyecto existe y pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('id_proyecto').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no autorizado'}), 404
        
        # Obtener tareas con joins
        resultado = supabase.table('tareas').select('''
            id_tarea,
            titulo,
            descripcion,
            prioridad,
            fecha_creacion,
            fecha_vencimiento,
            id_proyecto,
            id_categoria,
            id_estatus,
            categorias!inner(nombre),
            estatus!inner(nombre)
        ''').eq('id_proyecto', proyecto_id).execute()
        
        tareas = []
        if resultado.data:
            for tarea in resultado.data:
                tareas.append({
                    'id_tarea': tarea['id_tarea'],
                    'titulo': tarea['titulo'],
                    'descripcion': tarea['descripcion'],
                    'prioridad': tarea['prioridad'],
                    'fecha_creacion': tarea['fecha_creacion'],
                    'fecha_vencimiento': tarea['fecha_vencimiento'],
                    'categoria': tarea['categorias']['nombre'],
                    'estatus': tarea['estatus']['nombre'],
                    'id_proyecto': tarea['id_proyecto'],
                    'id_categoria': tarea['id_categoria'],
                    'id_estatus': tarea['id_estatus']
                })
        
        return jsonify({
            'tareas': tareas
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Actualizar tarea
@app.route('/tareas/<int:tarea_id>', methods=['PUT', 'OPTIONS'])
@token_required
def actualizar_tarea(usuario_id, tarea_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "PUT,OPTIONS")
        return response
        
    try:
        datos = request.get_json()
        
        if not datos:
            return jsonify({'error': 'No se enviaron datos'}), 400
        
        # Verificar que la tarea existe y pertenece a un proyecto del usuario
        resultado_tarea = supabase.table('tareas').select('''
            id_tarea,
            id_proyecto,
            id_categoria,
            id_estatus,
            proyectos!inner(id_usuario_creador)
        ''').eq('id_tarea', tarea_id).execute()
        
        if not resultado_tarea.data:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        
        tarea = resultado_tarea.data[0]
        
        if tarea['proyectos']['id_usuario_creador'] != usuario_id:
            return jsonify({'error': 'No autorizado'}), 403
        
        # Preparar datos para actualizar
        datos_actualizacion = {}
        
        if 'titulo' in datos:
            titulo = datos['titulo'].strip()
            if len(titulo) < 2:
                return jsonify({'error': 'El título debe tener al menos 2 caracteres'}), 400
            datos_actualizacion['titulo'] = titulo
        
        if 'descripcion' in datos:
            datos_actualizacion['descripcion'] = datos['descripcion'].strip()
        
        if 'prioridad' in datos:
            prioridad = datos['prioridad']
            if prioridad not in [1, 2, 3, 4, 5]:
                return jsonify({'error': 'La prioridad debe ser entre 1 y 5'}), 400
            datos_actualizacion['prioridad'] = prioridad
        
        if 'fecha_vencimiento' in datos:
            datos_actualizacion['fecha_vencimiento'] = datos['fecha_vencimiento']
        
        if 'nombre_categoria' in datos:
            nombre_categoria = datos['nombre_categoria'].strip()
            # Buscar o crear categoría
            resultado_categoria = supabase.table('categorias').select('id_categoria').eq('nombre', nombre_categoria).eq('id_proyecto', tarea['id_proyecto']).execute()
            
            if not resultado_categoria.data:
                # Crear categoría
                nueva_categoria = {
                    'nombre': nombre_categoria,
                    'id_proyecto': tarea['id_proyecto']
                }
                resultado_categoria = supabase.table('categorias').insert(nueva_categoria).execute()
                if resultado_categoria.data:
                    datos_actualizacion['id_categoria'] = resultado_categoria.data[0]['id_categoria']
                else:
                    return jsonify({'error': 'Error al crear categoría'}), 500
            else:
                datos_actualizacion['id_categoria'] = resultado_categoria.data[0]['id_categoria']
        
        if 'nombre_estatus' in datos:
            nombre_estatus = datos['nombre_estatus'].strip()
            # Buscar o crear estatus
            resultado_estatus = supabase.table('estatus').select('id_estatus').eq('nombre', nombre_estatus).execute()
            
            if not resultado_estatus.data:
                # Crear estatus
                nuevo_estatus = {
                    'nombre': nombre_estatus
                }
                resultado_estatus = supabase.table('estatus').insert(nuevo_estatus).execute()
                if resultado_estatus.data:
                    datos_actualizacion['id_estatus'] = resultado_estatus.data[0]['id_estatus']
                else:
                    return jsonify({'error': 'Error al crear estatus'}), 500
            else:
                datos_actualizacion['id_estatus'] = resultado_estatus.data[0]['id_estatus']
        
        if not datos_actualizacion:
            return jsonify({'error': 'No se enviaron datos válidos para actualizar'}), 400
        
        # Actualizar tarea
        resultado = supabase.table('tareas').update(datos_actualizacion).eq('id_tarea', tarea_id).execute()
        
        if resultado.data:
            # Obtener tarea actualizada con joins
            resultado_actualizada = supabase.table('tareas').select('''
                id_tarea,
                titulo,
                descripcion,
                prioridad,
                fecha_creacion,
                fecha_vencimiento,
                id_proyecto,
                id_categoria,
                id_estatus,
                categorias!inner(nombre),
                estatus!inner(nombre)
            ''').eq('id_tarea', tarea_id).execute()
            
            if resultado_actualizada.data:
                tarea_actualizada = resultado_actualizada.data[0]
                return jsonify({
                    'mensaje': 'Tarea actualizada exitosamente',
                    'tarea': {
                        'id_tarea': tarea_actualizada['id_tarea'],
                        'titulo': tarea_actualizada['titulo'],
                        'descripcion': tarea_actualizada['descripcion'],
                        'prioridad': tarea_actualizada['prioridad'],
                        'fecha_creacion': tarea_actualizada['fecha_creacion'],
                        'fecha_vencimiento': tarea_actualizada['fecha_vencimiento'],
                        'categoria': tarea_actualizada['categorias']['nombre'],
                        'estatus': tarea_actualizada['estatus']['nombre'],
                        'id_proyecto': tarea_actualizada['id_proyecto'],
                        'id_categoria': tarea_actualizada['id_categoria'],
                        'id_estatus': tarea_actualizada['id_estatus']
                    }
                }), 200
            else:
                return jsonify({'error': 'Error al obtener tarea actualizada'}), 500
        else:
            return jsonify({'error': 'Error al actualizar tarea'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# Eliminar tarea
@app.route('/tareas/<int:tarea_id>', methods=['DELETE', 'OPTIONS'])
@token_required
def eliminar_tarea(usuario_id, tarea_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "DELETE,OPTIONS")
        return response
        
    try:
        # Verificar que la tarea existe y pertenece a un proyecto del usuario
        resultado_tarea = supabase.table('tareas').select('''
            id_tarea,
            proyectos!inner(id_usuario_creador)
        ''').eq('id_tarea', tarea_id).execute()
        
        if not resultado_tarea.data:
            return jsonify({'error': 'Tarea no encontrada'}), 404
        
        tarea = resultado_tarea.data[0]
        
        if tarea['proyectos']['id_usuario_creador'] != usuario_id:
            return jsonify({'error': 'No autorizado'}), 403
        
        # Eliminar tarea
        resultado = supabase.table('tareas').delete().eq('id_tarea', tarea_id).execute()
        
        if resultado.data:
            return jsonify({
                'mensaje': 'Tarea eliminada exitosamente'
            }), 200
        else:
            return jsonify({'error': 'Error al eliminar tarea'}), 500
            
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ========================== RUTA DEL TABLERO ==========================

# Obtener tablero completo de un proyecto
@app.route('/proyectos/<int:proyecto_id>/tablero', methods=['GET', 'OPTIONS'])
@token_required
def obtener_tablero(usuario_id, proyecto_id):
    if request.method == 'OPTIONS':
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,OPTIONS")
        return response
        
    try:
        # Verificar que el proyecto existe y pertenece al usuario
        resultado_proyecto = supabase.table('proyectos').select('*').eq('id_proyecto', proyecto_id).eq('id_usuario_creador', usuario_id).execute()
        
        if not resultado_proyecto.data:
            return jsonify({'error': 'Proyecto no encontrado o no autorizado'}), 404
        
        proyecto = resultado_proyecto.data[0]
        
        # Obtener todas las tareas del proyecto con joins
        resultado_tareas = supabase.table('tareas').select('''
            id_tarea,
            titulo,
            descripcion,
            prioridad,
            fecha_creacion,
            fecha_vencimiento,
            id_proyecto,
            id_categoria,
            id_estatus,
            categorias!inner(nombre),
            estatus!inner(nombre)
        ''').eq('id_proyecto', proyecto_id).execute()
        
        # Organizar tareas por categoría (estatus)
        categorias_tablero = {
            'To Do': [],
            'In Progress': [],
            'Hot Fix': [],
            'Done': []
        }
        
        # Contadores para resumen
        total_tareas = 0
        por_categoria = {
            'To Do': 0,
            'In Progress': 0,
            'Hot Fix': 0,
            'Done': 0
        }
        por_prioridad = {
            '1': 0,
            '2': 0,
            '3': 0,
            '4': 0,
            '5': 0
        }
        
        if resultado_tareas.data:
            for tarea in resultado_tareas.data:
                total_tareas += 1
                
                tarea_formateada = {
                    'id_tarea': tarea['id_tarea'],
                    'titulo': tarea['titulo'],
                    'descripcion': tarea['descripcion'],
                    'prioridad': tarea['prioridad'],
                    'fecha_creacion': tarea['fecha_creacion'],
                    'fecha_vencimiento': tarea['fecha_vencimiento'],
                    'categoria': tarea['categorias']['nombre'],
                    'estatus': tarea['estatus']['nombre'],
                    'id_proyecto': tarea['id_proyecto'],
                    'id_categoria': tarea['id_categoria'],
                    'id_estatus': tarea['id_estatus']
                }
                
                estatus = tarea['estatus']['nombre']
                
                # Agregar a la categoría correspondiente
                if estatus in categorias_tablero:
                    categorias_tablero[estatus].append(tarea_formateada)
                    por_categoria[estatus] += 1
                else:
                    # Si el estatus no está en las categorías por defecto, agregarlo a "To Do"
                    categorias_tablero['To Do'].append(tarea_formateada)
                    por_categoria['To Do'] += 1
                
                # Contar por prioridad
                prioridad_str = str(tarea['prioridad'])
                if prioridad_str in por_prioridad:
                    por_prioridad[prioridad_str] += 1
        
        # Construir respuesta del tablero
        tablero = {
            'proyecto': {
                'id_proyecto': proyecto['id_proyecto'],
                'nombre': proyecto['nombre'],
                'id_grupo': proyecto['id_grupo'],
                'id_usuario_creador': proyecto['id_usuario_creador'],
                'fecha_creacion': proyecto['fecha_creacion']
            },
            'categorias': categorias_tablero,
            'resumen': {
                'total_tareas': total_tareas,
                'por_categoria': por_categoria,
                'por_prioridad': por_prioridad
            }
        }
        
        return jsonify(tablero), 200
        
    except Exception as e:
        return jsonify({'error': f'Error interno del servidor: {str(e)}'}), 500

# ========================== MANEJO DE ERRORES ==========================

# Manejo de errores mejorado
@app.errorhandler(404)
def not_found(error):
    response = jsonify({'error': 'Ruta no encontrada'})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
    return response, 404

@app.errorhandler(405)
def method_not_allowed(error):
    response = jsonify({'error': 'Método no permitido'})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
    return response, 405

@app.errorhandler(500)
def internal_error(error):
    response = jsonify({'error': 'Error interno del servidor'})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:4200")
    return response, 500

# ========================== RUTA DE SALUD ==========================

# Ruta de salud del servidor
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.utcnow().isoformat(),
        'message': 'Servidor Flask funcionando correctamente'
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)