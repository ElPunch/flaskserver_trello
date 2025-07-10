from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from config import Config
from routes.usuario import usuarios_bp
from routes.grupos import grupos_bp
from routes.proyectos import proyectos_bp
from routes.categorias import categorias_bp
from routes.estatus import estatus_bp
from routes.tareas import tareas_bp

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Registrar blueprints
app.register_blueprint(usuarios_bp)
app.register_blueprint(grupos_bp)
app.register_blueprint(proyectos_bp)
app.register_blueprint(categorias_bp)
app.register_blueprint(estatus_bp)
app.register_blueprint(tareas_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)