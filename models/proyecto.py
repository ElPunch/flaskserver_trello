from flask_sqlalchemy import SQLAlchemy
from . import db


db = SQLAlchemy()

class Proyecto(db.Model):
    __tablename__ = 'proyectos'
    id_proyecto = db.Column(db.Integer, primary_key=True)
    id_grupo = db.Column(db.Integer, db.ForeignKey('grupos_trabajo.id_grupo'), nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    id_usuario_creador = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())