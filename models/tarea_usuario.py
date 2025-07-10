from flask_sqlalchemy import SQLAlchemy
from . import db


db = SQLAlchemy()

class TareaUsuario(db.Model):
    __tablename__ = 'tareas_usuarios'
    id_tarea = db.Column(db.Integer, db.ForeignKey('tareas.id_tarea'), primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), primary_key=True)