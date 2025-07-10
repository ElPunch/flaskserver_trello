from flask_sqlalchemy import SQLAlchemy
from . import db


db = SQLAlchemy()

class Categoria(db.Model):
    __tablename__ = 'categorias'
    id_categoria = db.Column(db.Integer, primary_key=True)
    id_proyecto = db.Column(db.Integer, db.ForeignKey('proyectos.id_proyecto'), nullable=False)
    nombre = db.Column(db.String(50), nullable=False)