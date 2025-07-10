from flask_sqlalchemy import SQLAlchemy
from . import db


db = SQLAlchemy()

class Estatus(db.Model):
    __tablename__ = 'estatus'
    id_estatus = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)