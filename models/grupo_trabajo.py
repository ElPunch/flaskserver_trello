from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class GrupoTrabajo(db.Model):
    __tablename__ = 'grupos_trabajo'
    id_grupo = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    id_usuario_creador = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())