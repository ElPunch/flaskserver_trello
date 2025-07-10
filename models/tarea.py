from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Tarea(db.Model):
    __tablename__ = 'tareas'
    id_tarea = db.Column(db.Integer, primary_key=True)
    id_proyecto = db.Column(db.Integer, db.ForeignKey('proyectos.id_proyecto'), nullable=False)
    id_categoria = db.Column(db.Integer, db.ForeignKey('categorias.id_categoria'), nullable=False)
    id_estatus = db.Column(db.Integer, db.ForeignKey('estatus.id_estatus'), nullable=False)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())
    fecha_vencimiento = db.Column(db.DateTime)
    prioridad = db.Column(db.Integer)