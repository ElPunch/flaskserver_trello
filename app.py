from flask import Flask 
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
app= Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:Barman203#@db.bqicuqthwrkcwchzvane.supabase.co:5432/postgres"

db.init_app(app)

class SupaUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return "¡Hola! El servidor Flask está funcionando."

with app.app_context():
    db.create_all()

# Iniciar el servidor Flask
if __name__ == '__main__':
    app.run(debug=True)