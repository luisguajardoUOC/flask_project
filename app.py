from flask import Flask
from flask_cors import CORS
from routes import auth_bp, filter_bp, history_bp, others_bp, proxy_bp

app = Flask(__name__)
CORS(app)

# Registrar blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(filter_bp, url_prefix='/api/filter')
app.register_blueprint(history_bp, url_prefix='/api/history')
app.register_blueprint(others_bp, url_prefix='/api/other')
app.register_blueprint(proxy_bp, url_prefix='/api/proxy')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
