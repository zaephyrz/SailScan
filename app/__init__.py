from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from app.config import Config
import os

db = SQLAlchemy()
migrate = Migrate()
cors = CORS()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    cors.init_app(app)
    
    # Register blueprints
    from app.routes.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.routes.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    from app.routes.virustotal import bp as vt_bp
    app.register_blueprint(vt_bp, url_prefix='/api/virustotal')
    
    # Only register Frida blueprint if the module exists
    try:
        from app.routes.frida import bp as frida_bp
        app.register_blueprint(frida_bp, url_prefix='/api/frida')
    except ImportError:
        print("Note: Frida routes not registered - module may not exist")
    
    return app

# Import models AFTER creating app to avoid circular imports
from app import models