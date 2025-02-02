from app.models.user import User, UserRole
from app.models.url_check import URLCheck

# Esto asegura que todas las relaciones estén disponibles
__all__ = ['User', 'UserRole', 'URLCheck']
