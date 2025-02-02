from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy.ext.asyncio import async_sessionmaker
from app.core.config import settings

# Crear el motor de base de datos
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
)

# Configurar la sesión
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Crear la clase base para los modelos
Base = declarative_base()

# Función para obtener la sesión de BD
async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
