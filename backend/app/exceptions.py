class SecurityBaseException(Exception):
    """Excepción base para el módulo de seguridad."""
    def __init__(self, detail: str):
        self.detail = detail

class ServiceError(SecurityBaseException):
    """Error en un servicio de seguridad."""
    def __init__(self, detail: str):
        super().__init__(f"Error en el servicio: {detail}")

class InvalidURLError(SecurityBaseException):
    """URL inválida o malformada."""
    def __init__(self, detail: str):
        super().__init__(f"URL inválida: {detail}")

class UserLimitExceededError(SecurityBaseException):
    """Usuario ha excedido su límite de uso."""
    def __init__(self, detail: str):
        super().__init__(f"Límite excedido: {detail}")

class ServiceUnavailableError(SecurityBaseException):
    """Servicio temporalmente no disponible."""
    def __init__(self, detail: str):
        super().__init__(f"Servicio no disponible: {detail}")
