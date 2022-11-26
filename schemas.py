from pydantic import BaseModel

class InputSpoofing(BaseModel):
    ip_host: str
class InputSpoofingResponse(InputSpoofing):
    realParameters : bool
    msg : str
    
    