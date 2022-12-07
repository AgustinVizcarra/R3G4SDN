from typing import List
from typing import Optional
from pydantic import BaseModel

class InputSpoofing(BaseModel):
    ip_host: str
class InputSpoofingResponse(InputSpoofing):
    realParameters : bool
    msg : str
class SpoofedHost(BaseModel):
    ip_host: str
    mac_host: str
    switch_host: str
    port_host: int
class SpoofedHostResponse():
    msg: str
    spoofedHosts: List[SpoofedHost] = [] 
    