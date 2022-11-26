from schemas import *
from fastapi import FastAPI
import requests

def obtenerListadoActualDeHost():
    api = "http://10.20.12.48:8080/wm/firewall/R1/conectados/json"
    response = requests.get(api)
    data = response.json()
    return data
def addflow(flow):
    api = "http://10.20.12.48:8080/wm/staticflowpusher/json"
    response = requests.post(api, json=flow)
    if(response.status_code == 200):
        pass
    else:
        print("Ha ocurrido un error en la flow entry añadida")     
app = FastAPI(title = "Servidor del requerimiento 3 del grupo 4 de SDN",
              description = "Corriendo servidor!",
              version = "1.0.1")
#Variables global
global correctivos
correctivos = []
@app.on_event('startup')
async def startup():
    api = "http://10.20.12.48:8080/wm/device/"
    response = requests.get(api)
    data = response.json()
    #Obtengo todos los host conectados:
    global hosts
    hosts = {}
    for value in data:
        if(len(value['ipv4'])!=0):
            host = value['ipv4'][0]
            try:
                attachment_point = [value['mac'][0],value['attachmentPoint'][1]['switchDPID'],value['attachmentPoint'][1]['port']]
            except:
                attachment_point = [value['mac'][0],value['attachmentPoint'][0]['switchDPID'],value['attachmentPoint'][0]['port']]
            hosts[host]=attachment_point    
    print(len(hosts))
        
#En caso llegue un request con una dirección ip
@app.post("/R3/spoofing")
async def validarSpoofing(host: InputSpoofing):
    info=obtenerListadoActualDeHost()
    valores = []
    for value in info:
        if value['IP']['IP'] == host.ip_host:
            #Registro todos los valores así se repitan más de una vez
            valores.append([host.ip_host,[value['MAC']['MAC'],value['switch']['DPID'],value['Puerto_SW']['Puerto_SW']]])
    enOrden = False
    findHostIP = False
    for host_k in hosts.keys():
        for registro in valores:
            if(registro[0]==host_k):
                #Si es que concide la IP enviada existe dentro de nuestros registros
                findHostIP = True
                if(registro[1][0]==hosts[host_k][0] and registro[1][1]==hosts[host_k][1] and int(registro[1][2])==hosts[host_k][2]):
                    #Esto esta bien!
                    enOrden=True
                else:
                    #F 
                    correctivos.append(registro)
                    #Se ha detectado IP spoofing
    if(findHostIP):
        if(enOrden):
            return InputSpoofingResponse(ip_host=host.ip_host,realParameters=True,msg="El usuario cuenta con credenciales válidas!")
        else:
            #Se toman las medidas correctivas(Bloqueo de la IP/MAC)
            for registroIpspoof in correctivos:
                flowBlockSpoof ={
                    "name" : "blockIPspoof "+str(registroIpspoof[0])+"-"+str(registroIpspoof[1][2]),
                    "switch" : registroIpspoof[1][1],
                    "eth_type" : "0x0800",
                    "eth_src" : registroIpspoof[1][0],
                    "ipv4_src" : registroIpspoof[0],
                    "in_port" : str(registroIpspoof[1][2]),
                    "active" : "true",
                    "actions" : "output="
                }
                addflow(flowBlockSpoof)
                print("Direccion IP Spoofin bloqueada correctamente en el switch"+registroIpspoof[1][1]+" por el puerto "+str(registroIpspoof[1][2]))
            return InputSpoofingResponse(ip_host=host.ip_host,realParameters=False,msg="Se ha detectado falsificación de credenciales")
    else:
        return InputSpoofingResponse(ip_host=host.ip_host,realParameters=False,msg="No se ha encontrado la dirección IP enviada!")
        
