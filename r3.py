from schemas import *
from fastapi import FastAPI
from fastapi_utils.tasks import repeat_every
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
bloqueados = []
@app.on_event('startup')
async def startup():
    print("Iniciando el servicio")
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

#Configuro la tarea asincrona
@app.on_event('startup')
@repeat_every(seconds=10,wait_first=True)
def monitoreo():
    print("****Iniciando Monitoreo****")
    #Consulto al servicio
    info=obtenerListadoActualDeHost()
    valores = []
    enOrden = False
    for value in info:
        #Añado todos los valores 
        valores.append([value['IP']['IP'],[value['MAC']['MAC'],value['switch']['DPID'],value['Puerto_SW']['Puerto_SW']]])
    #Agora en vez de recibir una ip para comparar debo comparar con todos los hosts de la lista actual 
    for host_k in hosts.keys():
        for registro in valores:
            if(registro[0]==host_k):
                #Si es que concide la IP enviada existe dentro de nuestros registros
                if(registro not in bloqueados):
                    if(len(correctivos)==0):
                        print("No se tienen correctivos registrados para la dirección "+registro[0])
                        if(registro[1][0]==hosts[host_k][0] and registro[1][1]==hosts[host_k][1] and int(registro[1][2])==hosts[host_k][2]):
                            #Esto esta bien!
                            enOrden = True
                        else:
                            print("Se tiene un caso de IP Spoofing para la dirección "+registro[0])
                            correctivos.append(registro)
                            enOrden = False
                            #Se ha detectado IP spoofing
                    else:
                        if(registro[1][0]==hosts[host_k][0] and registro[1][1]==hosts[host_k][1] and int(registro[1][2])==hosts[host_k][2]):
                            #Esto esta bien!
                            print("No se tienen correctivos registrados para la dirección "+registro[0])
                            enOrden=True
                        else:
                            #No hago nada porque este IPSpoof ya fue encontrado
                            if(registro not in correctivos):
                                print("Se tiene un caso de IP Spoofing para la dirección "+registro[0])
                                enOrden=False
                                correctivos.append(registro)
                            else:
                                print("Esta dirección "+registro[0]+" fue bloqueada, se procederá almacenar en la lista de bloqueados")
                                #Elimino el valor de los registros para que ya no fastidie
                                correctivos.remove(registro)
                                bloqueados.append(registro)
                                enOrden=True
                else:
                    print("Esta dirección "+registro[0]+" ya se encuentra almacenada como bloqueada. Todo en orden")
                    
    if(not enOrden):
        if(len(correctivos) != 0):
            #Quiere decir que tenemos medidas que tomar!
            for registro in correctivos:
                if(registro not in bloqueados):
                    """"
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
                    """
                    print("Direccion IP Spoofing bloqueada correctamente en el switch "+registro[1][1]+" por el puerto "+str(registro[1][2]))
        else:
            print("No se tienen correctivos...Todo en orden")
    print("***Finalizando Monitoreo***")
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
    repetido = False
    for host_k in hosts.keys():
        for registro in valores:
            if(registro[0]==host_k):
                #Si es que concide la IP enviada existe dentro de nuestros registros
                findHostIP = True
                if(registro not in bloqueados):
                    if(len(correctivos)==0):
                        print("No se tienen correctivos registrados!")
                        if(registro[1][0]==hosts[host_k][0] and registro[1][1]==hosts[host_k][1] and int(registro[1][2])==hosts[host_k][2]):
                            #Esto esta bien!
                            enOrden=True
                        else:
                            #F 
                            enOrden=False
                            correctivos.append(registro)
                            #Se ha detectado IP spoofing
                    else:
                        print("Se tienen correctivos registrados")
                        if(registro[1][0]==hosts[host_k][0] and registro[1][1]==hosts[host_k][1] and int(registro[1][2])==hosts[host_k][2]):
                            #Esto esta bien!
                            enOrden=True
                        else:
                            #No hago nada porque este IPSpoof ya fue encontrado
                            
                                if(not(registro in correctivos)):
                                    enOrden=False
                                    repetido = False
                                    correctivos.append(registro)
                                else:
                                    print("Esta dirección IP ya fue bloqueada!")
                                    #Elimino el valor de los registros para que ya no fastidie
                                    correctivos.remove(registro)
                                    bloqueados.append(registro)
                                    repetido = True
                                    enOrden=True
                else:
                    enOrden = True
                    print("Esta dirección ya se encuentra almacenada como bloqueada")
                            
    if(findHostIP):
        if(enOrden):
            return InputSpoofingResponse(ip_host=host.ip_host,realParameters=True,msg="El usuario cuenta con credenciales válidas!")
        else:
            #Se toman las medidas correctivas(Bloqueo de la IP/MAC)
            if(not repetido):
                for registroIpspoof in correctivos:
                    """"
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
                    """
                    print("Direccion IP Spoofing bloqueada correctamente en el switch "+registroIpspoof[1][1]+" por el puerto "+str(registroIpspoof[1][2]))
                return InputSpoofingResponse(ip_host=host.ip_host,realParameters=False,msg="Se ha detectado falsificación de credenciales")
            else:
                print("Se detecto una IP Spoofing que ya fue bloqueada todo en orden!")
    else:
        return InputSpoofingResponse(ip_host=host.ip_host,realParameters=False,msg="No se ha encontrado la dirección IP enviada!")
@app.get("/R3/SpoofedHosts")
async def getSpoofedHosts():
    if(len(bloqueados)==0):
        return {"msg" : "No se tienen host con IP Spoofing dentro de la red",
                "bloqueados" : False}   
    else:
        lista = []
        for host in bloqueados:
            aux={}
            aux["ip_host"]=host[0]
            aux["mac_host"]=host[1][0]
            aux["switch_host"]=host[1][1]
            aux["port_host"]=host[1][2]
            lista.append(aux)
        return {"msg" : "Se han encontrado los siguientes hosts con IP Spoofing",
                "bloqueados" : True,
                "spoofedHosts": lista}   