
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# (A realizar por el alumno/a...)
# Lee clave KAT
KAT = open("KAT.bin", "rb").read()

print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()



# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# (A realizar por el alumno/a...)
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT) #EN GCM INICIO PARA CIFRAR CADA VEZ QUE CIFRO ALGO
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)




# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# (A realizar por el alumno/a...)
cifrado = socket.recibir()
mac = socket.recibir()
Na = socket.recibir()

json_recibido = funciones_aes.descifrarAES_GCM(KAT, Na, cifrado, mac) #EN GCM NO HACE FALTA INICIAR PARA DESCIFRAR

json_ET = json_recibido.decode("utf-8" ,"ignore")
print("T-> A (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)
# Extraigo el contenido
K1_hex, K2_hex, na_hex = msg_ET
K1 = bytearray.fromhex(K1_hex)
K2 = bytearray.fromhex(K2_hex)
na = bytearray.fromhex(na_hex)

if na != t_n_origen : print("No coincide el nonce")
else: print("Nonce verificado con exito")

socket.cerrar()



# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################
print("Creando conexion con B...")
socket_bob = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_bob.conectar()

# (A realizar por el alumno/a...)
aes_cifrado, nonce_A_ini = funciones_aes.iniciarAES_CTR_cifrado(K1) #EN CTR inicio una vez y lo puedo usar en todas las conexiones A->B
Mensaje = funciones_aes.cifrarAES_CTR(aes_cifrado, "Laura".encode("utf-8"))
h = HMAC.new(K2, "Laura".encode("utf-8"), digestmod=SHA256)
mac = h.digest()
print("A -> B (descifrado): " + "Laura")

socket_bob.enviar(nonce_A_ini) #EN CTR se envia el nonce junto con el primer mensaje de esa dirección, no se vuelve a enviar en los pasos siguientes con la misma dirección
socket_bob.enviar(Mensaje)
socket_bob.enviar(mac)




# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)

nonce_B_ini = socket_bob.recibir()
Apellido = socket_bob.recibir()
m = socket_bob.recibir()

aes_descifrar = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_B_ini) #EN CTR inicio una vez y lo puedo usar en todas las conexiones B -> A
Apellido_descifrado = funciones_aes.descifrarAES_CTR(aes_descifrar, Apellido)
h = HMAC.new(K2, Apellido_descifrado, digestmod=SHA256)
mac= h.digest()

print("B -> A (descifrado): " + Apellido_descifrado.decode())

if(m == mac): print("Mensaje correcto") 
else: print("Mensaje incorrecto")




# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
# (A realizar por el alumno/a...)
fin = funciones_aes.cifrarAES_CTR(aes_cifrado, "END".encode("utf-8")) #REUSO EL aes_cifrado
h = HMAC.new(K2, "END".encode("utf-8"), digestmod=SHA256)
m = h.digest()

print("A -> B (descifrado): " + "END")

socket_bob.enviar(fin)
socket_bob.enviar(m)

socket_bob.cerrar()