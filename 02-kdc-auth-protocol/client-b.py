

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT) #EN GCM INICIO PARA CIFRAR CADA VEZ QUE CIFRO ALGO
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)




# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# (A realizar por el alumno/a...)
cifrado = socket.recibir()
mac = socket.recibir()
Nb = socket.recibir()

json_recibido = funciones_aes.descifrarAES_GCM(KBT, Nb, cifrado, mac) #EN GCM NO HACE FALTA INICIAR PARA DESCIFRAR

json_ET = json_recibido.decode("utf-8" ,"ignore")
print("T-> B (descifrado): " + json_ET)
msg_ET = json.loads(json_ET)
# Extraigo el contenido
K1_hex, K2_hex, na_hex = msg_ET
K1 = bytearray.fromhex(K1_hex)
K2 = bytearray.fromhex(K2_hex)
nb = bytearray.fromhex(na_hex)

if nb != t_n_origen : print("No coincide el nonce")
else: print("Nonce verificado con exito")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 






# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# (A realizar por el alumno/a...)
print("Esperando a Alice...")
socket_alice = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_alice.escuchar()

nonce_A_ini = socket_alice.recibir()
Nombre = socket_alice.recibir()
m = socket_alice.recibir()

aes_des = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_A_ini) #EN CTR inicio una vez y lo puedo usar en todas las conexiones A->B
Nom_descifrado = funciones_aes.descifrarAES_CTR(aes_des, Nombre)

h = HMAC.new(K2, Nom_descifrado, digestmod=SHA256)
mac = h.digest()

print("A -> B (descifrado): " + Nom_descifrado.decode())

if (mac == m): print("Mensaje correcto") 
else: print("Mensaje incorrecto")






# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

# (A realizar por el alumno/a...)
aes_ci, nonce_B_ini = funciones_aes.iniciarAES_CTR_cifrado(K1) #EN CTR inicio una vez y lo puedo usar en todas las conexiones B -> A

Apellido = funciones_aes.cifrarAES_CTR(aes_ci, "Mondejar".encode("utf-8"))
h = HMAC.new(K2, "Mondejar".encode("utf-8"), digestmod=SHA256)
m = h.digest()

print("B -> A (descifrado): " + "Mondejar")

socket_alice.enviar(nonce_B_ini) #EN CTR se envia el nonce junto con el primer mensaje de esa dirección, no se vuelve a enviar en los pasos siguientes con la misma dirección
socket_alice.enviar(Apellido)
socket_alice.enviar(m)





# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

# (A realizar por el alumno/a...)
fin = socket_alice.recibir()
m = socket_alice.recibir()

fin_descifrado = funciones_aes.descifrarAES_CTR(aes_des, fin) #REUSO EL aes_des
h = HMAC.new(K2, fin_descifrado, digestmod=SHA256)
mac = h.digest()

print("A -> B (descifrado): " + fin_descifrado.decode())

if (m == mac): print("Mensaje correcto") 
else : print("mensaje incorrecto")

socket_alice.cerrar()