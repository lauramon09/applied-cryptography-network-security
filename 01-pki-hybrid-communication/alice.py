# -*- coding: utf-8 -*-
"""
Created on Fri Oct 24 10:07:26 2025

@author: laura
"""
import funciones_rsa as rsa
import os
import funciones_aes as aes
from socket_class import SOCKET_SIMPLE_TCP 

#EJERCICIO 1

clave_priv_alice = rsa.cargar_RSAKey_Privada('ficheroAlicePriv.txt', "passwordA")
clave_pub_bob = rsa.cargar_RSAKey_Publica('ficheroBobPub.txt')


K1 = os.urandom(16) #array random de 16 bits

cifrado_enviado1 = rsa.cifrarRSA_OAEP(K1, clave_pub_bob) #cifro el array
firma_enviada1 = rsa.firmarRSA_PSS(K1, clave_priv_alice) #firma alice


#creo el socket CLIENTE
socket_cliente = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket_cliente.conectar() #me conecto a un servidor

socket_cliente.enviar(cifrado_enviado1) #envio los datos 
socket_cliente.enviar(firma_enviada1) #envio la firma sobre el hash del texto


#EJERCICIO 2 

# - Alice recibe un mensaje de bob

nonce_b = socket_cliente.recibir() #recibo nonce
mecanismo_descifrado = aes.iniciarAES_CTR_descifrado(K1, nonce_b) #creo el mecanismo para descifrar el mensaje

datos_recibidos1 = socket_cliente.recibir() #recibo datos
firma_recibida1 = socket_cliente.recibir() #recibo firma

mensaje_recibido = aes.descifrarAES_CTR(mecanismo_descifrado, datos_recibidos1) #descifro el mensaje recibido

valido1 = rsa.comprobarRSA_PSS(mensaje_recibido, firma_recibida1, clave_pub_bob) #comprobamos que la firma coincide con el hash
if valido1:
    print("La firma es valida, K1 no fue alterado")
else: 
    print("El mensaje fue alterado")
    socket_cliente.cerrar()
    exit()
print("Mensaje descifrado: ", mensaje_recibido.decode())


# -Alice manda un mensaje a bob.

mensaje_enviado = "Hola Bob".encode('utf-8') #mensaje

mecanismo_cifrar, nonce_a = aes.iniciarAES_CTR_cifrado(K1) #mecanismo para cifrar, y nonce

socket_cliente.enviar(nonce_a) # envio el nonce

cifrado_enviado2 = aes.cifrarAES_CTR(mecanismo_cifrar, mensaje_enviado) #cifro el mensaje
firma_enviado2 = rsa.firmarRSA_PSS(mensaje_enviado, clave_priv_alice) #firmo con la clave privada de alice

socket_cliente.enviar(cifrado_enviado2) #envio mensaje
socket_cliente.enviar(firma_enviado2) #envio firma

socket_cliente.cerrar() #cierro comunicación