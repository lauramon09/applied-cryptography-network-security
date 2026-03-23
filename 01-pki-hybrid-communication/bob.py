# -*- coding: utf-8 -*-
"""
Created on Fri Oct 24 19:55:27 2025

@author: laura
"""
#SERVIDOR SE INICIA PRIMERO
import funciones_rsa as rsa
import funciones_aes as aes
import os
from socket_class import SOCKET_SIMPLE_TCP

#EJERCICIO 1

clave_priv_bob = rsa.cargar_RSAKey_Privada('ficheroBobPriv.txt', "passwordB")
clave_pub_alice = rsa.cargar_RSAKey_Publica('ficheroAlicePub.txt')

#creo el socket SERVIDOR
socket_servidor = SOCKET_SIMPLE_TCP('127.0.0.1', 5552) 
socket_servidor.escuchar() #socket escucha

datos_recibidos1 = socket_servidor.recibir() #socket recibe datos
firma_recibida1 = socket_servidor.recibir() #socket recibe firma

K1 = rsa.descifrarRSA_OAEP(datos_recibidos1, clave_priv_bob)
print("K1 descifrado: ", K1)

valido1 = rsa.comprobarRSA_PSS(K1, firma_recibida1, clave_pub_alice) #comprobamos que la firma coincide con el hash

if valido1:
    print("La firma es valida, K1 no fue alterado")
else: 
    print("El mensaje fue alterado")
    socket_servidor.cerrar()
    exit()


#EJERCICIO 2

# -Bob envia un mensaje a Alice

mensaje_enviado1 = "Hola Alice".encode('utf-8') #mesaje
mecanismo_cifrar, nonce_b= aes.iniciarAES_CTR_cifrado(K1) #creo el mecanismo para cifrar y el nonce

socket_servidor.enviar(nonce_b) #envio el nonce

cifrado = aes.cifrarAES_CTR(mecanismo_cifrar, mensaje_enviado1) #cifro el mensaje
firma = rsa.firmarRSA_PSS(mensaje_enviado1, clave_priv_bob) #firmo con la clave privada de bob


socket_servidor.enviar(cifrado) #envio mensaje cifrado
socket_servidor.enviar(firma) #envio firma

# -Bob recibe un mensaje de Alice

nonce_a = socket_servidor.recibir() #recibe el nonce
mecanismo_descifrado = aes.iniciarAES_CTR_descifrado(K1, nonce_a) #creo el mecanismo para descifrar usando el nonce

datos_recibidos2 = socket_servidor.recibir() #recibo el mensaje
firma_recibida2 = socket_servidor.recibir() #recibo la firma


mensaje = aes.descifrarAES_CTR(mecanismo_descifrado, datos_recibidos2) #descifro el mensaje
valido2 = rsa.comprobarRSA_PSS(mensaje, firma_recibida2, clave_pub_alice) #comprobamos que la firma coincide con el hash
if valido2:
    print("La firma es valida, K1 no fue alterado")
else: 
    print("El mensaje fue alterado")
    socket_servidor.cerrar()
    exit()
    
print("Mensaje descifrado: ", mensaje.decode())

socket_servidor.cerrar() #cierro conexión
