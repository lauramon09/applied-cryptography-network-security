# -*- coding: utf-8 -*-
"""
Created on Fri Oct 24 09:44:57 2025

@author: laura
"""
import funciones_rsa as rsa

#pip install pycryptodome

#EJERCICIO 1

clave_priv_alice = rsa.crear_RSAKey() #genero la clave privada con el método de RSA
clave_pub_alice = clave_priv_alice.publickey() #A partir de la privada genero la publica
rsa.guardar_RSAKey_Privada('ficheroAlicePriv.txt', clave_priv_alice, "passwordA") #guardo la clave privada en un fichero, y con la contraseña correspondiente para exportarla.
rsa.guardar_RSAKey_Publica('ficheroAlicePub.txt', clave_pub_alice) #guardo la clave publica en otro fichero, no hace falta contraseña

#Lo mismo con bob
clave_priv_bob= rsa.crear_RSAKey() 
clave_pub_bob = clave_priv_bob.publickey()
rsa.guardar_RSAKey_Privada('ficheroBobPriv.txt', clave_priv_bob, "passwordB")
rsa.guardar_RSAKey_Publica('ficheroBobPub.txt', clave_pub_bob)
