#!/bin/bash
#
# @Autor: Agustín Walabonso Lara Romero 
# @Descripción: Instalación del proyecto
#

#################################################
# Actualización de los paquetes                 #
#################################################
sudo apt-get update -y

#################################################
# Instalación de MySQL                          #
#################################################
sudo apt-get install mysql-server -y
if [ $? = 0 ] 
then
	echo -e "Instalacion mysql-server: \e[92mYES\e[0m"
else
	echo -e "Instalacion mysql-server: \e[0;31mERROR\e[0m"
	exit 0
fi

#################################################
# Creación de las tablas de la base de datos    #
#################################################
USUARIO_BASE_DATOS='wala'
BBDD=tfg
CREAR_TABLAS=crear_tablas.sql
mysql -u wala -p$USUARIO_BASE_DATOS $BBDD < $CREAR_TABLAS 2>/dev/null
if [ $? = 0 ] 
then
	echo -e "Creacion tablas de BBDD: \e[92mYES\e[0m"
else
	echo -e "Creacion tablas de BBDD: \e[0;31mERROR\e[0m"
	exit 0
fi

#################################################
# Instalación de nprobe                         #
#################################################
sudo apt-get install nprobe -y
if [ $? = 0 ] 
then
	echo -e "Instalacion nprobe: \e[92mYES\e[0m"
else
	echo -e "Instalacion nprobe: \e[0;31mERROR\e[0m"
	exit 0
fi
