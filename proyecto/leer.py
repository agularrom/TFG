"""

  Importaciones de Librerias necesarias

"""
import pandas as pd
import numpy as np
from datetime import datetime, date, time, timedelta
import os
import sys
import json
import mysql.connector
import math
import shutil
import ConfigParser
import ipcalc as ipc

"""

  Parametros obtenidos por el fichero de configuracion
  ubicado en configuraciones/configuraciones.conf

"""
pd.options.mode.chained_assignment = None  # default='warn'
config = ConfigParser.ConfigParser()
config.read('configuraciones/configuraciones.conf')
fecha = str(config.get('FECHA', 'fecha'))
usuario = str(config.get('BBDD', 'user'))
password = str(config.get('BBDD', 'password'))
host = str(config.get('BBDD', 'host'))
database = str(config.get('BBDD', 'database'))
clean = str(config.get('BBDD', 'clean'))
capacidad_ventana = int(config.get('ESTADISTICAS', 'capacidad_ventana'))
coeficiente_error = int(config.get('ESTADISTICAS', 'coeficiente_error'))
alpha = float(config.get('ESTADISTICAS', 'alpha'))
aprendizaje = str(config.get('ESTADISTICAS', 'aprendizaje'))
eliminar_anomalos = str(config.get('ESTADISTICAS', 'eliminar_anomalos'))
alertas_nuevas = str(config.get('ESTADISTICAS', 'alertas_nuevas'))
network = str(config.get('TRATAMIENTO', 'network'))

def calculaFecha(flow_start):
	"""

  	  Funcion que calcula y devuelve la fecha y hora a la que 
  	  se ha realizado una captura de flujo IP

  	  Parametros:

		    flow_start -- milisegundos transcurridos desde la fecha 1 de julio de 1970
		    			  a las 01:02:03.123456.
		    			  (Este parametro es sumado a la fecha mencionada anteriormente
		    			  y asi poder calcular la fecha y hora de la captura realizada)

	"""
	dia_wireshark = datetime.strptime('1970-01-01 01:02:03.123456', '%Y-%m-%d %H:%M:%S.%f')
	dia_wireshark = dia_wireshark + timedelta(milliseconds=flow_start)
	return str(dia_wireshark.strftime('%Y%m%d%H'))

def calcula_var_exp(alpha, varianza):
	"""

  	  Funcion que calcula y devuelve la varianza exponencial

  	  Parametros:

		    alpha    -- Factor de suavizado para el calculo de la varianza

		    varianza -- Valor de la varianza sobre la que se realiza el 
						siguiente calculo: (varianza_exp = (alpha / (2 - alpha)) * varianza)

	"""
	varianza_exp = (alpha / (2 - alpha)) * varianza
	return varianza_exp 

def calcula_ema(alpha, lista):
	"""

  	  Funcion que calcula y devuelve la esperanza exponencial

  	  Parametros:

		    alpha -- Factor de suavizado para el calculo de 
		             la esperanza exponencial

		    lista -- Conjunto de valores sobre la que se realiza 
		             el siguiente calculo de la esperanza exponencial:
		             (alpha * lista[i] + (1 - alpha) * EXP[i - 1])
												
	"""
	ema = []
	if(len(lista) > 0):
		ema.append(lista[0])
	for i in range(1, len(lista)):
		ema.append(alpha * lista[i] + (1 - alpha) * ema[i - 1])
	return ema[len(ema) - 1]

def insertarBaseDatosIndicadores(carpeta, tabla, colum_name):
	"""

  	  Funcion que inserta valores en base de datos 
  	  de los distintos indicadores

  	  Parametros:

		    carpeta --    Ubicacion de la carpeta donde se encuentra el 
		                  indicador que se desea insertar en base de datos

		    tabla --      Nombre de la tabla donde se desea insertar
		    			  los valores del indicador

 		    colum_name -- Nombre de la columna de la tabla donde se desea 
 		                  insertar los valores del indicador
												
	"""

	if len(os.listdir(carpeta)) > 1:
		cnx = mysql.connector.connect(user = usuario, password = password, host = host, database = database)
		cursor = cnx.cursor()
		ficheroIP_aux = carpeta + '/' + os.listdir(carpeta)[0]

		if 'FicherosProcesados' in ficheroIP_aux:
			ficheroIP_aux = carpeta + '/' + os.listdir(carpeta)[1]
		ficheroIP = open(ficheroIP_aux,'r')
		lines = ficheroIP.readlines()

		if(lines[0] != 'NO SE ENCUENTRA LA IP'):
			fecha_aux = lines[0]
			fecha = fecha_aux[0:8]
			hora = fecha_aux[8:]
			ip = lines[1].rstrip('\n')
			i=0
			ayuda_indicador = ''

			if tabla == 'puertos_destino':
				ayuda_indicador = 'D '		
			elif tabla == 'puertos_origen':
				ayuda_indicador = 'O '
			elif tabla == 'icmp_destino':
				ayuda_indicador = 'I '
			for linea in lines:
				if(i >= 2):
					linea_aux = linea.split(' ')
					indicador = ayuda_indicador + linea_aux[0]
					num_veces = linea_aux[len(linea_aux) - 1]
					cursor.execute('INSERT INTO ' + tabla + ' VALUES ("' + ip + '", "' + indicador + '", ' + num_veces + ', ' + fecha + ', ' + hora + ')')
					cnx.commit()									
				i += 1
			calcularIndicadores(ip, tabla, colum_name, hora, fecha)
		ficheroIP.close()
		os.system('cat ' + ficheroIP_aux + ' >> ' + carpeta + '/FicherosProcesados/Historico')
		os.system('rm ' + ficheroIP_aux)
		cursor.close()
		cnx.close()

def generarAlerta(ip, nuevoIndicador, indicador, fecha, hora, media, varianza, media_anterior, varianza_anterior, nuevo_valor, media_exp, media_exp_anterior, varianza_exp, varianza_exp_anterior):
	"""

  	  Funcion que evalua el valor de un indicador a traves de dos metodos, la media movil exponencial 
  	  y la media movil.
  	  En caso de que el sistema no este en modo aprendizaje y el valor exceda los estandares predefinido
  	  se insertara una alerta en la base de datos de la tabla de nombre logs.

  	  Parametros:

		    ip --	Direccion IP correspondiente al indicador

		    nuevoIndicador --	Bandera que vale uno cuando aun no existe ningun resgistro para el indicador

 		    indicador --	Nombre del indicador

		    fecha --	Fecha en formato YYYYMMDD que corresponde al indicador

		    hora --	Hora en formato HH que corresponde al indicador

 		    media -- Calculo de la media del indicador 
 		    		 incluyendo la ultima muestra

 		    varianza --	Calculo de la varianza del indicador 
 		    			incluyendo la ultima muestra

		    media_anterior --	Calculo de la media del indicador 
		    					NO incluyendo la ultima muestra

 		    varianza_anterior --	Calculo de la varianza del indicador 
 		    						NO incluyendo la ultima muestra

		    nuevo_valor --	Valor de la ultima muestra del indicador

		    media_exp --  Calculo de la media exponencial movil del indicador 
 		    		 	  incluyendo la ultima muestra

 		    media_exp_anterior -- Calculo de la media exponencial movil del indicador 
 		    		 	  		  NO incluyendo la ultima muestra		                  

		    varianza_exp --	Calculo de la varianza exponencial movil del indicador 
 		    		 	  	incluyendo la ultima muestra

 		    varianza_exp_anterior -- Calculo de la varianza exponencial movil del indicador 
 		    		 	  			 NO incluyendo la ultima muestra
												
	"""

	rellenar = True
	cnx = mysql.connector.connect(user = usuario, password = password, host = host, database = database)
	cursor = cnx.cursor()

	if media_anterior == None:
		media_anterior = media
		varianza_anterior = varianza
		media_exp_anterior = media_exp
		varianza_exp_anterior = varianza_exp

	if nuevoIndicador and aprendizaje == 'TRUE' and alertas_nuevas == 'TRUE':
		cursor.execute('INSERT INTO logs VALUES ("' + ip + '", ' + str(fecha) + ', ' + str(hora) + ', "NUEVO", "' + indicador + '", ' + str(nuevo_valor) + ')')
	else:
		error = abs(nuevo_valor - media_anterior)
		error_exp = abs(nuevo_valor - media_exp_anterior)
		if error > coeficiente_error * math.sqrt(varianza_anterior) and aprendizaje == 'FALSE':
			cursor.execute('INSERT INTO logs VALUES ("' + ip + '", ' + str(fecha) + ', ' + str(hora) + ', "ERROR", "' + indicador + '", ' + str(nuevo_valor) + ')')
			rellenar = False
		if error_exp > coeficiente_error * math.sqrt(varianza_exp_anterior) and aprendizaje == 'FALSE':
			cursor.execute('INSERT INTO logs VALUES ("' + ip + '", ' + str(fecha) + ', ' + str(hora) + ', "ERROR_EXP", "' + indicador + '", ' + str(nuevo_valor) + ')')
			rellenar = False
	cnx.commit()
	cnx.close()
	return rellenar

def rellenarBaseDatosEstadisticos(ip, indicador, hora, media, varianza, fecha, nuevo_valor, num_muestras, media_exp, varianza_exp):
	"""

  	  Funcion que rellena la tabla Estadisticos, la cual contiene todos los indicadores con
  	  los calculos estadisticos realizados.

  	  Parametros:

		    ip --	Direccion IP correspondiente al indicador

 		    indicador --	Nombre del indicador

		    hora --	Hora en formato HH que corresponde al indicador

 		    media -- Calculo de la media del indicador 
 		    		 incluyendo la ultima muestra

 		    varianza --	Calculo de la varianza del indicador 
 		    			incluyendo la ultima muestra

		    fecha --	Fecha en formato YYYYMMDD que corresponde al indicador

		    nuevo_valor --	Valor de la ultima muestra del indicador

		    num_muestras --	Numero de muestras del indicador

		    media_exp --  Calculo de la media exponencial movil del indicador 
 		    		 	  incluyendo la ultima muestra	                  

		    varianza_exp --	Calculo de la varianza exponencial movil del indicador 
 		    		 	  	incluyendo la ultima muestra

	"""
	rellenar = True
	cnx = mysql.connector.connect(user = usuario, password = password, host = host, database = database)
	cursor = cnx.cursor()
	cursor.execute('SELECT media FROM estadisticos WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND indicador = "' + indicador + '"' + ' order by fecha desc limit 1')	
	media_anterior = cursor.fetchone()
	cursor.execute('SELECT varianza FROM estadisticos WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND indicador = "' + indicador + '"' + ' order by fecha desc limit 1')	
	varianza_anterior = cursor.fetchone()
	cursor.execute('SELECT media_exp FROM estadisticos WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND indicador = "' + indicador + '"' + ' order by fecha desc limit 1')	
	media_exp_anterior = cursor.fetchone()
	cursor.execute('SELECT varianza_exp FROM estadisticos WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND indicador = "' + indicador + '"' + ' order by fecha desc limit 1')	
	varianza_exp_anterior = cursor.fetchone()	
	if media_anterior is None or varianza_anterior is None:
		generarAlerta(ip, True, indicador, fecha, hora, media, varianza, None, None, nuevo_valor, media_exp, media_exp_anterior, varianza_exp, varianza_exp_anterior)
		cursor.execute('INSERT INTO estadisticos VALUES ("' + ip + '", "' + indicador + '", ' + str(hora) + ', ' + str(media) + ', ' + str(varianza) + ', ' + str(fecha) + ' ,' + str(num_muestras) + ' ,' + str(media_exp) + ' ,' + str(varianza_exp) + ')')
	else:
		rellenar = generarAlerta(ip, False, indicador, fecha, hora, media, varianza, media_anterior[0], varianza_anterior[0], nuevo_valor, media_exp, media_exp_anterior[0], varianza_exp, varianza_exp_anterior[0])
		if rellenar :
			cursor.execute('INSERT INTO estadisticos VALUES ("' + ip + '", "' "'"+ indicador +"'" '", ' + str(hora) + ', ' + str(media) + ', ' + str(varianza) + ', ' + str(fecha) + ' ,' + str(num_muestras) + ' ,' + str(media_exp) + ' ,' + str(varianza_exp) + ')')
	cnx.commit()
	cursor.close()
	cnx.close()
	return rellenar

def calcularIndicadores(ip, tabla, indicador, hora, fecha):
	"""

  	  Funcion que extrae los datos de las tablas auxiliares para 
  	  llevar a cabo el calculo de los indicadores.

  	  Parametros:

		    ip --	Direccion IP correspondiente al indicador

		    tabla --      Nombre de la tabla donde del indicador

		    hora --	Hora en formato HH que corresponde al indicador

		    fecha --	Fecha en formato YYYYMMDD que corresponde al indicador

	"""
	eliminar_registro = False
	cnx = mysql.connector.connect(user = usuario, password = password, host = host, database = database)
	cursor = cnx.cursor()
	cursor.execute('SELECT DISTINCT ' + indicador + ' FROM ' + tabla + ' WHERE ip="' + ip + '"')
	Indicadores=cursor.fetchall()
	for indicador_aux in Indicadores:
		cursor.execute('SELECT num_veces FROM ' + tabla + ' WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND ' + indicador + ' = "' + indicador_aux[0] + '" order by fecha desc limit '+ str(capacidad_ventana) +'')	
		num_veces = cursor.fetchall()
		flat_list = [item for sublist in num_veces for item in sublist]
		cursor.execute('SELECT num_veces FROM ' + tabla + ' WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND ' + indicador + ' = "' + indicador_aux[0] + '" order by fecha desc ')	
		num_veces_exp = cursor.fetchall()
		flat_list_exp = [item for sublist in num_veces_exp for item in sublist]
		flat_list_exp.reverse()
		ema = calcula_ema(alpha, flat_list_exp)
		varianza_exp = calcula_var_exp(alpha, np.var(flat_list))
		cursor.execute('SELECT num_veces FROM ' + tabla + ' WHERE ip= "' + ip + '" AND hora=' + str(hora) + ' AND ' + indicador + ' = "' + indicador_aux[0] + '" order by fecha desc limit 1')	
		nuevo_valor = cursor.fetchone()[0]
		eliminar_registro = rellenarBaseDatosEstadisticos(ip, indicador_aux[0], hora, np.mean(flat_list), np.var(flat_list), fecha, nuevo_valor, len(flat_list), ema, varianza_exp)
		if eliminar_registro == False and aprendizaje == 'FALSE' and eliminar_anomalos == 'TRUE':
			cursor.execute('DELETE FROM ' + tabla + ' WHERE ' + indicador + '='+ "'" + indicador_aux[0] +"'" ' AND hora=' + str(hora) + ' AND fecha=' + str(fecha) + '  AND ip="' + ip + '"')

	cursor.close()
	cnx.close()

def crearCarpetaIp(carpeta, ipFiltrado, indicador):
	"""

  	  Funcion que crea dinamicamente una carpeta
  	  que contiene la informacion de un indicador

  	  Parametros:

		    carpeta --		Nombre de la carpeta

		    ipFiltrado --	Direccion IP asociado al indicador

		    indicador --	Nombre del indicador

	"""
	if (os.path.isdir( carpeta ) == False):
		os.makedirs('Indicadores/IP/' + ipFiltrado + '/' + indicador + '/FicherosProcesados')
		os.system('touch Indicadores/IP/' + ipFiltrado + '/' + indicador + '/FicherosProcesados/Historico')

def buscaLinea(palabra, fichero):
	"""

  	  Funcion que busca una palabra en un fichero
  	  y en caso de existir, devuelve el numero de linea
  	  en el que se encuentra

  	  Parametros:

		    palabra --	Palabra que se desea buscar

		    fichero --	Nombre del fichero en el que se busca la coincidencia

	"""
	linea = 0
	for line in fichero :
		if 'Destino:\t' + palabra in line or 'Origen:\t' + palabra in line:
			return linea
		linea += 1

def tratamientoIP(ipFiltrado, fichero, ficheroIP):
	"""

  	  Funcion auxiliar para la generacion de los ficheros
  	  que contienen la informacion de los indicadores

  	  Parametros:
		    
		    ipFiltrado --	Direccion IP asociada al indicador

		    carpeta --		Nombre de la carpeta

		    indicador --	Nombre del indicador

	"""
	file1 = open(fichero,'r')
	lines = file1.readlines()
	linea = buscaLinea(ipFiltrado, lines)
	if linea == None:
		return 0
	else:
		fileIP = open(ficheroIP,'wr')
		fileIP.write(fecha + '\n')
		fileIP.write(ipFiltrado + '\n')
		linea += 1
		bandera = 0
		while bandera == 0:
			if '---' not in lines[linea]:
				fileIP.write(lines[linea])
				linea += 1
			else:
				bandera = 1
		fileIP.close()
	file1.close()

def mostrarAplicaciones(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de Aplicaciones
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	Aplicaciones = df.L7_PROTO_NAME.unique()
	file = open('/home/anonymus/Escritorio/tfg/Indicadores/aplicaciones','wr')
	file.write('#######################################################\n')
	file.write('# Descripcion: Aplicaciones detectadas en el analisis #\n')
	file.write('# Fecha: '+ fecha +'                                   #\n')	
	file.write('#######################################################\n\n')
	file.write('--> Total de aplicaciones:\t'+ str(len(Aplicaciones)) +'\n\n')
	i=1
	for app in Aplicaciones:
		file.write(str(i) + '\t' + app + '\n')
		i+=1
	file.write('\n--> Analisis de aplicaciones con IP origen:\n')
	for ip in df.IPV4_SRC_ADDR.unique():
		file.write('\n------------------------------\n')
		file.write('IP Origen:\t' + ip + '\n')
		file.write(str(df[df['IPV4_SRC_ADDR'] == ip]['L7_PROTO_NAME'].value_counts()))
		file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/aplicaciones')
	os.system('sed -i "/\.\./d" Indicadores/aplicaciones')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/aplicaciones'
	ficheroIpAplicaciones = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'aplicaciones' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'aplicaciones', ipFiltrado, 'aplicaciones') 
	tratamientoIP(ipFiltrado,fichero,ficheroIpAplicaciones)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'aplicaciones', 'aplicaciones', 'aplicacion')

def mostrarDataset(df,ipFiltrado):
	df.to_csv('/home/anonymus/Escritorio/tfg/Indicadores/dataset', sep='\t', encoding='utf-8')

def mostrarIpPuertosDestino(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de Puertos destino
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/PuertosDestino','wr')
	file.write('###########################################################\n')
	file.write('# Descripcion: Puertos destinos detectados en el analisis #\n')
	file.write('# Fecha: '+ fecha +'                                       #\n')
	file.write('###########################################################\n\n')
	file.write('--> Puertos destino con el numero de veces abiertos: \n\n')
	file.write(str(df.L4_SRC_PORT.value_counts()) + '\n\n --> IP destino numero de puertos abiertos')
	for ip in df.IPV4_SRC_ADDR.unique():
		df2 = df[df.IPV4_SRC_ADDR == ip]
		puertos = df2.L4_SRC_PORT.unique()
		num_puertos = len(puertos)
		file.write('\n------------------------------')	
		file.write('\nIP Origen:\t' + ip + '\n')
		file.write('PUERTOS' + '     ' + str(num_puertos))
		file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/PuertosDestino')
	os.system('sed -i "/\.\./d" Indicadores/PuertosDestino')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/PuertosDestino'
	ficheroIpPuertosOrigen = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'PuertosDestino' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'PuertosDestino', ipFiltrado, 'PuertosDestino') 
	tratamientoIP(ipFiltrado,fichero,ficheroIpPuertosOrigen)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'PuertosDestino', 'puertos_destino', 'puerto')

def mostrarIpPuertosOrigen(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de puertos origen
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/PuertosOrigen','wr')
	file.write('#########################################################\n')
	file.write('# Descripcion: Puertos origen detectados en el analisis #\n')
	file.write('# Fecha: '+ fecha +'                                     #\n')	
	file.write('#########################################################\n\n')
	file.write('--> Puertos origen con el numero de veces abiertos: \n\n')
	file.write(str(df.L4_SRC_PORT.value_counts()) + '\n\n --> IP origen numero de puertos abiertos')
	for ip in df.IPV4_SRC_ADDR.unique():
		df2 = df[df.IPV4_SRC_ADDR == ip]
		puertos = df2.L4_SRC_PORT.unique()
		num_puertos = len(puertos)
		file.write('\n------------------------------')	
		file.write('\nIP Origen:\t' + ip + '\n')
		file.write('PUERTOS' + '     ' + str(num_puertos))
		file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/PuertosOrigen')
	os.system('sed -i "/\.\./d" Indicadores/PuertosOrigen')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/PuertosOrigen'
	ficheroIpPuertosOrigen = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'PuertosOrigen' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'PuertosOrigen', ipFiltrado, 'PuertosOrigen')
	tratamientoIP(ipFiltrado,fichero,ficheroIpPuertosOrigen)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'PuertosOrigen', 'puertos_origen', 'puerto')

def mostrarIPoIPd(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de relacion ip
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/IPorigen-destino','wr')
	file.write('#########################################################\n')
	file.write('# Descripcion: Relacion de IP origen con IP destino #\n')
	file.write('# Fecha: '+ fecha +'                                   #\n')	
	file.write('#########################################################\n\n')
	for ip in df.IPV4_SRC_ADDR.unique():
		file.write('\n------------------------------')	
		file.write('\nIP Origen:\t' + ip + '\n')
		file.write(str(df[df['IPV4_SRC_ADDR'] == ip]['IPV4_DST_ADDR'].value_counts()))
		file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/IPorigen-destino')
	os.system('sed -i "/\.\./d" Indicadores/IPorigen-destino')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/IPorigen-destino'
	ficheroIpPuertosOrigen = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'IPorigen-destino' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'IPorigen-destino', ipFiltrado, 'IPorigen-destino')
	tratamientoIP(ipFiltrado,fichero,ficheroIpPuertosOrigen)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'IPorigen-destino', 'relacion_ip', 'ip_destino')

def mostrarIPdIPo(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de relacion ip
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/IPdestino-origen','wr')
	file.write('#########################################################\n')
	file.write('# Descripcion: Relacion de IP destino con IP origen     #\n')
	file.write('# Fecha: '+ fecha +'                                     #\n')	
	file.write('#########################################################\n\n')
	for ip in df.IPV4_DST_ADDR.unique():
		file.write('\n------------------------------')	
		file.write('\nIP Destino:\t' + ip + '\n')
		file.write(str(df[df['IPV4_DST_ADDR'] == ip]['IPV4_SRC_ADDR'].value_counts()))
		file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/IPdestino-origen')
	os.system('sed -i "/\.\./d" Indicadores/IPdestino-origen')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/IPdestino-origen'
	ficheroIpPuertosOrigen = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'IPdestino-origen' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'IPdestino-origen', ipFiltrado, 'IPdestino-origen')
	tratamientoIP(ipFiltrado,fichero,ficheroIpPuertosOrigen)

def mostrarDestinoICMP(df,ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de mensajes icmp
  	  y llama a las diferentes funciones para la generacion del indicador
  	  en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/ICMP-Destino','wr')
	file.write('################################################################\n')
	file.write('# Descripcion: ICMPs con IPs origen detectados en el analisis #\n')
	file.write('# Fecha: '+ fecha +'                                            #\n')	
	file.write('################################################################\n\n')
	file.write('\n--> IP origen con ICMP:\n')
	file.write('\n------------------------------\n')
	file.write(str(df['IPV4_SRC_ADDR'][df['L7_PROTO_NAME']=='ICMP'].value_counts()))
	file.write('\n------------------------------')
	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/ICMP-Destino')
	os.system('sed -i "/\.\./d" Indicadores/ICMP-Destino')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/ICMP-Destino'
	ficheroIpPuertosOrigen = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'ICMP-Destino' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'ICMP-Destino', ipFiltrado, 'ICMP-Destino')
	tratamientoIP(ipFiltrado,fichero,ficheroIpPuertosOrigen)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'ICMP-Destino', 'icmp_destino', 'ip_destino')

def mostrarNumIpDistintas(df, ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de Aplicaciones
  	  y llama a las diferentes funciones para la generacion de numero
  	  IP distintas en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/Numero-IP','wr')
	file.write('################################################################\n')
	file.write('# Descripcion: Numero de IP distintas #\n')
	file.write('# Fecha: '+ fecha +'                                            #\n')	
	file.write('################################################################\n\n')

	for ip in df.IPV4_SRC_ADDR.unique():
		df2 = df[df.IPV4_SRC_ADDR == ip]
		IPs_destino = df2.IPV4_DST_ADDR.unique()
		num_IPs = len(IPs_destino)
		file.write('\n------------------------------\n')
		file.write('IP Origen:\t' + ip + '\n')
		file.write('DISTINTAS' + '     ' + str(num_IPs))
		file.write('\n------------------------------')

	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/Numero-IP')
	os.system('sed -i "/\.\./d" Indicadores/Numero-IP')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/Numero-IP'
	ficheroNumIP = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'Numero-IP' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'Numero-IP', ipFiltrado, 'Numero-IP')
	tratamientoIP(ipFiltrado,fichero,ficheroNumIP)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'Numero-IP', 'num_ip', 'ip_aux')

def mostrarNumApp(df, ipFiltrado):
	"""

  	  Funcion que genera el fichero del indicador de Aplicaciones
  	  y llama a las diferentes funciones para la generacion de numero
  	  aplicaciones distintas en la base de datos
  	  
  	  Parametros:
		    
		    df --	DataFrame del indicador de aplicaciones

		    ipFiltrado --	Direccion IP asociada al indicador

	"""

	file = open('/home/anonymus/Escritorio/tfg/Indicadores/Numero-APP','wr')
	file.write('################################################################\n')
	file.write('# Descripcion: Numero de APLICACIONES distintas #\n')
	file.write('# Fecha: '+ fecha +'                                            #\n')	
	file.write('################################################################\n\n')

	for ip in df.IPV4_SRC_ADDR.unique():
		df2 = df[df.IPV4_SRC_ADDR == ip]
		aplicaciones = df2.L7_PROTO_NAME.unique()
		num_app = len(aplicaciones)
		file.write('\n------------------------------\n')
		file.write('IP Origen:\t' + ip + '\n')
		file.write('APLICACIONES' + '     ' + str(num_app))
		file.write('\n------------------------------')

	file.close()
	os.system('sed -i "/dtype:/d" Indicadores/Numero-APP')
	os.system('sed -i "/\.\./d" Indicadores/Numero-APP')

	fichero = '/home/anonymus/Escritorio/tfg/Indicadores/Numero-APP'
	ficheroNumApp = '/home/anonymus/Escritorio/tfg/Indicadores/IP/' + ipFiltrado + '/'+ 'Numero-APP' + '/' + fecha
	crearCarpetaIp('Indicadores/IP/' + ipFiltrado + '/'+ 'Numero-APP', ipFiltrado, 'Numero-APP')
	tratamientoIP(ipFiltrado,fichero,ficheroNumApp)
	insertarBaseDatosIndicadores('/home/anonymus/Escritorio/tfg/Indicadores/IP/'+ ipFiltrado + '/'+ 'Numero-APP', 'num_app', 'aplicacion')

def limpiarbaseDatos():
	"""

  	  Funcion que limpia la base de datos

	"""
	cnx = mysql.connector.connect(user = usuario, password = password, host = host, database = database)
	cursor = cnx.cursor()
	cursor.execute('DELETE FROM aplicaciones;')
	cursor.execute('DELETE FROM puertos_origen;')
	cursor.execute('DELETE FROM puertos_destino;')
	cursor.execute('DELETE FROM relacion_ip;')
	cursor.execute('DELETE FROM num_ip;')
	cursor.execute('DELETE FROM num_app;')
	cursor.execute('DELETE FROM icmp_destino;')
	cursor.execute('DELETE FROM estadisticos;')
	cursor.execute('DELETE FROM logs;')
	cnx.commit()
	cnx.close()

# Lectura del fichero en bruto de IPFIX
ficheroFlujos = sys.argv[1]
df = pd.read_csv(ficheroFlujos)

#Comprobacion de rango de subred para cada IP
lista_ip_filtrado = []
for ip in df['IPV4_SRC_ADDR'].unique():
	if ip in ipc.Network(network):
		lista_ip_filtrado += [ip]

if lista_ip_filtrado:
	# Identificacion de todas las IP internas a la IP 1.1.1.1 en el campo L7_PROTO
	df['L7_PROTO'][df['IPV4_SRC_ADDR'].isin(lista_ip_filtrado)] = '1.1.1.1'
	df = df[(df.L7_PROTO == '1.1.1.1')]

# Obtencion de la fecha inicio de IPFIX
vacio = True
if len(df) > 0:
	inicio = df.FLOW_START_MILLISECONDS.unique()[0]
	vacio = False
if fecha == 'AUTO':
	fecha = calculaFecha(inicio)
dia = datetime.strptime(fecha, '%Y%m%d%H')
dia = dia.weekday()

if vacio == False:
	# En caso de que la fecha en la que se reciben datos es festivo, el sistema
	# no procesara nada
	if dia < 5:

		if clean == 'TRUE':
			limpiarbaseDatos()
			print 'Limpieza Base de datos OK'

		for ipFiltrado_aux in lista_ip_filtrado:
			mostrarIpPuertosOrigen(df, ipFiltrado_aux)
			mostrarIpPuertosDestino(df, ipFiltrado_aux)
			mostrarAplicaciones(df, ipFiltrado_aux)
			mostrarIPoIPd(df, ipFiltrado_aux)
			mostrarIPdIPo(df, ipFiltrado_aux)
			mostrarDestinoICMP(df, ipFiltrado_aux)
			mostrarNumIpDistintas(df, ipFiltrado_aux)
			mostrarNumApp(df, ipFiltrado_aux)
			mostrarDataset(df, ipFiltrado_aux)
	else:
		print 'DIA FESTIVO'