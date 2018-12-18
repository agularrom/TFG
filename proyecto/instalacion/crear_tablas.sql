--
-- @Autor: Agustín Walabonso Lara Romero
-- @Descripción: Script de creación de las tablas de la base de datos
--

-- Creación de la tabla de aplicaciones
CREATE TABLE IF NOT EXISTS aplicaciones (
  ip varchar(15) NOT NULL,
  aplicacion varchar(50) NOT NULL,
  num_veces int(11) NOT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,aplicacion,num_veces,fecha,hora)
);

-- Creación de la tabla estadísticos
CREATE TABLE IF NOT EXISTS estadisticos (
  ip varchar(15) NOT NULL,
  indicador varchar(40) NOT NULL,
  hora int(11) NOT NULL,
  media float DEFAULT NULL,
  varianza float DEFAULT NULL,
  fecha date NOT NULL,
  muestras int(11) DEFAULT NULL,
  media_exp float DEFAULT NULL,
  varianza_exp float DEFAULT NULL,
  PRIMARY KEY (ip,indicador,hora,fecha)
);

-- Creación de la tabla icmp_destino
CREATE TABLE IF NOT EXISTS icmp_destino (
  ip varchar(15) NOT NULL,
  ip_destino varchar(50) NOT NULL,
  num_veces int(11) NOT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,ip_destino,num_veces,fecha,hora)
);

-- Creación de la tabla logs
CREATE TABLE IF NOT EXISTS logs (
  ip varchar(15) NOT NULL,
  fecha date NOT NULL,
  hora int(11) NOT NULL,
  tipo varchar(20) NOT NULL,
  indicador varchar(50) NOT NULL,
  valor int(11) DEFAULT NULL,
  PRIMARY KEY (ip,fecha,hora,indicador,tipo)
);

-- Creación de la tabla num_app
CREATE TABLE IF NOT EXISTS num_app (
  ip varchar(15) NOT NULL,
  aplicacion varchar(50) NOT NULL,
  num_veces int(11) DEFAULT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,aplicacion,fecha,hora)
);

-- Creación de la tabla num_ip
CREATE TABLE IF NOT EXISTS num_ip (
  ip varchar(15) NOT NULL,
  ip_aux varchar(15) DEFAULT NULL,
  num_veces int(11) DEFAULT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,fecha,hora)
);

-- Creación de la tabla puertos_destino
CREATE TABLE IF NOT EXISTS puertos_destino (
  ip varchar(15) NOT NULL,
  puerto varchar(50) NOT NULL,
  num_veces int(11) NOT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,puerto,num_veces,fecha,hora)
);

-- Creación de la tabla puertos_origen
CREATE TABLE IF NOT EXISTS puertos_origen (
  ip varchar(15) NOT NULL,
  puerto varchar(50) NOT NULL,
  num_veces int(11) NOT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,puerto,num_veces,fecha,hora)
);

-- Creación de la tabla relacion_ip
CREATE TABLE IF NOT EXISTS relacion_ip (
  ip varchar(15) NOT NULL,
  ip_destino varchar(50) NOT NULL,
  num_veces int(11) NOT NULL,
  fecha date NOT NULL,
  hora varchar(2) NOT NULL,
  PRIMARY KEY (ip,ip_destino,num_veces,fecha,hora)
);