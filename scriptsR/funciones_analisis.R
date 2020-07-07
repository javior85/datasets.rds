## @knitr answer

###########################################################################################################################
#                                                   MASTER CYBERSECURITY                                                  #
#                                                                                                                         #
#                                               TRABAJO FINAL DE MASTER                                                   #
#                                         FUNCIONES PARA EL ANALISIS DE DATOS                                             #
#                                                                                                                         #
#                                                ALUMNO: Javier Ortega Martín                                             #
###########################################################################################################################

#Poner las funcione en memoria:
# source ("funciones_analisis.R")

#intalar_packages()

#cargar_librerias()

#install.packages('rsconnect')

###########################################################################################################################
# FUNCION PARA INSTALAR PAQUETES DE R NECESARIOS PARA EJECUTAR LA PRÁCTICA, EN CASO QUE NO
# ESTEN YA INSTALADOS

instalar_packages <- function(){
  if (!require("dplyr")) install.packages("dplyr")
  if (!require("ggplot2")) install.packages("ggplot2")
  if (!require("flexdashboard"))install.packages("flexdashboard")
  if (!require("maps"))install.packages("maps")
  if (!require("rworldmap"))install.packages("rworldmap")
}
###########################################################################################################################


###########################################################################################################################
# FUNCIÓN PARA EJECUTAR LAS LIBRERIAS PARA EL PROYECTO
cargar_librerias <- function(){
  library(dplyr) #libreria básica
  library(ggplot2) #libreria para gráficos 
  library(flexdashboard) #libreria para crear el Dashboard
  library(readr) #libreria para leer ficheros csv
  library(rworldmap)
  library(maps)
  
}
###########################################################################################################################

###########################################################################################################################
# FUNCIÓN PARA LEER LOS DATASETS 
cargar_datasets <- function(){
  osint <- readRDS("C:/DEVEL/datasets/General_Osint.rds")
  firehol <- readRDS("C:/DEVEL/datasets/General_Firehol.rds")
  osint_geolocation <- readRDS("C:/DEVEL/datasets/General_TopOsint.rds")
  geolocation <- readRDS("C:/DEVEL/datasets/General_Geolocation.rds")
}
###########################################################################################################################

###########################################################################################################################
# FUNCIÓN QUE DEVUELVE LA CANTIDAD DE IPs ESCANEADAS

TotalScannedIP <- function(osint){
  
  value = dplyr::summarise(osint, Quantity = dplyr::n())
  
  #En caso que no exista ninguna instancia del valor buscado devolvemos 0
  value  <- if(nrow(value) == 0) {0} else {value}
  
  return(value)
}
#######################################################################################################################

#######################################################################################################################
#FUNCIÓN  QUE DETERMINA LAS IP'S DETECTADAS POR CADA MANTENEDOR

IP_ByMaintainer <- function(firehol){
  
  #1.0 Agrupar información por mantenedor
  by_maintainer <- dplyr::group_by(firehol, mnt)
  
  #2.0 Contar cuantas IP's han sido descubierta por cada mantenedor
  by_maintainer <- dplyr::summarise(by_maintainer, Quantity = dplyr::n())
  
  #3.0 Ordenar las categorias de más vulnerabilidades a menos (ORDEN INVERSO)
  by_maintainer <- by_maintainer[with(by_maintainer, order(-by_maintainer$Quantity)), ] 
  
  return (by_maintainer)
}
#######################################################################################################################


#######################################################################################################################
#FUNCIÓN  QUE DETERMINA EL CONTAJE de IP's POR CATEGORIA 

IP_ByCategory <- function(firehol){

  #1.0 Agrupar información por categoria
  by_category <- dplyr::group_by(firehol, category)
  
  #2.0 Contar cuantas vulnerabilidades hay de cada categoria
  by_category <- dplyr::summarise(by_category, Quantity = dplyr::n())
  
  #3.0 Ordenar las categorias de más vulnerabilidades a menos (ORDEN INVERSO)
  by_category <- by_category[with(by_category, order(-by_category$Quantity)), ] 
  
  
  #5.0 Graficar las categorias de vulnerabilidades en un gráfico circula
  Grafo_CatIP = ggplot(by_category,aes(x="", y=Quantity, fill=category)) +
    geom_bar(stat = "identity", color="white") +
    coord_polar(theta="y") +
    theme (axis.text.x=element_blank(),   #Remove axis tick mark labels
           axis.title.x = element_blank(),
           axis.title.y = element_blank(),
           panel.border = element_blank(),
           panel.grid=element_blank(),
           axis.ticks = element_blank() )
    
  #6.0 Dibujar gráfico
  Grafo_CatIP
  
  return (Grafo_CatIP)
}
#######################################################################################################################

#######################################################################################################################
#FUNCIÓN  QUE DETERMINA EL TOP 10 DE IP's CON UN NIVEL DE AMENAZA ALTO

TOP10IP_ByThreatLevel <- function(osint){

  #1.0 Agrupar información por THREAT_LEVEL
  by_ThreatLevel <- dplyr::group_by(osint, THREAT_LEVEL)
  
  #2.0 Ordenar el Dataset en orden inverso según el THREAT_LEVEL
  by_ThreatLevel <- by_ThreatLevel[with(by_ThreatLevel, order(-by_ThreatLevel$THREAT_LEVEL)), ] 
  
  #3.0 Seleccionar las 10 IP's con un THREAT_LEVEL más alto
  top10_by_ThreatLevel <- by_ThreatLevel[1:10,]

  return (top10_by_ThreatLevel)
}
###########################################################################################################################

###########################################################################################################################
#FUNCIÓN  QUE DETERMINA EL CONTAJE de IP's POR PAIS

IP_ByCountry <- function(osint_geolocation, paises){
  
  #1.0 Importar fichero CSV de codificación de Paises
  paises <- read_csv("paises.csv")
  paises <- paises %>% select(nombre, iso2)
  names (paises)[1] ="Country Name"
  names (paises)[2] ="country" # cambiar nombre de la columna de código para posteriormente correlecionarla con los datos reales.
  
  #2.0 Agrupar información por país
  by_country <- dplyr::group_by(osint_geolocation, country)
  
  #3.0 Contar cuantas IP's maliciosas¡ hay de cada país
  by_country <- dplyr::summarise(by_country, Quantity = dplyr::n())
  
  #4.0 Añadir columna con el nombre del Pais
  by_country <- left_join(paises, by_country, by="country", copy=TRUE)  %>% filter(!is.na("Country Name"))
  
  #5.0 Ordenar las IP's de más maliciosas a menos (ORDEN INVERSO)
  by_country <- by_country[with(by_country, order(-by_country$Quantity)), ] 
  
  
  return (by_country)
}
###########################################################################################################################


###########################################################################################################################
#FUNCIÓN QUE CREA UN MAPA DEL MUNDO CON PAISES (rworldmap)

Create_WorldMap <- function(){
  
  #1.0 Agrupar información por país
  by_country <- dplyr::group_by(osint_geolocation, country)
  
  #2.0 Contar cuantas IP's maliciosas¡ hay de cada país
  by_country <- dplyr::summarise(by_country, Cantidad = dplyr::n())
  
  
  #3.0 Crear mapa mundi con las IP's maliciosas
  spdf <- joinCountryData2Map(by_country, joinCode="ISO2", nameJoinColumn="country", mapResolution = "medium", verbose ="FALSE")
  
  map <- mapCountryData(spdf, nameColumnToPlot="Cantidad", catMethod="diverging",borderCol="black", colourPalette="red", oceanCol="lightblue", missingCountryCol= "white")
  
  map
  
  return (map)
}
###########################################################################################################################




Create_WorldMap_Interactive <- function(){

  
  #1.0 Agrupar información por país
  by_country <- dplyr::group_by(osint_geolocation, country)
  
  #2.0 Contar cuantas IP's maliciosas¡ hay de cada país
  by_country <- dplyr::summarise(by_country, Cantidad = dplyr::n())
  
  
  # para instalar leaflet:    
  #   install.packages("leaflet")
  
  # Cargamos el paquete    
  library(leaflet)
  
  
  # carga del plano base
  m <- leaflet(by_country)  %>%  
    addTiles() %>%   
    setView( lat=10, lng=0 , zoom=2) 
  
  m
  
  
}




