  
**PRÁCTICA 4**

**Análisis de Logs de Seguridad (SIEM)**

Limpieza, validación lógica y visualización de datos de ciberincidentes

| 🛡  SecureGDL — Centro de Operaciones de Seguridad siem\_eventos\_sucio.csv  |  5,515 eventos  |  21 columnas  |  Período: Enero–Diciembre 2024 |
| :---: |

| Materia: | Análisis y Visualización de Datos |
| :---- | :---- |
| **Tipo:** | Práctica individual / equipos de 2 |
| **Objetivo:** | Limpiar y analizar registros de un SIEM empresarial, identificar inconsistencias operativas de seguridad y producir visualizaciones que apoyen la toma de decisiones del SOC |
| **Entregable:** | Notebook .ipynb comentado con reporte de decisiones y mínimo 2 gráficas |

# **PARTE A — El Escenario**

| Contexto profesional Eres analista de datos junior en SecureGDL, una empresa de servicios de ciberseguridad con sede en Guadalajara. Tu equipo opera un Centro de Operaciones de Seguridad (SOC) que monitorea la infraestructura de varios clientes corporativos. El SIEM (Security Information and Event Management) registra automáticamente cada alerta generada por firewalls, sistemas de detección de intrusiones, antivirus y logs de autenticación. |
| :---- |

El **Gerente del SOC** te entregó el export directo de la base de datos de eventos del año 2024 tal como salió del sistema. El archivo contiene ruido, errores de entrada de datos, inconsistencias operativas y registros corruptos. Antes de presentar cualquier métrica a los clientes, necesitas que los datos sean confiables.

| ❓ Preguntas de negocio (SOC):  ¿Qué tipo de evento de seguridad tiene la mayor tasa de falsos positivos? ¿Y en qué sistema operativo se concentran los eventos CRÍTICOS que aún no han sido resueltos? |
| :---- |

**¿Por qué importa responder esto?**

* Alta tasa de FP en un tipo de evento → los analistas están perdiendo tiempo en ruido → regla del SIEM mal calibrada.

* Eventos Críticos sin resolver en cierto SO → vulnerabilidad activa no parcheada → riesgo real para el cliente.

## **Glosario Técnico**

Para que puedas trabajar con el dataset sin necesidad de tener experiencia previa en ciberseguridad:

| Término | Significado en este contexto |
| ----- | ----- |
| SIEM | Sistema que centraliza y correlaciona logs de seguridad de toda la red |
| SOC | Equipo humano que revisa las alertas del SIEM y toma decisiones |
| Severidad | Nivel de peligro: Crítica \> Alta \> Media \> Baja |
| Falso positivo (FP) | El sistema marcó algo como amenaza pero en realidad era tráfico legítimo |
| IP origen | Dirección IP de quien inició la conexión o ataque |
| Puerto destino | Puerta lógica del servidor atacado (0–65535 válidos) |
| Tiempo de respuesta | Minutos entre la detección del evento y su resolución |
| SLA de respuesta | Acuerdo de nivel de servicio: Crítica ≤60 min, Alta ≤240 min, Media ≤480 min |
| Acción tomada | Lo que hizo el sistema/analista: Bloqueado, Permitido, Cuarentenado, etc. |
| Exfiltración | Robo de datos: el atacante saca información del sistema hacia afuera |
| Movimiento lateral | El atacante ya está dentro y se mueve entre sistemas internos |

## **Descripción del Dataset**

| Columna | Tipo esperado | Descripción |
| ----- | ----- | ----- |
| evento\_id | texto | Identificador único del evento |
| timestamp\_evento | datetime | Fecha y hora exacta de la detección |
| timestamp\_resolucion | datetime | Cuándo fue cerrado el evento (null si no resuelto) |
| ip\_origen | texto | IP de la fuente del tráfico sospechoso |
| ip\_destino | texto | IP del sistema atacado (siempre interna) |
| puerto\_destino | entero | Puerto del servicio objetivo (1–65535 válidos) |
| protocolo | texto | Protocolo de red utilizado |
| tipo\_evento | texto | Clasificación del incidente |
| categoria | texto | Categoría agrupadora del tipo de evento |
| severidad | texto | Nivel de criticidad: Crítica, Alta, Media, Baja |
| sistema\_afectado | texto | Nombre del servidor o equipo objetivo |
| sistema\_operativo | texto | SO del sistema afectado |
| pais\_origen | texto | País de procedencia del ataque |
| usuario | texto | Cuenta de usuario involucrada (puede ser null) |
| analista\_id | texto | Analista SOC que gestionó el evento |
| bytes\_enviados | entero | Bytes de tráfico enviados por el atacante |
| bytes\_recibidos | entero | Bytes de respuesta del sistema objetivo |
| accion\_tomada | texto | Respuesta del sistema: Bloqueado, Permitido, etc. |
| tiempo\_respuesta\_min | entero | Minutos entre detección y resolución |
| falso\_positivo | booleano | True si el evento fue descartado como FP |
| resuelto | booleano | True si el evento fue cerrado |

| ⚙  Reglas de negocio del SOC:  Regla 1 — Tiempo de respuesta calculable:    tiempo\_respuesta\_min \= (timestamp\_resolucion − timestamp\_evento) en minutos Regla 2 — Consistencia de resolución:    Si resuelto \= True → timestamp\_resolucion debe existir Regla 3 — Puerto válido:    0 \< puerto\_destino ≤ 65535 Regla 4 — Falso positivo implica no amenaza real:    Si falso\_positivo \= True → accion\_tomada NO debería ser 'Bloqueado' o 'Cuarentenado' Regla 5 — SLA de respuesta por severidad:    Crítica ≤ 60 min | Alta ≤ 240 min | Media ≤ 480 min | Baja ≤ 1440 min |
| :---- |

# **PARTE B — Instrucciones del Ejercicio**

Desarrolla tu solución en un **Jupyter Notebook**. Estructura cada fase con un encabezado Markdown. Cada decisión de limpieza debe estar documentada en el código con comentarios.

## **Fase 1 — Diagnóstico del Dataset**

| 📋 Regla:  No modifiques ningún dato todavía. Solo observa, documenta y lista los problemas. |
| :---- |

**1.1** Carga el dataset. Muestra shape, dtypes e info(). ¿Cuántas columnas tienen el tipo incorrecto para su contenido?

**1.2** Calcula el porcentaje de nulos por columna. ¿Hay columnas donde los nulos son esperados y lógicos? ¿Cuáles?

**1.3** Muestra los valores únicos de las columnas: tipo\_evento, severidad, accion\_tomada, categoria, pais\_origen.

**1.4** Revisa el campo ip\_origen. ¿Puedes detectar visualmente IPs que no tienen el formato correcto de una dirección IPv4?

**1.5** Describe() sobre columnas numéricas. ¿Qué columnas tienen valores que físicamente no pueden ser negativos?

**1.6** Escribe en una celda Markdown tu lista completa de problemas identificados.

## **Fase 2 — Limpieza de Texto y Estandarización**

**2.1** Normaliza con strip() y title() las columnas: tipo\_evento, severidad, accion\_tomada, categoria, pais\_origen, protocolo, sistema\_operativo.

**2.2** La columna severidad debe quedar con exactamente estos valores: Crítica, Alta, Media, Baja. Los valores 'Grave' y 'Urgente' son sinónimos no estándar. Documenta tu decisión de mapeo.

**2.3** La columna accion\_tomada debe tener solo: Bloqueado, Permitido, En Revisión, Alertado, Cuarentenado. ¿Qué haces con 'Ignorado'?

**2.4** Unifica los valores de pais\_origen: 'Russia' y 'Rusia' son el mismo país. 'EEUU', 'United States' y 'Estados Unidos' también.

**2.5** Elimina duplicados exactos. ¿Cuántos había?

## **Fase 3 — Timestamps y Tipos de Datos**

**3.1** Convierte timestamp\_evento a datetime. El campo mezcla al menos 3 formatos distintos incluyendo el americano MM/DD/YYYY. Usa el parámetro adecuado.

**3.2** Convierte timestamp\_resolucion a datetime. ¿Por qué NO debes usar errors='coerce' sin analizar primero si los nulos son legítimos?

**3.3** Convierte las columnas bytes\_enviados, bytes\_recibidos, puerto\_destino y tiempo\_respuesta\_min a enteros (maneja los nulos con Int64).

**3.4** Convierte falso\_positivo y resuelto a tipo booleano.

## **Fase 4 — Valores Imposibles y Outliers**

**4.1** Detecta y elimina puertos fuera del rango 1–65535.

**4.2** Detecta y decide qué hacer con filas donde bytes\_enviados o tiempo\_respuesta\_min sean negativos o cero.

**4.3** Valida el formato de ip\_origen: una IP válida tiene 4 octetos separados por puntos, cada uno entre 0 y 255\. ¿Cómo detectas las inválidas con Python?

## **Fase 5 — Inconsistencias Lógicas (Nivel SOC)**

| 🔴 Nivel crítico:  Aquí es donde demuestras que entiendes el negocio de ciberseguridad, no solo pandas. |
| :---- |

**5.1 — Falso positivo bloqueado:** Si falso\_positivo \= True, el sistema detectó tráfico legítimo como amenaza. ¿Tiene sentido que la accion\_tomada sea 'Bloqueado' o 'Cuarentenado'? Detecta estas filas y decide qué campo está equivocado.

**5.2 — Resuelto sin timestamp:** Un evento resuelto sin fecha de resolución es un registro incompleto. Detecta los casos donde resuelto \= True pero timestamp\_resolucion es null.

**5.3 — Resolución antes del evento:** timestamp\_resolucion anterior a timestamp\_evento es físicamente imposible. Detecta y elimina estas filas.

**5.4 — Tiempo de respuesta inconsistente:** Crea una columna tiempo\_calculado a partir de la diferencia real entre los dos timestamps. Compara con tiempo\_respuesta\_min. ¿Cuántos registros tienen una diferencia mayor a 30 minutos?

**5.5 — Violación de SLA:** Aplica las reglas de SLA por severidad. ¿Qué porcentaje de eventos Críticos superaron los 60 minutos de respuesta? ¿Y los Altos por encima de 240?

**5.6 — IP origen igual a IP destino:** Un host no puede atacarse a sí mismo en este contexto. Detecta y elimina filas donde ip\_origen \== ip\_destino.

**5.7 — Login exitoso bloqueado:** Un evento de tipo 'Login Exitoso' con accion \= 'Bloqueado' es una contradicción semántica: si se bloqueó, el login no pudo ser exitoso. Detecta estos casos.

**5.8 — Falso positivo crítico no resuelto:** Un evento marcado como falso positivo Y de severidad Crítica Y no resuelto es una combinación sospechosa. Detecta estos registros. ¿Qué indica esto sobre la calidad del proceso de triage?

## **Fase 6 — Imputación y Decisiones Finales**

**6.1** Para usuario (muchos nulos esperados): ¿conviene imputar o dejar null? Justifica considerando qué significa que un evento no tenga usuario asociado.

**6.2** Para pais\_origen nulo: ¿imputarías con 'Desconocido' o eliminarías la fila? ¿Qué impacto tiene cada decisión en el análisis posterior?

**6.3** Para puerto\_destino nulo: ¿tiene sentido imputar la mediana? ¿O un puerto nulo es un dato fundamentalmente diferente a cualquier otro puerto?

**6.4** Aplica tus decisiones y documenta cuántos nulos quedan al final.

## **Fase 7 — Análisis y Visualización**

| ✅ Meta final:  Los datos ya están limpios. Ahora responde las preguntas del SOC con evidencia visual. |
| :---- |

**7.1** Calcula la tasa de falsos positivos por tipo\_evento:

| tasa\_fp \= df.groupby('tipo\_evento')\['falso\_positivo'\].mean() \* 100 |
| :---- |

**7.2** Genera una gráfica de barras horizontales mostrando la tasa de FP por tipo de evento, ordenada de mayor a menor. Usa una línea vertical punteada para el promedio global.

**7.3** Filtra los eventos con severidad \= 'Crítica' y resuelto \= False. Agrupa por sistema\_operativo y cuenta cuántos hay en cada uno.

**7.4** Genera una segunda gráfica (barras o treemap si conoces squarify) mostrando los SO con más eventos críticos sin resolver. Usa rojo o escala de calor.

**7.5** Escribe tu conclusión en Markdown respondiendo las dos preguntas del SOC con números concretos. Incluye también cuántos eventos violaron el SLA de respuesta.

# **PARTE C — Criterios de Evaluación**

| Criterio | Descripción | Puntos |
| ----- | ----- | ----- |
| Diagnóstico documentado | Lista de problemas antes de tocar datos | 10 |
| Limpieza de texto | Normalización \+ mapeo de sinónimos justificado | 15 |
| Timestamps y tipos | Conversión correcta de múltiples formatos | 10 |
| Valores imposibles | Puertos, bytes negativos, IPs inválidas | 10 |
| Inconsistencias lógicas (8) | Detección y decisión justificada por cada una | 30 |
| Imputación de nulos | Estrategia argumentada para cada columna | 10 |
| Visualizaciones | 2 gráficas correctas, legibles, con título y ejes | 10 |
| Conclusión del SOC | Responde ambas preguntas con evidencia numérica | 5 |
| **TOTAL** |  | **100** |

| SECCIÓN DOCENTE — NO DISTRIBUIR Solución completa paso a paso con código comentado |
| :---: |

# **Solución Completa — Guía Docente**

## **Fase 1 — Diagnóstico**

| import pandas as pd import numpy as np import matplotlib.pyplot as plt import matplotlib.ticker as ticker import re df \= pd.read\_csv('siem\_eventos\_sucio.csv') print(df.shape)    \# \~(5515, 21\) df.info() \# Nulos por columna con porcentaje nulos \= df.isnull().sum() pct   \= (nulos / len(df) \* 100).round(2) print(pd.DataFrame({'nulos': nulos, 'pct': pct})\[nulos \> 0\]) \# NOTA PEDAGÓGICA: timestamp\_resolucion y usuario tienen nulos esperados. \# Un evento no resuelto legítimamente no tiene timestamp\_resolucion. \# Un evento sin usuario asociado (escaneo de puertos, DDoS) es normal. |
| :---- |

| \# Revisar valores únicos en columnas categóricas for col in \['tipo\_evento','severidad','accion\_tomada','categoria','pais\_origen'\]:     print(f'\\n{col} ({df\[col\].nunique()} únicos):')     print(df\[col\].value\_counts().to\_string()) \# Estadísticas numéricas — buscar negativos y absurdos print(df\[\['puerto\_destino','bytes\_enviados','bytes\_recibidos',           'tiempo\_respuesta\_min'\]\].describe()) \# ALERTA: bytes\_enviados con mínimo negativo \# ALERTA: puerto\_destino con valores \> 65535 o \<= 0 \# ALERTA: tiempo\_respuesta\_min con valores negativos o cero |
| :---- |

## **Fase 2 — Limpieza de Texto**

| \# 2.1 Normalización general cols\_texto \= \['tipo\_evento','severidad','accion\_tomada','categoria',               'pais\_origen','protocolo','sistema\_operativo'\] for col in cols\_texto:     df\[col\] \= df\[col\].astype(str).str.strip().str.title()     df\[col\] \= df\[col\].replace('Nan', np.nan) |
| :---- |

| \# 2.2 Mapeo de severidad \# 'Grave' y 'Urgente' no tienen equivalente estándar establecido. \# Decisión: mapearlos a 'Alta' por ser sinónimos de nivel de riesgo elevado. \# ALTERNATIVA: eliminar la fila. Documentar la elección. mapa\_sev \= {     'Crítica': 'Crítica', 'Critica': 'Crítica',     'Alta':    'Alta',    'Grave':   'Alta',   'Urgente': 'Alta',     'Media':   'Media',     'Baja':    'Baja', } df\['severidad'\] \= df\['severidad'\].map(mapa\_sev).fillna(df\['severidad'\]) print(df\['severidad'\].value\_counts()) |
| :---- |

| \# 2.3 Mapeo de accion\_tomada \# 'Cuarentena' → 'Cuarentenado' (normalizar al participio) \# 'Ignorado' → decisión: no está en catálogo, lo marcamos como 'Permitido' \#   ya que ignorar \= no actuar \= dejar pasar. Documentar. mapa\_accion \= {     'En Revisión': 'En Revisión', 'En Revision': 'En Revisión',     'Cuarentena':  'Cuarentenado',     'Ignorado':    'Permitido', } df\['accion\_tomada'\] \= df\['accion\_tomada'\].replace(mapa\_accion) |
| :---- |

| \# 2.4 Unificar país de origen mapa\_pais \= {     'Russia':         'Rusia',     'Eeuu':           'Estados Unidos',     'United States':  'Estados Unidos',     'China ':         'China', } df\['pais\_origen'\] \= df\['pais\_origen'\].replace(mapa\_pais) \# 2.5 Eliminar duplicados exactos print('Duplicados exactos:', df.duplicated().sum()) df \= df.drop\_duplicates() |
| :---- |

## **Fase 3 — Timestamps y Tipos**

| \# 3.1 Convertir timestamp\_evento — mezcla de formatos incluyendo MM/DD/YYYY americano \# infer\_datetime\_format maneja la mayoría; dayfirst=False prioriza el formato ISO df\['timestamp\_evento'\] \= pd.to\_datetime(     df\['timestamp\_evento'\], infer\_datetime\_format=True,     dayfirst=False, errors='coerce' ) \# 3.2 timestamp\_resolucion — los nulos legítimos (no resueltos) se preservan df\['timestamp\_resolucion'\] \= pd.to\_datetime(     df\['timestamp\_resolucion'\], infer\_datetime\_format=True,     dayfirst=False, errors='coerce' ) \# 3.3 Tipos numéricos con Int64 para soportar NaN for col in \['bytes\_enviados','bytes\_recibidos','puerto\_destino','tiempo\_respuesta\_min'\]:     df\[col\] \= pd.to\_numeric(df\[col\], errors='coerce').astype('Int64') \# 3.4 Booleanos df\['falso\_positivo'\] \= df\['falso\_positivo'\].astype(bool) df\['resuelto'\]       \= df\['resuelto'\].astype(bool) |
| :---- |

## **Fase 4 — Valores Imposibles**

| \# 4.1 Puertos fuera de rango mask\_puerto \= (df\['puerto\_destino'\] \<= 0\) | (df\['puerto\_destino'\] \> 65535\) print('Puertos inválidos:', mask\_puerto.sum()) df \= df\[\~mask\_puerto | df\['puerto\_destino'\].isna()\] \# 4.2 Bytes y tiempo negativos df \= df\[df\['bytes\_enviados'\] \> 0\] df \= df\[df\['tiempo\_respuesta\_min'\] \> 0\] \# 4.3 Validar formato IPv4 def ip\_valida(ip):     if pd.isna(ip): return False     partes \= str(ip).split('.')     if len(partes) \!= 4: return False     try:         return all(0 \<= int(p) \<= 255 for p in partes)     except:         return False mask\_ip \= \~df\['ip\_origen'\].apply(ip\_valida) print('IPs inválidas en ip\_origen:', mask\_ip.sum()) df \= df\[\~mask\_ip\] |
| :---- |

## **Fase 5 — Inconsistencias Lógicas**

| \# L1: Falso positivo con acción agresiva mask\_L1 \= df\['falso\_positivo'\] & df\['accion\_tomada'\].isin(\['Bloqueado','Cuarentenado'\]) print('L1 \- FP bloqueado/cuarentenado:', mask\_L1.sum()) \# Decisión: si es FP, la acción debería ser 'Permitido'. Corregir acción. df.loc\[mask\_L1, 'accion\_tomada'\] \= 'Permitido' |
| :---- |

| \# L2: Resuelto sin timestamp de resolución mask\_L2 \= df\['resuelto'\] & df\['timestamp\_resolucion'\].isna() print('L2 \- Resuelto sin timestamp:', mask\_L2.sum()) \# Decisión: si no tiene timestamp, no podemos confirmar cuándo se resolvió. \# Marcar como no resuelto para no contaminar métricas de tiempo de respuesta. df.loc\[mask\_L2, 'resuelto'\] \= False |
| :---- |

| \# L3: timestamp\_resolucion ANTES que timestamp\_evento mask\_L3 \= df\['timestamp\_resolucion'\] \< df\['timestamp\_evento'\] print('L3 \- Resolución antes del evento:', mask\_L3.sum()) df \= df\[\~mask\_L3\] |
| :---- |

| \# L4: Tiempo de respuesta inconsistente con timestamps reales df\['tiempo\_calculado'\] \= (     (df\['timestamp\_resolucion'\] \- df\['timestamp\_evento'\])     .dt.total\_seconds() / 60 ).round(0).astype('Int64') mask\_L4 \= (df\['tiempo\_calculado'\] \- df\['tiempo\_respuesta\_min'\]).abs() \> 30 mask\_L4 \= mask\_L4 & df\['tiempo\_calculado'\].notna() print('L4 \- Tiempo respuesta inconsistente:', mask\_L4.sum()) \# Decisión: confiar en los timestamps (fuente primaria) y recalcular el campo df.loc\[mask\_L4, 'tiempo\_respuesta\_min'\] \= df.loc\[mask\_L4, 'tiempo\_calculado'\] df \= df.drop(columns=\['tiempo\_calculado'\]) |
| :---- |

| \# L5: Violación de SLA de respuesta sla \= {'Crítica': 60, 'Alta': 240, 'Media': 480, 'Baja': 1440} df\['sla\_limite'\] \= df\['severidad'\].map(sla) mask\_L5 \= df\['tiempo\_respuesta\_min'\] \> df\['sla\_limite'\] print('\\nViolaciones de SLA por severidad:') print(df\[mask\_L5\]\['severidad'\].value\_counts()) print(f'% Críticos fuera de SLA: {mask\_L5\[df\["severidad"\]=="Crítica"\].mean()\*100:.1f}%') df \= df.drop(columns=\['sla\_limite'\]) |
| :---- |

| \# L6: IP origen \= IP destino mask\_L6 \= df\['ip\_origen'\] \== df\['ip\_destino'\] print('L6 \- IP origen \= IP destino:', mask\_L6.sum()) df \= df\[\~mask\_L6\] \# L7: Login exitoso bloqueado mask\_L7 \= (df\['tipo\_evento'\].str.lower() \== 'login exitoso') & \\           (df\['accion\_tomada'\] \== 'Bloqueado') print('L7 \- Login exitoso bloqueado:', mask\_L7.sum()) \# Decisión: si el login fue exitoso, la acción real fue Permitido df.loc\[mask\_L7, 'accion\_tomada'\] \= 'Permitido' \# L8: FP \+ Crítica \+ No resuelto mask\_L8 \= df\['falso\_positivo'\] & (df\['severidad'\] \== 'Crítica') & \~df\['resuelto'\] print('L8 \- FP Crítico sin resolver:', mask\_L8.sum()) \# Nota pedagógica: esto indica un proceso de triage deficiente. \# Si es FP, debería haberse resuelto inmediatamente. Marcar como resuelto. df.loc\[mask\_L8, 'resuelto'\] \= True |
| :---- |

| ✅  Checkpoint: después de todas las fases, el dataset debería tener entre 4,700 y 5,000 filas. El número exacto dependerá del orden de aplicación de las limpiezas. |
| :---- |

## **Fase 6 — Imputación de Nulos**

| \# usuario: los nulos son LEGÍTIMOS — muchos eventos de red no tienen usuario. \# NO imputar. Dejar null y documentar que representa tráfico no autenticado. \# pais\_origen: imputar con 'Desconocido' para no perder el evento. \# Eliminar la fila solo si el análisis de país es el objetivo principal. df\['pais\_origen'\] \= df\['pais\_origen'\].fillna('Desconocido') \# puerto\_destino: NO imputar con mediana — un puerto nulo es ausencia de \# información, no un puerto intermedio. Conservar null para análisis que \# no usen puerto, eliminar solo en análisis que lo requieran. \# analista\_id: pocos nulos, imputar con 'SIN\_ASIGNAR' df\['analista\_id'\] \= df\['analista\_id'\].fillna('SIN\_ASIGNAR') print('Nulos restantes:') print(df.isnull().sum()\[df.isnull().sum() \> 0\]) |
| :---- |

## **Fase 7 — Análisis y Visualización**

| \# ── GRÁFICA 1: Tasa de FP por tipo de evento ────────────────────── tasa\_fp \= (     df.groupby('tipo\_evento')\['falso\_positivo'\]     .agg(\['mean','count'\])     .rename(columns={'mean':'tasa\_fp','count':'total'}) ) tasa\_fp\['tasa\_fp'\] \= tasa\_fp\['tasa\_fp'\] \* 100 tasa\_fp \= tasa\_fp.sort\_values('tasa\_fp', ascending=True) fig, ax \= plt.subplots(figsize=(11, 8)) colores \= \['\#B71C1C' if v \> tasa\_fp\['tasa\_fp'\].mean() else '\#1565C0'            for v in tasa\_fp\['tasa\_fp'\]\] bars \= ax.barh(tasa\_fp.index, tasa\_fp\['tasa\_fp'\],                color=colores, edgecolor='white', height=0.65) promedio \= tasa\_fp\['tasa\_fp'\].mean() ax.axvline(x=promedio, color='gray', linestyle='--', linewidth=1.5,            alpha=0.7, label=f'Promedio global: {promedio:.1f}%') for bar, (\_, row) in zip(bars, tasa\_fp.iterrows()):     ax.text(bar.get\_width() \+ 0.3, bar.get\_y() \+ bar.get\_height()/2,             f"{row\['tasa\_fp'\]:.1f}%  (n={int(row\['total'\])})",             va='center', fontsize=9) ax.set\_xlabel('Tasa de Falsos Positivos (%)', fontsize=12) ax.set\_title('Tasa de Falsos Positivos por Tipo de Evento\\n'              '(Rojo \= por encima del promedio global)',              fontsize=13, fontweight='bold', pad=15) ax.legend() plt.tight\_layout() plt.savefig('tasa\_fp\_por\_evento.png', dpi=150) plt.show() |
| :---- |

| \# ── GRÁFICA 2: Eventos Críticos sin resolver por SO ──────────────── criticos\_sin\_resolver \= df\[     (df\['severidad'\] \== 'Crítica') & (\~df\['resuelto'\]) \] por\_so \= criticos\_sin\_resolver\['sistema\_operativo'\].value\_counts() fig, ax \= plt.subplots(figsize=(10, 6)) colores\_red \= plt.cm.Reds(np.linspace(0.4, 0.9, len(por\_so))\[::-1\]) bars \= ax.bar(range(len(por\_so)), por\_so.values,               color=colores\_red, edgecolor='white') ax.set\_xticks(range(len(por\_so))) ax.set\_xticklabels(por\_so.index, rotation=35, ha='right', fontsize=9) ax.set\_ylabel('Eventos Críticos sin resolver', fontsize=12) ax.set\_title('Eventos de Severidad CRÍTICA Sin Resolver\\npor Sistema Operativo',              fontsize=13, fontweight='bold', color='\#B71C1C', pad=15) for bar, val in zip(bars, por\_so.values):     ax.text(bar.get\_x() \+ bar.get\_width()/2, bar.get\_height() \+ 0.3,             str(val), ha='center', va='bottom', fontsize=10, fontweight='bold') plt.tight\_layout() plt.savefig('criticos\_por\_so.png', dpi=150) plt.show() |
| :---- |

| \# ── CONCLUSIÓN (ejemplo de lo que el alumno debe escribir) ───────── \# El tipo de evento con mayor tasa de falsos positivos es \[X\] con \[Y\]%, \# muy por encima del promedio global de \[Z\]%. Esto sugiere que la regla \# del SIEM para ese tipo de evento necesita reajuste de umbral. \# \# Los eventos Críticos sin resolver se concentran en \[SO\] con \[N\] casos. \# Esto representa una superficie de ataque activa no parcheada. \# \# Adicionalmente, \[M\]% de los eventos Críticos violaron el SLA de 60 min, \# lo que indica una capacidad de respuesta del SOC por debajo del contrato. |
| :---- |

**Valores de referencia esperados** (±5% según orden de limpieza): Filas finales: \~4,700–5,000 | Duplicados: \~15 | IPs inválidas: \~18 | FP bloqueados (L1): \~50 | Timestamps imposibles (L3): \~35 | Inconsistencia tiempo (L4): \~80