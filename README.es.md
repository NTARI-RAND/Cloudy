> Traducción comunitaria (borrador) — Política P2-002 de NTARI, Difusión Multilingüe Global. Fuente: README.md (original en inglés, instantánea del 2026-07-29). Borrador comunitario asistido por máquina, pendiente de revisión por el mantenedor regional según P2-002 §3.1. Las especificaciones técnicas centrales permanecen en inglés según §2.2.
>
> ¿Encontraste un error en esta traducción? Tu corrección es una contribución
> bienvenida y valorada: haz un fork del repositorio y abre un pull request en
> https://github.com/NTARI-RAND/Cloudy.

# Cloudy

Un frontend sobre la red de coordinación SoHoLINK / sohocloud. Cloudy es donde
los miembros realizan transacciones; consume la coordinación del sustrato a
través del módulo compartido `sohocloud-protocol` y posee, por encima, su
propia economía de miembros JFA.

## Estado (honesto)

Las tres capas de la economía de miembros JFA que Cloudy posee —y que el
protocolo deliberadamente no posee— ya están **construidas, con pruebas**.
Todavía no hay un bucle de coordinación en vivo ni una superficie orientada a
los miembros.

- **`internal/record` — construido.** Registro sellado por diálogo, de solo
  anexado (append-only) y atestiguado: cada Entry lleva los sellos de ambos
  miembros sobre bytes canónicos con separación de dominio, de modo que un
  convenio sellado a medias o autonegociado nunca puede entrar en un log; los
  logs por operador encadenados por hash se reverifican por completo en
  `OpenLog`; los checkpoints del operador, más las contrafirmas de testigos
  independientes, hacen que cualquier reescritura del historial con checkpoint
  sea criptográficamente detectable (la factorización CT), y un despliegue con
  un solo testigo queda etiquetado como el sustituto provisional que es. No
  existe ninguna forma de PII en el commons: el contenido identificatorio vive
  únicamente en el Locker borrable y local del miembro. `Entry.ID()`, el hash
  de hoja, es la única referencia de intercambio entre capas.
- **`internal/economy` — construido.** Crédito mutuo soberano por plataforma:
  el crédito se emite en el momento del gasto, dentro de un único tope de
  débito uniforme y gobernado, y la suma de todos los saldos es siempre
  exactamente cero. Ningún mint, campo fiat, redención ni memo es
  representable; el cambio entre escrow-ahora y crédito-después es exactamente
  un PolicyChange firmado por quórum sobre el mismo almacén de solo anexado;
  `Open` reproduce y reverifica por completo cada registro. `Spend.ExchangeHash`
  lleva el ID de hoja de la entrada del registro, pero es deliberadamente
  opaco y no se verifica en Post — el anclaje es una responsabilidad de la
  raíz de composición.
- **`internal/covenant` — construido.** Reputación según la Leveson-Based
  Trade Assessment Scale (LBTAS) de NTARI: seis niveles cargados de
  significado, desde -1 No Trust (sin confianza) hasta +4 Delight (deleite),
  bidireccional (ambas partes de un intercambio sellado se evalúan
  mutuamente), expresada por categoría sobre un vocabulario cerrado (valores
  predeterminados: confiabilidad, usabilidad, desempeño, soporte), y leída
  únicamente como distribuciones completas de conteo por nivel —por categoría,
  agregadas en conjunto, y un conteo de daño que hace visible cada -1—
  **nunca promediada**, sin puntaje, exportación, enmienda, retractación ni
  comparación entre miembros en ninguna parte (dos pruebas centinela —un
  escaneo por reflexión del conjunto de métodos y un escaneo con go/ast de
  funciones exportadas— lo mantienen así). Un veredicto de -1 requiere un
  comentario que lo justifique; el texto del comentario vive en el Locker
  borrable y local del miembro, mientras que solo su hash viaja en el commons.
  Cada evaluación está firmada por quien evalúa y tiene como precio un
  intercambio sellado a través de la compuerta Anchors; los IDs de miembro son
  hashes de clave con alcance de plataforma, y los IDs elegidos por humanos se
  rechazan de plano. La especificación vinculante y la implementación de
  referencia viven en
  `Development/Covenant/Leveson-Based-Trade-Assessment-Scale`.
- **Real pero delgado:** `internal/coord` — un cliente delgado sobre el
  transporte HTTP+JSON de referencia del protocolo, que demuestra que Cloudy
  consume `sohocloud-protocol`. `cmd/cloudy` lo construye e informa el
  arranque; todavía no hay un bucle de coordinación en vivo.

`cmd/cloudy` ahora construye las tres capas en memoria al arrancar (génesis en
ModeEscrow, log de operador vacío, libro de convenios vacío sobre un
directorio de miembros compartido vacío) y registra una línea honesta por
capa. Cada paquete nombra sus invariantes no negociables en la documentación
del paquete.

## Qué posee Cloudy (arquitectura)

Bajo la arquitectura resuelta, Cloudy —el frontend— posee el mundo completo
del miembro. Tres capacidades, un solo dueño:

- **La economía de miembros JFA — construida.** `internal/economy` (crédito
  emitido por los miembros), `internal/covenant` (reputación LBTAS),
  `internal/record` (registro sellado por diálogo), exactamente como se
  documenta arriba. Estas son de Cloudy y deliberadamente no del protocolo:
  las personas nunca viajan por el cable.
- **El agente de nodo — propiedad de Cloudy, actualmente alojado en el
  repositorio del coordinador a la espera de migración.** Detección de
  hardware, perfiles de recursos, generación del listado de capacidades,
  heartbeat, el ejecutor de trabajos, aplicación local de opt-out/lista de
  permitidos, telemetría y el instalador para la máquina del miembro. Este
  código (`internal/agent`, `cmd/agent` y el instalador MSI) vive hoy en el
  repositorio de SoHoLINK y sigue funcionando allí — un remanente de la era
  en que SoHoLINK era a la vez frontend y coordinador, no el rol de largo
  plazo de SoHoLINK. El agente es la presencia del miembro en su propia
  máquina, así que pertenece al frontend; un coordinador que despliega
  agentes en el hardware de los miembros es un coordinador que toca el
  hardware de los miembros, algo que SoHoLINK nunca debe hacer.
- **El portal de miembros — propiedad de Cloudy, actualmente alojado en el
  repositorio del coordinador a la espera de migración.** Registro, inicio de
  sesión, panel de control, envío de trabajos y opt-out. La superficie antes
  llamada el «portal de participantes» (`internal/portal`, `cmd/portal`,
  `web/` en el repositorio de SoHoLINK) es de aquí en adelante el portal de
  miembros de Cloudy — la identidad del miembro es un asunto del frontend,
  así que la puerta por la que entran los miembros debe ser la puerta del
  frontend.

El agente de nodo y el portal de miembros son los próximos hitos de
construcción ahora que las tres capas están completas como bibliotecas. Como
dice honestamente el estado de arriba: ninguno de los dos tiene todavía un
punto de entrada aquí, y nada en este repositorio pretende que la migración ya
haya ocurrido.

### Glosario

- **Miembro** — una persona, siempre relativa a un frontend/plataforma. La
  identidad (MemberID con alcance de plataforma), el crédito, la posición
  LBTAS, los registros sellados, la PII (borrable, local al miembro) y las
  máquinas aportadas son hechos de membresía. La membresía es lenguaje de
  convenio — obligación mutua hacia una plataforma particular; el mismo ser
  humano es un miembro distinto en cada plataforma por construcción
  criptográfica.
- **Participante** — un rol, no una entidad: un miembro que actúa en la
  economía coordinada, aportando nodos y/o enviando trabajos — una identidad
  unificada, nunca dividida en productor y consumidor. Los registros de
  personas del lado del coordinador (la tabla de participants de SoHoLINK y
  las cuentas del portal) son superficies transicionales de la era dual.
- **Nodo** — una máquina que un miembro aporta, identificada por NodeID con
  la vinculación SPIFFE `/node/<id>` (el paquete `identity/` del protocolo).

### Identidad hacia el coordinador

Dos identidades cruzan la frontera frontend/coordinador, y no deben
confundirse. Las máquinas de los miembros portan **identidad de carga de
trabajo (workload identity)**: un SVID de SPIFFE bajo `/node/<id>`, autorizado
del lado del coordinador exactamente según la SPEC del protocolo — identidad
de máquina, sin cambios. Cloudy mismo se autentica como un **operador**
inscrito: el modelo de frontend-como-operador, un **objetivo de diseño**
modelado sobre el esquema de operadores de la Fase 5 de Agrinet (un registro
de operators + operator-keys; un conjunto rotatorio de siete claves Ed25519,
cada transmisión firmada con dos; replay acotado por una ventana de marca de
tiempo más una caché de nonces — ver
`Development/Economy/Agrinet backend/lib/operatorKeys.js` y
`backend/middleware/operatorAuth.js`). La rotación es el punto: una clave
compartida estática y nunca rotada es precisamente el antipatrón que la
referencia advierte no heredar. Ninguna de las dos identidades es jamás una
persona: la identidad del miembro permanece dentro de Cloudy.

## Invariante del grafo de importaciones

Cloudy importa `sohocloud-protocol`; **nada importa a Cloudy**. Cloudy depende
del núcleo del protocolo y de su transporte de referencia, y no elude a
ninguno de los dos. La dirección de la dependencia es lo que mantiene
separables al frontend y al coordinador: un frontend puede reemplazarse sin
tocar el sustrato, y el sustrato no sabe de ningún frontend en particular.

Dentro de Cloudy, los tres paquetes JFA nunca se importan entre sí; cada uno
ve solo la biblioteca estándar y el paquete `canon` del protocolo, y todas las
importaciones se mantienen unidireccionales. Se encuentran únicamente en la
raíz de composición: `test/composition` es la única prueba de raíz de
composición — allí viven el único directorio de miembros compartido, el
predicado Anchors que une el convenio con el registro sobre `Entry.ID()` y la
historia completa del miembro — y `cmd/cloudy` realiza la misma composición al
arrancar.

## Compilación

El módulo del protocolo es actualmente privado y no tiene tags. Este esqueleto
lo resuelve mediante una directiva `replace` hacia un **checkout hermano
local**:

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

Por lo tanto, `sohocloud-protocol` debe clonarse junto a `Cloudy` (ambos bajo
el mismo directorio padre). Este `replace` es una conveniencia para el
desarrollo local — tal cual está, no es compilable por terceros. Publicar
Cloudy para compilación externa requerirá etiquetar el módulo del protocolo (o
una configuración de `GOPRIVATE` + descarga autenticada) y eliminar el
`replace`.

```
go build ./...
go test ./...
```

## Licencia

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
