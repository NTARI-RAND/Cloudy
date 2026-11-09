> Traducción comunitaria (borrador) — Política P2-002 de NTARI, Difusión Multilingüe Global. Fuente: CONFORMANCE.md (original en inglés, instantánea del 2026-10-05). Borrador comunitario asistido por máquina, pendiente de revisión por mantenedores regionales conforme a P2-002 §3.1. Las especificaciones técnicas centrales permanecen en inglés conforme a §2.2.
>
> ¿Encontraste un error en esta traducción? Tu corrección es una contribución
> bienvenida y valorada: haz un fork del repositorio y abre un pull request en
> https://github.com/NTARI-RAND/Cloudy.

> **El original en inglés es normativo.** Esta traducción se ofrece para lectura, no para interpretación: donde difiera de `CONFORMANCE.md`, rige el inglés. Las palabras clave normativas (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY), los nombres de campos, las etiquetas y los identificadores se mantienen en inglés porque constituyen el contrato de conformidad.

# Conformidad — Janus-Facing Architecture

La autodescripción del repositorio en los propios términos de la arquitectura, expuesta **antes** de cualquier cosa específica del producto, según la regla de orden de la arquitectura. Cada afirmación de conformidad está vinculada al mecanismo y a la verificación que la hacen cumplir; de lo contrario, se etiqueta como suplencia o como stub. La prosa no vinculada es marketing.

La arquitectura es **Janus-Facing Architecture (JFA)**: el documento de arquitectura unificada de NTARI, documentación libre bajo el bien común AGPL-3.0 del proyecto.

## Declaración de rol

Cloudy es un **frontend** de un sustrato de JFA — la aplicación de cara a los miembros — y el hogar de las **capas de la economía de miembros** que el protocolo de coordinación del sustrato deliberadamente no define: la bitácora de diálogos por operador, el pacto de reputación y el crédito emitido por los miembros. Los miembros existen aquí y solo aquí; el canal de coordinación que está por debajo de este repositorio no conoce personas. Cloudy es un producto independiente y bifurcable: habla el protocolo publicado y cualquier coordinador conforme puede servirlo.

| Término de este repositorio | Rol en la arquitectura |
|---|---|
| `internal/record` | la **bitácora de diálogos por operador** — de solo adición, sellada por diálogo, atestiguada |
| `internal/covenant` | la implementación de la **escala de evaluación** (la reputación de los miembros como pacto) |
| `internal/economy` | el **crédito emitido por los miembros** (la economía de miembros) |
| `internal/coord` | el consumo del **protocolo de coordinación** del sustrato |
| `internal/enroll` | la **inscripción de frontend-como-operador** ante un coordinador (solicitud → claves → verificación → conformidad → activo) |
| Miembro | una persona, con alcance de plataforma; la PII permanece local del miembro y es borrable |

## Invariantes y sus vínculos — a la fecha de `main`

Los estados se declaran según la regla de honestidad de la arquitectura. El trabajo ya construido de la capa de miembros más allá de esto existe en la pila de PR abiertos y actualiza esta tabla a medida que se integra.

| Invariante (arquitectura) | Estado en main | Mecanismo / verificación |
|---|---|---|
| El registro es **de solo adición**; las correcciones son entradas nuevas | **Construido** | `internal/record`: Store/Log solo exponen Append — actualizar y borrar son verbos ausentes; la documentación del paquete enuncia las reglas estructurales; pruebas |
| El registro está **sellado por diálogo** — lo que dos miembros acordaron, no lo que uno afirma | **Construido** | Verificación de doble sello sobre bytes canónicos; el autodiálogo se rechaza en la construcción |
| **Nada de PII en el bien común**; la narrativa permanece local del miembro y borrable | **Construido** | Los tipos del bien común llevan solo hashes, claves e instantes; el contenido borrable vive en un almacén local del miembro con tipos disjuntos |
| **Atestiguamiento** con independencia estructural; un despliegue de un solo testigo es una suplencia etiquetada | **Construido (suplencia)** | Contrafirmas de testigos con verificación de independencia por pares; la etiqueta StandIn se calcula, no se afirma |
| Pacto: **nunca promediar**; distribución completa; simétrico; decide si, nunca cuánto | **Stub, etiquetado** | La documentación del paquete `internal/covenant` declara los invariantes innegociables que debe satisfacer cuando se construya; la implementación construida está en revisión |
| Economía: los saldos son una **función determinista del registro sellado**; suma cero; depósito de garantía primero; ganado, nunca comprado | **Stub, etiquetado** | La documentación del paquete `internal/economy` declara los invariantes; la implementación construida está en revisión |
| **Identidad única de participante** — un miembro, simultáneamente contribuyente y consumidor | Vinculante por diseño | No existe ninguna separación productor/consumidor en ningún esquema ni tipo; vincula cada superficie de miembros a medida que se integra |
| **Bifurcabilidad** | Construido | Consume el protocolo de coordinación en una etiqueta de versión publicada; ningún coordinador es privilegiado |

## Vínculos con el registro de JFA

Las pruebas que vinculan un ID del registro de invariantes de Janus (`jfa-conformance-suite.py` en NTARI-RAND/Janus) se nombran `TestInvariant_<ID>_<Name>`, escribiendo como `_` cualquier `-` del ID (así, `REC-six-holders` pasa a ser `TestInvariant_REC_six_holders_…`). `go test -run TestInvariant_ -v ./...` lista cada vínculo y su resultado.

| ID del registro | Prueba | Lo que añade más allá de las pruebas existentes del paquete |
|---|---|---|
| **L1** — cada intercambio mueve dos saldos que se compensan a cero | `internal/economy` `TestInvariant_L1_ZeroSumBalance` | Pagadores concurrentes en dos libros contables que comparten un mismo almacén; compensación por registro; la reproducción reconstruye cada saldo |
| **L6** — sin actualización en el lugar, sin borrado; la desestimación es una anotación | `internal/record` `TestInvariant_L6_AppendOnly` (mitad de la desestimación: `internal/covenant` `TestAnswersCloseTheSymmetryBreach`) | Una corrección se añade y deja intactas la entrada corregida y todas las pruebas anteriores; una reescritura en el lugar hecha directamente sobre el almacenamiento falla la verificación de consistencia frente a un checkpoint tomado antes de ella; un escaneo del código fuente de todo el módulo no encuentra ningún verbo de actualización ni de borrado en ningún tipo de solo adición — rastreados por nombre (Store/Log/Ledger/Book) o por un comentario de documentación "append-only", con `market.Catalog` y `techtree.Tree` fijados para que no puedan salir del alcance |
| **L7** — el bien común contiene solo hashes, tipos, marcas de tiempo y referencias | `internal/record` `TestInvariant_L7_CommonsSchema` | Cada tipo del bien común, campo por campo, admite solo arreglos de bytes, enteros sin signo, `time.Time` y campos `[]byte` nombrados en una lista explícita de permitidos de claves y firmas ed25519 — ningún string, map, interface, float ni `[]byte` no listado; cada campo de la lista de permitidos, rellenado con un memo, falla la verificación frente a un control sin relleno que sí la supera, y nunca entra en un log |
| **L8** — se lleva la distribución completa; ninguna puntuación escalar en ninguna parte | `internal/covenant` `TestInvariant_L8_NoScalarAggregation` | Dos miembros con medias iguales y formas distintas siguen siendo distinguibles; un escaneo del código fuente de todo el módulo en busca de funciones exportadas con nombres de puntuación o que devuelvan float, etiquetas JSON con aspecto de puntuación y campos float en los paquetes de reputación |

## Suplencias y residuos abiertos

- **Suplencia StandIn de un solo testigo.** Hoy, cada checkpoint atestiguado tiene menos de dos testigos independientes; la capa de registro calcula e informa esta etiqueta de forma estructural. La federación en vivo es el problema abierto 2 de la arquitectura — la pieza clave por construir.
- **El pacto y la economía son stubs en main.** La documentación de sus paquetes contiene los invariantes vinculantes; las implementaciones construidas están en los PR abiertos y apilados, y deben satisfacer esa documentación para integrarse.
- **El cambio de nombre de la etiqueta de dominio del registro** (nomenclatura del producto) está pendiente y debe integrarse **antes de cualquier persistencia duradera** — reetiquetar después de que existan logs duraderos sería una reescritura.
- **Los residuos nombrados del registro** (piso esteganográfico, canal encubierto de marcas de tiempo, amnesia del testigo, brecha de vivacidad) se documentan en la documentación del paquete de registro en lugar de fingir que no existen.
- **Nodo contribuyente — costura Executor construida; implementaciones de tiempo de ejecución pendientes.** `internal/contribute` fija el contrato de contribución de nodos (Executor / ServiceExecutor / Registry / NodeContract) con dos invariantes que las pruebas hacen cumplir: un nodo aprovechado solo acepta ejecutores interrumpibles (el propietario nunca es interrumpido), y una carga de trabajo Service requiere una ubicación fijada. `cmd/cloudy-agent` lo ejecuta de extremo a extremo con un ejecutor de Storage **real** (fragmentos sellados opacos + la prueba de posesión de `internal/storage`) y ejecutores de Compute/Service **provisionales**. La migración pesada del tiempo de ejecución desde el `internal/agent` transitorio del coordinador — ejecutor de Docker, muestreo de hardware con gopsutil, exclusión voluntaria/lista de permitidos/impresoras, y el relevo agent→cloudyd→`/v0` — es el siguiente paso nombrado y se integra *detrás* de esta costura sin modificarla.
- **Controlador de inscripción de operadores — construido y verificado en vivo.** `internal/enroll` + `cmd/cloudy-enroll` conducen de extremo a extremo el ciclo de vida de incorporación de operadores de un coordinador (solicitud → registro del conjunto de 7 claves → verificación por correo electrónico → suites de conformidad A/B → activación automática), reutilizando `internal/opcred` para la custodia de claves y para calcular las respuestas de conformidad a través del canon real del protocolo. La suite C se califica del lado del coordinador y no necesita respuesta del operador, por lo que no hay un paso de la suite C. El cliente está deliberadamente separado de `internal/coord`: la inscripción es JSON simple sobre la superficie de **portal** del coordinador, no sobre el canal `/v0` del lado de los nodos. El código de correo electrónico fuera de banda se suministra mediante un `CodeSource` inyectado. Verificado contra un coordinador SoHoLINK en vivo — el operador inscrito alcanzó `active` y su credencial luego se autenticó en `/v0`.

## Declaración de dependencias

Consume `sohocloud-protocol` en una etiqueta de versión publicada — nada más de la pila. Las capas de miembros referencian los intercambios sellados por un ID de hoja opaco, por valor, nunca importando tipos del registro en otras capas; la conversión ocurre solo en la raíz de composición.

## Notas específicas del producto (al final, según la regla de orden)

Cloudy se distribuye como un producto de consumo independiente (su propia API de miembros y sus superficies de aplicación, en revisión). SoHoLINK es el coordinador de referencia con el que habla; cualquier coordinador conforme puede reemplazarlo.
