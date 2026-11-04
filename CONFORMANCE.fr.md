> Traduction communautaire (brouillon) — politique NTARI P2-002, Diffusion multilingue mondiale. Source : CONFORMANCE.md (original anglais, instantané du 2026-10-05). Brouillon communautaire assisté par machine, en attente de relecture par le mainteneur régional conformément à P2-002 §3.1. Les spécifications techniques essentielles restent en anglais conformément au §2.2.
>
> Vous avez remarqué une erreur de traduction ? N'hésitez pas à la corriger
> vous-même : forkez le dépôt https://github.com/NTARI-RAND/Cloudy et
> ouvrez une pull request. Les corrections de traduction sont des
> contributions précieuses, tout autant que le code.

> L'original anglais est normatif. Cette traduction est proposée pour la lecture, non pour l'interprétation : là où elle diverge de `CONFORMANCE.md`, l'anglais prévaut. Les mots-clés normatifs (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY), les noms de champs, les libellés et les identifiants sont conservés en anglais, car ils constituent le contrat de conformité.

# Conformité — Janus-Facing Architecture

L'autodescription du dépôt dans les termes propres à l'architecture, énoncée **avant** tout élément propre au produit, conformément à la règle d'ordonnancement de l'architecture. Chaque affirmation de conformité est rattachée au mécanisme et à la vérification qui la font respecter ; à défaut, elle est étiquetée comme substitution ou comme ébauche. Une prose non rattachée relève du marketing.

L'architecture est **Janus-Facing Architecture (JFA)** — le document d'architecture unifié de NTARI, documentation libre placée sous les communs AGPL-3.0 du projet.

## Déclaration de rôle

Cloudy est un **frontend** d'un substrat JFA — l'application destinée aux membres — et le foyer des **couches de l'économie des membres** que le protocole de coordination du substrat ne définit délibérément pas : le registre de dialogues par opérateur, le pacte de réputation et le crédit émis par les membres. Les membres existent ici et seulement ici ; le fil de coordination situé sous ce dépôt ne connaît aucune personne. Cloudy est un produit autonome et forkable : il parle le protocole publié, et tout coordinateur conforme peut le servir.

| Terme de ce dépôt | Rôle dans l'architecture |
|---|---|
| `internal/record` | le **registre de dialogues par opérateur** — en ajout seul, scellé par dialogue, attesté par témoins |
| `internal/covenant` | l'implémentation de l'**échelle d'évaluation** (la réputation des membres en tant que pacte) |
| `internal/economy` | le **crédit émis par les membres** (l'économie des membres) |
| `internal/coord` | la consommation du **protocole de coordination** du substrat |
| `internal/enroll` | l'**enrôlement du frontend en tant qu'opérateur** auprès d'un coordinateur (candidature → clés → vérification → conformité → actif) |
| Membre | une personne, rattachée à une plateforme ; les données personnelles (PII) restent locales au membre et effaçables |

## Invariants et leurs rattachements — état de `main`

Les statuts sont énoncés conformément à la règle d'honnêteté de l'architecture. Le travail déjà construit sur la couche des membres au-delà de ce qui figure ici se trouve dans la pile de PR ouvertes et met ce tableau à jour à mesure qu'il est fusionné.

| Invariant (architecture) | Statut sur main | Mécanisme / vérification |
|---|---|---|
| Le registre est **en ajout seul** ; les corrections sont de nouvelles entrées | **Construit** | `internal/record` : Store/Log n'exposent que Append — la mise à jour et la suppression sont des verbes absents ; la documentation du paquet énonce les règles structurelles ; tests |
| Le registre est **scellé par dialogue** — ce dont deux membres ont convenu, et non ce qu'un seul affirme | **Construit** | Vérification du double scellement sur les octets canoniques ; le dialogue avec soi-même est rejeté dès la construction |
| **Aucune donnée personnelle (PII) dans les communs** ; le récit reste local au membre et effaçable | **Construit** | Les types des communs ne portent que des empreintes, des clés et des instants ; le contenu effaçable réside dans un magasin local au membre, disjoint par les types |
| **Attestation par témoins** avec indépendance structurelle ; un déploiement à témoin unique est une substitution étiquetée | **Construit (substitution)** | Contresignatures des témoins avec vérification de l'indépendance deux à deux ; l'étiquette StandIn est calculée, et non affirmée |
| Pacte : **jamais de moyenne** ; distribution complète ; symétrique ; détermine si, jamais combien | **Ébauche, étiquetée** | La documentation du paquet `internal/covenant` déclare les invariants non négociables qu'il doit respecter une fois construit ; l'implémentation construite est en cours de revue |
| Économie : les soldes sont une **fonction déterministe du registre scellé** ; somme nulle ; séquestre d'abord ; gagné, jamais acheté | **Ébauche, étiquetée** | La documentation du paquet `internal/economy` déclare les invariants ; l'implémentation construite est en cours de revue |
| **Identité unique du participant** — un seul membre, à la fois contributeur et consommateur | Contraignant pour la conception | Aucune séparation producteur/consommateur n'existe dans aucun schéma ni aucun type ; s'impose à chaque surface destinée aux membres à mesure qu'elle arrive |
| **Forkabilité** | Construit | Consomme le protocole de coordination à une étiquette de version publiée ; aucun coordinateur n'est privilégié |

## Rattachements au registre JFA

Les tests qui rattachent un ID du registre des invariants de Janus (`jfa-conformance-suite.py` dans NTARI-RAND/Janus) sont nommés `TestInvariant_<ID>_<Name>`, tout `-` de l'ID étant écrit `_` (ainsi `REC-six-holders` devient `TestInvariant_REC_six_holders_…`). `go test -run TestInvariant_ -v ./...` liste chaque rattachement et son résultat.

| ID du registre | Test | Ce qu'il ajoute au-delà des tests existants du paquet |
|---|---|---|
| **L1** — chaque échange modifie deux soldes dont la somme est nulle | `internal/economy` `TestInvariant_L1_ZeroSumBalance` | Payeurs concurrents sur deux registres partageant un même magasin ; compensation par enregistrement ; la relecture reproduit chaque solde |
| **L6** — aucune mise à jour sur place, aucune suppression ; un rejet est une annotation | `internal/record` `TestInvariant_L6_AppendOnly` (volet rejet : `internal/covenant` `TestAnswersCloseTheSymmetryBreach`) | Une correction s'ajoute et laisse intactes l'entrée corrigée et toutes les preuves antérieures ; une réécriture sur place effectuée directement sur le stockage échoue au contrôle de cohérence face à un point de contrôle pris avant elle ; un balayage du code source à l'échelle du module ne trouve aucun verbe de mise à jour ou de suppression sur aucun type en ajout seul — repéré par son nom (Store/Log/Ledger/Book) ou par un commentaire de documentation « append-only », `market.Catalog` et `techtree.Tree` étant épinglés afin qu'ils ne puissent pas sortir du périmètre |
| **L7** — les communs ne contiennent que des empreintes, des types, des horodatages et des références | `internal/record` `TestInvariant_L7_CommonsSchema` | Chaque type des communs, champ par champ, n'admet que des tableaux d'octets, des entiers non signés, `time.Time` et des champs `[]byte` nommés dans une liste d'autorisation explicite de clés et de signatures ed25519 — aucun string, map, interface, float ni `[]byte` non listé ; chaque champ autorisé, complété par un mémo, échoue à la vérification face à un cas de contrôle non complété qui, lui, réussit, et n'entre jamais dans un journal |
| **L8** — distribution complète portée ; aucun score scalaire nulle part | `internal/covenant` `TestInvariant_L8_NoScalarAggregation` | Deux membres ayant des moyennes égales et des formes de distribution différentes restent distinguables ; un balayage du code source à l'échelle du module recherche les fonctions exportées nommées d'après un score ou renvoyant un float, les balises JSON évoquant un score et les champs float dans les paquets de réputation |

## Substitutions et résidus ouverts

- **Substitution StandIn à témoin unique.** Chaque point de contrôle attesté par témoins compte aujourd'hui moins de deux témoins indépendants ; la couche registre calcule et signale cette étiquette de manière structurelle. La fédération en conditions réelles est le problème ouvert 2 de l'architecture — la construction clé de voûte.
- **Le pacte et l'économie sont des ébauches sur main.** La documentation de leurs paquets porte les invariants contraignants ; les implémentations construites se trouvent dans les PR ouvertes et empilées, et doivent respecter cette documentation pour être fusionnées.
- **Le renommage de l'étiquette de domaine du registre** (nommage du produit) est en attente et doit être fusionné **avant toute persistance durable** — réétiqueter une fois que des journaux durables existent reviendrait à une réécriture.
- **Les résidus nommés du registre** (plancher stéganographique, canal caché par horodatage, amnésie des témoins, écart de vivacité) sont documentés dans la documentation du paquet registre plutôt que passés sous silence.
- **Nœud contributeur — jointure Executor construite ; implémentations d'exécution en attente.** `internal/contribute` fixe le contrat de contribution des nœuds (Executor / ServiceExecutor / Registry / NodeContract) avec deux invariants imposés par des tests : un nœud récupéré n'accepte que des exécuteurs préemptibles (le propriétaire n'est jamais interrompu), et une charge de travail Service exige un placement épinglé. `cmd/cloudy-agent` l'exécute de bout en bout avec un exécuteur Storage **réel** (fragments scellés opaques + la preuve de possession de `internal/storage`) et des exécuteurs Compute/Service **provisoires**. Le portage lourd de l'environnement d'exécution depuis le `internal/agent` transitoire du coordinateur — exécuteur Docker, échantillonnage matériel gopsutil, exclusion volontaire/liste d'autorisation/imprimantes, et le relais agent→cloudyd→`/v0` — est l'étape suivante désignée et s'insère *derrière* cette jointure sans la modifier.
- **Pilote d'enrôlement des opérateurs — construit et vérifié en conditions réelles.** `internal/enroll` + `cmd/cloudy-enroll` pilotent de bout en bout le cycle d'intégration des opérateurs d'un coordinateur (candidature → enregistrement du jeu de 7 clés → vérification par e-mail → suites de conformité A/B → activation automatique), en réutilisant `internal/opcred` pour la garde des clés et pour le calcul des réponses de conformité à travers le canon réel du protocole. La suite C est évaluée côté coordinateur et n'exige aucune réponse de l'opérateur ; il n'y a donc pas d'étape pour la suite C. Le client est délibérément séparé de `internal/coord` : l'enrôlement est du JSON simple sur la surface **portail** du coordinateur, et non sur le fil `/v0` côté nœud. Le code e-mail hors bande est fourni par une `CodeSource` injectée. Vérifié face à un coordinateur SoHoLINK en conditions réelles — l'opérateur enrôlé a atteint `active`, et son justificatif s'est ensuite authentifié sur `/v0`.

## Déclaration de dépendances

Consomme `sohocloud-protocol` à une étiquette de version publiée — rien d'autre de la pile. Les couches des membres référencent les échanges scellés par un ID de feuille opaque, par valeur, sans jamais importer les types du registre dans d'autres couches ; la conversion n'a lieu qu'à la racine de composition.

## Notes propres au produit (en dernier, conformément à la règle d'ordonnancement)

Cloudy est livré comme un produit grand public autonome (sa propre API destinée aux membres et ses propres surfaces applicatives, en cours de revue). SoHoLINK est le coordinateur de référence auquel il s'adresse ; tout coordinateur conforme peut le remplacer.
