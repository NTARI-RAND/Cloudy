> Traduction communautaire (brouillon) — politique NTARI P2-002, Diffusion
> multilingue mondiale. Source : README.md (original anglais, instantané du
> 2026-07-29). Brouillon communautaire assisté par machine, en attente de
> relecture par le mainteneur régional conformément au P2-002 §3.1. Les
> spécifications techniques de base restent en anglais conformément au §2.2.
>
> Vous avez remarqué une erreur de traduction ? N'hésitez pas à la corriger
> vous-même : forkez le dépôt https://github.com/NTARI-RAND/Cloudy et ouvrez
> une pull request. Les corrections de traduction sont des contributions
> précieuses, tout autant que le code.

# Cloudy

Un frontend du réseau de coordination SoHoLINK / sohocloud. Cloudy est l'endroit
où les membres effectuent leurs transactions ; il consomme la coordination du
substrat via le module partagé `sohocloud-protocol` et possède, par-dessus, sa
propre économie des membres JFA.

## État (en toute honnêteté)

Les trois couches de l'économie des membres JFA que Cloudy possède — et que le
protocole, délibérément, ne possède pas — sont désormais **construites, avec
tests**. Il n'existe encore ni boucle de coordination active, ni surface
visible par les membres.

- **`internal/record` — construit.** Registre scellé par dialogue, en ajout
  seul (append-only) et attesté par témoins : chaque Entry porte les sceaux des
  deux membres sur des octets canoniques à séparation de domaine, de sorte
  qu'un covenant à moitié scellé ou conclu avec soi-même ne peut jamais entrer
  dans un journal ; les journaux chaînés par hachage, propres à chaque
  opérateur, sont entièrement revérifiés lors de `OpenLog` ; les points de
  contrôle de l'opérateur, associés aux contresignatures de témoins
  indépendants, rendent cryptographiquement détectable toute réécriture de
  l'historique déjà pointé (le découpage de type CT), et un déploiement à
  témoin unique est explicitement désigné pour ce qu'il est : une solution
  provisoire. Aucune forme de données personnelles identifiantes (PII)
  n'existe dans les communs — le contenu identifiant ne vit que dans le
  Locker effaçable, local au membre. `Entry.ID()`, le hachage de feuille, est
  la seule référence d'échange entre les couches.
- **`internal/economy` — construit.** Crédit mutuel souverain, propre à chaque
  plateforme : le crédit est émis au moment de la dépense, dans les limites
  d'un plafond de débit unique, uniforme et gouverné, et la somme de tous les
  soldes est toujours exactement nulle. Aucune frappe monétaire, aucun champ
  fiat, aucun remboursement ni aucun mémo n'est représentable ; le passage
  « séquestre immédiat / crédit différé » se réduit à un seul PolicyChange
  signé par quorum sur le même stockage en ajout seul ; `Open` rejoue et
  revérifie intégralement chaque enregistrement. `Spend.ExchangeHash` porte
  l'identifiant de feuille de l'entrée du registre, mais reste délibérément
  opaque et non vérifié au niveau de Post — l'ancrage relève de la racine de
  composition.
- **`internal/covenant` — construit.** Réputation sur l'échelle d'évaluation
  des échanges fondée sur Leveson (Leveson-Based Trade Assessment Scale,
  LBTAS) de NTARI : six niveaux porteurs de sens, de -1 Aucune confiance
  (No Trust) à +4 Enchantement (Delight), bidirectionnels (les deux parties à
  un échange scellé s'évaluent mutuellement), rendus par catégorie sur un
  vocabulaire fermé (par défaut : reliability, usability, performance,
  support), et lus uniquement sous forme de distributions complètes du nombre
  d'évaluations par niveau — par catégorie, agrégées globalement, plus un
  compte des préjudices qui fait remonter chaque -1 — **jamais sous forme de
  moyenne**, sans aucun score, export, amendement, rétractation ni comparaison
  entre membres où que ce soit (deux tests garde-fous — un scan de l'ensemble
  des méthodes par réflexion et un scan des fonctions exportées via go/ast —
  veillent à ce que cela reste ainsi). Un verdict à -1 exige un commentaire
  justificatif ; le texte du commentaire vit dans le Locker effaçable, local au
  membre, tandis que seul son hachage circule dans les communs. Chaque
  évaluation est signée par son auteur et tarifée à un échange scellé via la
  barrière Anchors ; les identifiants de membre sont des hachages de clés
  limités à une plateforme, et les identifiants choisis par des humains sont
  rejetés d'emblée. La spécification contraignante et l'implémentation de
  référence se trouvent dans
  `Development/Covenant/Leveson-Based-Trade-Assessment-Scale`.
- **Réel mais minimal :** `internal/coord` — un client léger au-dessus du
  transport de référence HTTP+JSON du protocole, qui démontre que Cloudy
  consomme bien `sohocloud-protocol`. `cmd/cloudy` le construit et signale le
  démarrage ; il n'y a pas encore de boucle de coordination active.

`cmd/cloudy` construit désormais les trois couches en mémoire au démarrage
(genèse ModeEscrow, journal d'opérateur vide, livre de covenants vide au-dessus
d'un annuaire des membres partagé et vide) et journalise une ligne honnête par
couche. Chaque paquet nomme ses invariants non négociables dans sa
documentation de paquet.

## Ce que Cloudy possède (architecture)

Dans l'architecture retenue, Cloudy — le frontend — possède tout le monde du
membre. Trois capacités, un seul propriétaire :

- **L'économie des membres JFA — construite.** `internal/economy` (crédit émis
  par les membres), `internal/covenant` (réputation LBTAS), `internal/record`
  (registre scellé par dialogue), exactement comme décrit ci-dessus. Ces
  éléments appartiennent à Cloudy et délibérément pas au protocole : les
  personnes n'apparaissent jamais sur le fil.
- **L'agent de nœud — propriété de Cloudy, actuellement hébergé dans le dépôt
  du coordinateur en attendant sa migration.** Détection du matériel, profils
  de ressources, génération des listes de capacités, heartbeat, exécuteur de
  tâches, application locale du retrait (opt-out) et des listes d'autorisation
  (allowlist), télémétrie, et installateur pour les machines des membres. Ce
  code (`internal/agent`, `cmd/agent` et l'installateur MSI) vit aujourd'hui
  dans le dépôt SoHoLINK et continue d'y fonctionner — un vestige de l'époque
  où SoHoLINK était à la fois frontend et coordinateur, et non son rôle à long
  terme. L'agent est la présence du membre sur sa propre machine : il
  appartient donc au frontend ; un coordinateur qui livre des agents sur le
  matériel des membres est un coordinateur qui touche au matériel des membres,
  ce que SoHoLINK ne doit jamais faire.
- **Le portail des membres — propriété de Cloudy, actuellement hébergé dans le
  dépôt du coordinateur en attendant sa migration.** Inscription, connexion,
  tableau de bord, soumission de tâches et retrait (opt-out). La surface
  autrefois appelée « portail des participants » (`internal/portal`,
  `cmd/portal`, `web/` dans le dépôt SoHoLINK) devient désormais le portail des
  membres de Cloudy — l'identité du membre est une affaire de frontend, donc la
  porte que franchissent les membres doit être celle du frontend.

L'agent de nœud et le portail des membres sont les prochains jalons de
développement, maintenant que les trois couches sont complètes en tant que
bibliothèques. Comme l'indique honnêtement l'état ci-dessus : ni l'un ni
l'autre ne dispose encore d'un point d'entrée ici, et rien dans ce dépôt ne
prétend que la migration a déjà eu lieu.

### Glossaire

- **Membre** — une personne, toujours relative à un frontend/plateforme.
  L'identité (MemberID limité à une plateforme), le crédit, la position LBTAS,
  les enregistrements scellés, les PII (effaçables, locales au membre) et les
  machines contribuées sont des faits d'adhésion. L'adhésion relève du langage
  du covenant — une obligation mutuelle envers une plateforme particulière ; le
  même être humain est un membre différent sur chaque plateforme, par
  construction cryptographique.
- **Participant** — un rôle, non une entité : un membre agissant dans
  l'économie coordonnée, contribuant des nœuds et/ou soumettant des tâches —
  une identité unifiée, jamais scindée entre producteur et consommateur. Les
  enregistrements de personnes côté coordinateur (la table des participants de
  SoHoLINK et les comptes du portail) sont des surfaces transitoires héritées
  de l'époque duale.
- **Nœud** — une machine qu'un membre contribue, identifiée par un NodeID avec
  la liaison SPIFFE `/node/<id>` (le paquet `identity/` du protocole).

### Identité face au coordinateur

Deux identités traversent la frontière frontend/coordinateur, et elles ne
doivent pas être confondues. Les machines des membres portent une **identité de
charge de travail** : un SVID SPIFFE sous `/node/<id>`, autorisé côté
coordinateur exactement selon le SPEC du protocole — identité machine,
inchangée. Cloudy lui-même s'authentifie comme **opérateur** enrôlé : le modèle
frontend-en-tant-qu'opérateur, une **cible de conception** calquée sur le
schéma d'opérateurs de la Phase 5 d'Agrinet (un registre operators +
operator-keys ; un jeu rotatif de sept clés Ed25519, chaque transmission étant
signée par deux d'entre elles ; le rejeu borné par une fenêtre d'horodatage et
un cache de nonces — voir
`Development/Economy/Agrinet backend/lib/operatorKeys.js` et
`backend/middleware/operatorAuth.js`). La rotation est le point essentiel : une
clé partagée statique, jamais renouvelée, est précisément l'anti-pattern contre
l'héritage duquel la référence met en garde. Aucune de ces deux identités n'est
jamais une personne : l'identité du membre reste à l'intérieur de Cloudy.

## Invariant du graphe d'imports

Cloudy importe `sohocloud-protocol` ; **rien n'importe Cloudy**. Cloudy dépend
du cœur du protocole et de son transport de référence, et ne contourne ni l'un
ni l'autre. C'est la direction de la dépendance qui garde le frontend et le
coordinateur séparables : un frontend peut être remplacé sans toucher au
substrat, et le substrat ne connaît aucun frontend en particulier.

À l'intérieur de Cloudy, les trois paquets JFA ne s'importent jamais entre eux ;
chacun ne voit que la bibliothèque standard et le paquet `canon` du protocole,
et tous les imports restent unidirectionnels. Ils ne se rencontrent qu'à la
racine de composition : `test/composition` est le seul test de racine de
composition — l'annuaire des membres unique et partagé, le prédicat Anchors qui
relie covenant à record via `Entry.ID()`, et l'histoire complète d'un membre y
vivent — et `cmd/cloudy` effectue la même composition au démarrage.

## Compilation

Le module du protocole est actuellement privé et sans tag. Ce squelette le
résout via une directive `replace` pointant vers une **copie locale voisine** :

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

`sohocloud-protocol` doit donc être cloné à côté de `Cloudy` (tous deux sous le
même répertoire parent). Ce `replace` est une commodité de développement
local — il n'est pas compilable en l'état par d'autres personnes. Publier Cloudy
pour une compilation externe exigera de taguer le module du protocole (ou de
mettre en place `GOPRIVATE` + une récupération authentifiée) et de supprimer le
`replace`.

```
go build ./...
go test ./...
```

## Licence

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
