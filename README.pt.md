> Tradução comunitária (rascunho) — política P2-002 da NTARI, Transmissão Multilíngue Global. Fonte: README.md (original em inglês, snapshot de 2026-07-29). Rascunho comunitário assistido por máquina, pendente de revisão do mantenedor regional conforme P2-002 §3.1. As especificações técnicas centrais permanecem em inglês conforme §2.2.
>
> Notou algum erro nesta tradução? Correções de tradução são contribuições
> valiosas e muito bem-vindas: faça um fork do repositório e abra um pull
> request em https://github.com/NTARI-RAND/Cloudy.

# Cloudy

Um frontend na rede de coordenação SoHoLINK / sohocloud. O Cloudy é onde os
membros transacionam; ele consome a coordenação do substrato através do módulo
compartilhado `sohocloud-protocol` e, por cima disso, é dono da sua própria
economia de membros JFA.

## Status (honesto)

As três camadas da economia de membros JFA que pertencem ao Cloudy — e que o
protocolo deliberadamente não possui — estão agora **construídas, com testes**.
Ainda não existe loop de coordenação ativo nem superfície voltada ao membro.

- **`internal/record` — construído.** Registro selado em diálogo, somente de
  anexação (append-only) e testemunhado: cada Entry carrega os selos de ambos
  os membros sobre bytes canônicos e separados por domínio, de modo que um
  pacto meio-selado ou autonegociado nunca pode entrar em um log; os logs
  encadeados por hash de cada operador são reverificados integralmente em
  `OpenLog`; checkpoints do operador mais contra-assinaturas de testemunhas
  independentes tornam criptograficamente detectável qualquer reescrita do
  histórico já submetido a checkpoint (a fatoração CT), e uma implantação com
  uma única testemunha é rotulada como o substituto provisório que ela é.
  Nenhuma forma de PII existe no commons — o conteúdo identificador vive
  apenas no Locker apagável e local ao membro. `Entry.ID()`, o hash da folha,
  é a única referência de troca entre camadas.
- **`internal/economy` — construído.** Crédito mútuo soberano por plataforma:
  o crédito é emitido no momento do gasto, dentro de um único limite de débito
  uniforme e governado, e a soma de todos os saldos é sempre exatamente zero.
  Não há como representar cunhagem, campo fiat, resgate ou memo;
  escrow-agora/crédito-depois é exatamente um PolicyChange assinado por quórum
  no mesmo armazenamento somente de anexação; `Open` reexecuta e reverifica
  integralmente cada registro. `Spend.ExchangeHash` carrega o ID da folha da
  entrada de registro, mas é deliberadamente opaco e não verificado em Post —
  a ancoragem é uma questão da raiz de composição.
- **`internal/covenant` — construído.** Reputação na Leveson-Based Trade
  Assessment Scale (LBTAS) da NTARI: seis níveis carregados de significado,
  de -1 No Trust (Nenhuma Confiança) a +4 Delight (Encantamento),
  bidirecional (ambas as partes de uma troca selada avaliam uma à outra),
  expressa por categoria sobre um vocabulário fechado (padrões: reliability,
  usability, performance, support) e lida apenas como distribuições completas
  de contagem por nível — por categoria, agrupada no geral, e uma contagem de
  dano que expõe cada -1 — **nunca em média**, sem nenhuma pontuação,
  exportação, emenda, retratação ou comparação entre membros em lugar algum
  (dois testes sentinela — uma varredura do conjunto de métodos por reflexão e
  uma varredura de funções exportadas com go/ast — mantêm as coisas assim).
  Um veredito -1 exige um comentário justificando; o texto do comentário vive
  no Locker apagável e local ao membro, enquanto apenas o seu hash trafega no
  commons. Toda avaliação é assinada pelo avaliador e custa exatamente uma
  troca selada, através do portão Anchors; os IDs de membro são hashes de
  chave com escopo de plataforma, e IDs escolhidos por humanos são rejeitados
  de imediato. A especificação vinculante e a implementação de referência
  vivem em `Development/Covenant/Leveson-Based-Trade-Assessment-Scale`.
- **Real, mas enxuto:** `internal/coord` — um cliente fino sobre o transporte
  HTTP+JSON de referência do protocolo, provando que o Cloudy consome
  `sohocloud-protocol`. `cmd/cloudy` o constrói e informa a inicialização;
  ainda não há loop de coordenação ativo.

`cmd/cloudy` agora constrói as três camadas em memória na inicialização
(gênese em ModeEscrow, log de operador vazio, livro de pactos vazio sobre um
diretório de membros compartilhado vazio) e registra uma linha honesta por
camada. Cada pacote nomeia seus invariantes não negociáveis na documentação do
próprio pacote.

## O que pertence ao Cloudy (arquitetura)

Sob a arquitetura já resolvida, o Cloudy — o frontend — é dono de todo o mundo
do membro. Três capacidades, um só dono:

- **A economia de membros JFA — construída.** `internal/economy` (crédito
  emitido pelo membro), `internal/covenant` (reputação LBTAS),
  `internal/record` (registro selado em diálogo), exatamente como documentado
  acima. Essas camadas são do Cloudy e deliberadamente não do protocolo:
  pessoas nunca trafegam pela rede.
- **O agente de nó — pertence ao Cloudy, hoje hospedado no repositório do
  coordenador, aguardando migração.** Detecção de hardware, perfis de
  recursos, geração da listagem de capacidades, heartbeat, o executor de jobs,
  a aplicação local de opt-out/allowlist, telemetria e o instalador para a
  máquina do membro. Esse código (`internal/agent`, `cmd/agent` e o instalador
  MSI) vive hoje no repositório do SoHoLINK e continua funcionando lá — um
  resquício da era dupla frontend+coordenador do SoHoLINK, não o papel de
  longo prazo do SoHoLINK. O agente é a presença do membro na própria máquina,
  logo ele pertence ao frontend; um coordenador que distribui agentes para o
  hardware dos membros é um coordenador que toca o hardware dos membros, o que
  o SoHoLINK nunca deve fazer.
- **O portal do membro — pertence ao Cloudy, hoje hospedado no repositório do
  coordenador, aguardando migração.** Cadastro, login, dashboard, submissão de
  jobs e opt-out. A superfície antes chamada de "portal do participante"
  (`internal/portal`, `cmd/portal`, `web/` no repositório do SoHoLINK) é, de
  agora em diante, o portal do membro do Cloudy — a identidade do membro é uma
  questão do frontend, então a porta pela qual os membros entram tem de ser a
  porta do frontend.

O agente de nó e o portal do membro são os próximos marcos de construção,
agora que as três camadas estão completas como biblioteca. Como o status acima
diz honestamente: nenhum dos dois tem ponto de entrada aqui ainda, e nada
neste repositório finge que a migração já aconteceu.

### Glossário

- **Membro** — uma pessoa, sempre relativa a um frontend/plataforma.
  Identidade (MemberID com escopo de plataforma), crédito, situação na LBTAS,
  registros selados, PII (apagável, local ao membro) e máquinas contribuídas
  são fatos de associação. Associação é linguagem de pacto — obrigação mútua
  com uma plataforma específica; o mesmo ser humano é um membro diferente em
  cada plataforma, por construção criptográfica.
- **Participante** — um papel, não uma entidade: um membro atuando na economia
  coordenada, contribuindo com nós e/ou submetendo jobs — uma identidade
  unificada, nunca dividida entre produtor e consumidor. Os registros de
  pessoas do lado do coordenador (a tabela participants do SoHoLINK e as
  contas do portal) são superfícies transitórias da era dupla.
- **Nó** — uma máquina que um membro contribui, identificada por NodeID com a
  vinculação SPIFFE `/node/<id>` (o pacote `identity/` do protocolo).

### Identidade em direção ao coordenador

Duas identidades cruzam a fronteira frontend/coordenador, e elas não podem ser
confundidas. As máquinas dos membros portam **identidade de carga de trabalho**
(workload identity): um SVID SPIFFE sob `/node/<id>`, autorizado do lado do
coordenador exatamente conforme o SPEC do protocolo — identidade de máquina,
sem alteração. O próprio Cloudy se autentica como um **operador** inscrito: o
modelo frontend-como-operador, um **alvo de projeto** moldado no esquema de
operadores da Fase 5 do Agrinet (um registro de operators + operator-keys; um
conjunto rotativo de sete chaves Ed25519, com cada transmissão assinada por
duas; replay limitado por uma janela de timestamp mais um cache de nonces —
veja `Development/Economy/Agrinet backend/lib/operatorKeys.js` e
`backend/middleware/operatorAuth.js`). A rotação é justamente o ponto: uma
chave compartilhada estática, nunca rotacionada, é exatamente o antipadrão que
a referência alerta para não herdar. Nenhuma das duas identidades é jamais uma
pessoa: a identidade do membro permanece dentro do Cloudy.

## Invariante do grafo de importações

O Cloudy importa `sohocloud-protocol`; **nada importa o Cloudy**. O Cloudy
depende do núcleo do protocolo e do seu transporte de referência, e não
contorna nenhum dos dois. A direção da dependência é o que mantém o frontend e
o coordenador separáveis: um frontend pode ser substituído sem tocar no
substrato, e o substrato não conhece nenhum frontend em particular.

Dentro do Cloudy, os três pacotes JFA nunca importam uns aos outros; cada um vê
apenas a biblioteca padrão e o pacote `canon` do protocolo, e todas as
importações permanecem unidirecionais. Eles se encontram somente na raiz de
composição: `test/composition` é o único teste de raiz de composição — o
diretório de membros compartilhado único, o predicado Anchors que liga
covenant a record por `Entry.ID()`, e a história completa do membro vivem lá —
e `cmd/cloudy` realiza a mesma composição na inicialização.

## Compilando

O módulo do protocolo é, no momento, privado e sem tags. Este esqueleto o
resolve por meio de uma diretiva `replace` que aponta para um **checkout local
irmão**:

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

Portanto, `sohocloud-protocol` precisa ser clonado ao lado de `Cloudy` (ambos
sob o mesmo diretório pai). Esse `replace` é uma conveniência de
desenvolvimento local — como está, não é compilável por terceiros. Publicar o
Cloudy para compilação externa exigirá criar uma tag do módulo do protocolo
(ou uma configuração de `GOPRIVATE` + fetch autenticado) e remover o
`replace`.

```
go build ./...
go test ./...
```

## Licença

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
