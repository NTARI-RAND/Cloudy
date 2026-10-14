> Tradução comunitária (rascunho) — Política NTARI P2-002, Transmissão Multilíngue Global (Global Multilingual Broadcast). Fonte: CONFORMANCE.md (original em inglês, snapshot de 2026-10-05). Rascunho comunitário assistido por máquina, pendente de revisão por mantenedor regional conforme P2-002 §3.1. As especificações técnicas centrais permanecem em inglês conforme §2.2.
>
> Notou algum erro nesta tradução? Correções de tradução são contribuições
> valiosas e muito bem-vindas: faça um fork do repositório e abra um pull
> request em https://github.com/NTARI-RAND/Cloudy.

> O original em inglês é normativo. Esta tradução é oferecida para leitura, não para interpretação: onde ela divergir de `CONFORMANCE.md`, prevalece o inglês. As palavras-chave normativas (MUST, MUST NOT, SHOULD, SHOULD NOT, MAY), os nomes de campos, os rótulos e os identificadores são mantidos em inglês porque constituem o contrato de conformidade.

# Conformidade — Arquitetura de Dupla Face (Janus-Facing Architecture)

A autodescrição do repositório nos próprios termos da arquitetura, apresentada **antes** de qualquer coisa específica do produto, conforme a regra de ordenação da arquitetura. Toda alegação de conformidade está vinculada ao mecanismo e à verificação que a fazem cumprir, ou então é rotulada como provisória (stand-in) ou stub. Prosa sem vínculo é marketing.

A arquitetura é a **Arquitetura de Dupla Face (Janus-Facing Architecture, JFA)** — o documento de arquitetura unificada da NTARI, documentação livre sob o commons AGPL-3.0 do projeto.

## Declaração de papel

O Cloudy é um **frontend** de um substrato JFA — a aplicação voltada aos membros — e o lar das **camadas de economia dos membros** que o protocolo de coordenação do substrato deliberadamente não define: o registro de diálogos por operador, o pacto de reputação e o crédito emitido pelos membros. Os membros existem aqui e somente aqui; o canal de coordenação abaixo deste repositório não conhece pessoas. O Cloudy é um produto autônomo e passível de fork: ele fala o protocolo publicado, e qualquer coordenador conforme pode servi-lo.

| Termo deste repositório | Papel na arquitetura |
|---|---|
| `internal/record` | o **livro-razão de diálogos por operador** — somente de adição, selado por diálogo, testemunhado |
| `internal/covenant` | a implementação da **escala de avaliação** (reputação dos membros como pacto) |
| `internal/economy` | o **crédito emitido pelos membros** (a economia dos membros) |
| `internal/coord` | o consumo do **protocolo de coordenação** do substrato |
| `internal/enroll` | a **inscrição do frontend como operador** junto a um coordenador (apply → keys → verify → conformance → active) |
| Membro | uma pessoa, com escopo de plataforma; a PII permanece local ao membro e apagável |

## Invariantes e seus vínculos — conforme `main`

Os status são apresentados conforme a regra de honestidade da arquitetura. O trabalho já construído na camada de membros além deste existe na pilha de PRs abertos e atualiza esta tabela à medida que é integrado.

| Invariante (arquitetura) | Status em main | Mecanismo / verificação |
|---|---|---|
| O registro é **somente de adição**; correções são novas entradas | **Construído** | `internal/record`: Store/Log expõem apenas Append — atualização e exclusão são verbos ausentes; a documentação do pacote enuncia as regras estruturais; testes |
| O registro é **selado por diálogo** — o que dois membros acordaram, não o que um deles afirma | **Construído** | Verificação de selo duplo sobre bytes canônicos; o autodiálogo é rejeitado na construção |
| **Nenhuma PII no commons**; a narrativa permanece local ao membro e apagável | **Construído** | Os tipos do commons carregam apenas hashes, chaves e instantes; o conteúdo apagável vive em um armazenamento local ao membro, disjunto em tipos |
| **Testemunho** com independência estrutural; uma implantação com uma única testemunha é uma solução provisória (stand-in) rotulada | **Construído (provisório)** | Contra-assinaturas de testemunhas com verificação de independência par a par; o rótulo StandIn é computado, não afirmado |
| Pacto: **nunca fazer média**; distribuição completa; simétrico; controla o se, nunca o quanto | **Stub, rotulado** | A documentação do pacote `internal/covenant` declara as invariantes inegociáveis que ele deve satisfazer quando construído; a implementação construída está em revisão |
| Economia: saldos são uma **função determinística do registro selado**; soma zero; custódia em primeiro lugar; conquistado, nunca comprado | **Stub, rotulado** | A documentação do pacote `internal/economy` declara as invariantes; a implementação construída está em revisão |
| **Identidade única de participante** — um membro, simultaneamente contribuidor e consumidor | Vinculante por design | Não existe divisão entre produtor e consumidor em nenhum esquema ou tipo; vincula toda superfície de membro à medida que é integrada |
| **Possibilidade de fork** | Construído | Consome o protocolo de coordenação em uma tag de versão publicada; nenhum coordenador é privilegiado |

## Vínculos ao registro da JFA

Os testes que vinculam um ID do registro de invariantes do Janus (`jfa-conformance-suite.py` em NTARI-RAND/Janus) são nomeados `TestInvariant_<ID>_<Name>`, com qualquer `-` do ID escrito como `_` (assim, `REC-six-holders` torna-se `TestInvariant_REC_six_holders_…`). `go test -run TestInvariant_ -v ./...` lista cada vínculo e seu resultado.

| ID no registro | Teste | O que acrescenta além dos testes já existentes do pacote |
|---|---|---|
| **L1** — cada troca movimenta dois saldos cuja soma líquida é zero | `internal/economy` `TestInvariant_L1_ZeroSumBalance` | Pagadores concorrentes em dois livros-razão que compartilham um mesmo armazenamento; compensação por registro; a reexecução reproduz cada saldo |
| **L6** — nenhuma atualização no lugar, nenhuma exclusão; o arquivamento é anotação | `internal/record` `TestInvariant_L6_AppendOnly` (metade do arquivamento: `internal/covenant` `TestAnswersCloseTheSymmetryBreach`) | Uma correção é adicionada e deixa intactas a entrada corrigida e todas as provas anteriores; uma reescrita no lugar feita diretamente no armazenamento falha na verificação de consistência contra um checkpoint tomado antes dela; uma varredura do código-fonte de todo o módulo não encontra nenhum verbo de atualização ou exclusão em nenhum tipo somente de adição — rastreado pelo nome (Store/Log/Ledger/Book) ou por um comentário de documentação "append-only", com `market.Catalog` e `techtree.Tree` fixados para que não possam sair do escopo |
| **L7** — o commons guarda apenas hashes, tipos, carimbos de tempo e referências | `internal/record` `TestInvariant_L7_CommonsSchema` | Todo tipo do commons, campo por campo, admite apenas arrays de bytes, inteiros sem sinal, `time.Time` e campos `[]byte` nomeados em uma lista de permissões explícita de chaves e assinaturas ed25519 — nenhum campo string, map, interface, float ou `[]byte` não listado; todo campo da lista de permissões, preenchido com um memorando, falha na verificação contra um controle sem preenchimento que passa, e nunca entra em um log |
| **L8** — a distribuição completa é mantida; nenhuma pontuação escalar em lugar algum | `internal/covenant` `TestInvariant_L8_NoScalarAggregation` | Dois membros com médias iguais e formas diferentes permanecem distinguíveis; uma varredura do código-fonte de todo o módulo em busca de funções exportadas com nome de pontuação ou que retornam float, tags JSON semelhantes a pontuação e campos float nos pacotes de reputação |

## Soluções provisórias e resíduos em aberto

- **StandIn de testemunha única.** Todo checkpoint testemunhado hoje tem menos de duas testemunhas independentes; a camada de registro computa e reporta esse rótulo estruturalmente. A federação ao vivo é o problema em aberto 2 da arquitetura — a construção central.
- **Pacto e economia são stubs em main.** A documentação de seus pacotes carrega as invariantes vinculantes; as implementações construídas estão nos PRs abertos e empilhados e devem satisfazer essa documentação para serem integradas.
- **Renomeação da domain-tag do registro** (nomenclatura do produto) está pendente e deve ser integrada **antes de qualquer persistência durável** — reetiquetar depois que existirem logs duráveis seria uma reescrita.
- **Resíduos nomeados do registro** (piso esteganográfico, canal encoberto de carimbo de tempo, amnésia de testemunha, lacuna de vivacidade) são documentados na documentação do pacote de registro, em vez de serem ignorados como se não existissem.
- **Nó contribuidor — interface Executor construída; implementações de runtime pendentes.** `internal/contribute` fixa o contrato de contribuição de nós (Executor / ServiceExecutor / Registry / NodeContract) com duas invariantes impostas por testes: um nó aproveitado aceita apenas executores preemptíveis (o proprietário nunca é interrompido), e uma carga de trabalho Service exige posicionamento fixado. `cmd/cloudy-agent` executa isso de ponta a ponta com um executor Storage **real** (fragmentos selados opacos + a prova de posse de `internal/storage`) e executores Compute/Service **provisórios** (placeholder). A portabilidade pesada de runtime a partir do `internal/agent` transitório do coordenador — executor Docker, amostragem de hardware com gopsutil, opt-out/allowlist/impressoras e o relay agent→cloudyd→`/v0` — é o próximo passo nomeado e será integrada *por trás* dessa interface sem alterá-la.
- **Driver de inscrição de operadores — construído e verificado ao vivo.** `internal/enroll` + `cmd/cloudy-enroll` conduzem de ponta a ponta o ciclo de vida de integração de operadores de um coordenador (apply → registro do conjunto de 7 chaves → verificação por e-mail → conjuntos de conformidade A/B → ativação automática), reutilizando `internal/opcred` para a custódia de chaves e para computar as respostas de conformidade por meio do cânone real do protocolo. O conjunto C é avaliado do lado do coordenador e não precisa de resposta do operador, portanto não há etapa do conjunto C. O cliente é deliberadamente separado de `internal/coord`: a inscrição é JSON simples na superfície de **portal** do coordenador, não no canal `/v0` do lado dos nós. O código de e-mail fora de banda é fornecido por meio de um `CodeSource` injetado. Verificado contra um coordenador SoHoLINK ao vivo — o operador inscrito alcançou `active` e sua credencial então se autenticou em `/v0`.

## Declaração de dependências

Consome `sohocloud-protocol` em uma tag de versão publicada — nada mais da pilha. As camadas de membros referenciam trocas seladas por ID de folha opaco, por valor, nunca importando tipos de registro para outras camadas; a conversão ocorre apenas na raiz de composição.

## Notas específicas do produto (por último, conforme a regra de ordenação)

O Cloudy é distribuído como um produto de consumo autônomo (com sua própria API de membros e superfícies de aplicativo, em revisão). O SoHoLINK é o coordenador de referência com o qual ele se comunica; qualquer coordenador conforme pode substituí-lo.
