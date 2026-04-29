# Trust-Transpiler

> **Universal Static Security Auditor** — Taint Analysis Sensível ao Fluxo em Rascal MPL 0.28.x

[![CI](https://github.com/your-org/trust-transpiler/actions/workflows/main_build.yml/badge.svg)](https://github.com/your-org/trust-transpiler/actions)

---

## Visão Geral

O **Trust-Transpiler** é uma ferramenta de análise estática de segurança que detecta vulnerabilidades de fluxo de dados — como **SQL Injection** e **XSS** — em código de múltiplas linguagens (PHP, JavaScript, Java, etc.), utilizando uma **Representação Intermediária Universal (UIR)** como alvo único de todos os front-ends.

A análise é realizada por um motor de **Taint Analysis Sensível ao Fluxo**, que acompanha a propagação de dados não-confiáveis desde sua entrada (*Source*) até seu uso em operações sensíveis (*Sink*), detectando ausência de higienização (*Sanitizer*) no caminho.

---

## Arquitetura

```
┌─────────────────────────────────────────────────────┐
│              Trust-Transpiler Pipeline               │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │ Front-end│    │  UIR     │    │   CFG        │  │
│  │ (PHP/JS/ │───▶│  (IR.rsc)│───▶│  Builder     │  │
│  │  Java…)  │    │          │    │  (CFG.rsc)   │  │
│  └──────────┘    └──────────┘    └──────┬───────┘  │
│                                         │           │
│                                         ▼           │
│                                  ┌──────────────┐  │
│                                  │  Gatekeeper  │  │
│                                  │ (Taint Anal.)│  │
│                                  └──────┬───────┘  │
│                                         │           │
│                                         ▼           │
│                                  ┌──────────────┐  │
│                                  │  Audit Report│  │
│                                  │  (SARIF/TXT) │  │
│                                  └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Estrutura de Pastas

```
trust-transpiler/
├── RASCAL.MF                          # Manifesto do projeto
├── README.md                          # Este arquivo
├── .github/
│   └── workflows/
│       └── main_build.yml             # Pipeline CI/CD
└── src/
    ├── lang/
    │   └── universal/
    │       └── IR.rsc                 # Representação Intermediária Universal
    ├── analysis/
    │   └── CFG.rsc                    # Construtor de CFG + Grafo de Chamadas
    ├── validation/
    │   └── Gatekeeper.rsc             # Motor de Taint Analysis
    └── pipeline/
        └── TrustTranspiler.rsc        # Orquestrador + Fixtures de demo
```

---

## Módulos

### `lang::universal::IR`

Define o conjunto de instruções agnóstico de linguagem da UIR.

#### Tipos principais

| Tipo | Descrição |
|------|-----------|
| `UIRType` | Sistema de tipos: `tInt`, `tString`, `tRef`, `tArray`, … |
| `UIRValue` | Expressões puras: variáveis, literais, operações binárias, φ-nodes SSA |
| `UIRInstr` | Instruções: `iAssign`, `iCall`, `iMethodCall`, `iJump`, `iCondJump`, `iReturn`, … |
| `SecurityTag` | **Anotações de segurança** (ver abaixo) |
| `BasicBlock` | Bloco básico: rótulo + lista de instruções + sucessores |
| `UIRProc` | Procedimento com parâmetros, tipo de retorno e blocos |
| `UIRUnit` | Unidade de compilação (arquivo) com procs e globais |

#### Anotações de Segurança (`SecurityTag`)

```
Source(category, origin, propagatesTo)
  ↳ Marca o ponto de entrada de dados não-confiáveis
    Ex: Source("HTTP_PARAM", "$_GET['id']", {"id"})

Sink(category, target, requiredSanitizers)
  ↳ Marca operações sensíveis que não devem receber dados sujos
    Ex: Sink("SQL_EXEC", "mysql_query", {"PREPARED_STMT", "INTVAL"})

Sanitizer(category, technique, cleanedVars)
  ↳ Marca operações que higienizam dados
    Ex: Sanitizer("HTTP_PARAM", "INTVAL", {"id"})

Propagation(from, to)
  ↳ Transferência implícita de taint (concatenação, atribuição, …)

Neutral()
  ↳ Sem relevância de segurança
```

---

### `analysis::CFG`

Converte uma `UIRProc` em um **Grafo de Fluxo de Controle (CFG)** explícito e constrói o **Grafo de Chamadas** para suporte interprocedural.

#### Tipos principais

| Tipo | Descrição |
|------|-----------|
| `CFGNode` | `entry`, `exit`, `instrNode(proc, block, idx, instr)` |
| `CFGEdge` | Aresta tipada: `flowEdge`, `trueEdge`, `falseEdge`, `callEdge`, `returnEdge`, `exceptionEdge` |
| `ProcCFG` | CFG de um procedimento com mapas pred/succ |
| `CallGraph` | Grafo de chamadas do programa com todos os CFGs |

#### Funções principais

```rascal
ProcCFG buildProcCFG(UIRProc p)
  // Constrói o CFG intra-procedural

CallGraph buildCallGraph(UIRUnit u)
  // Constrói o grafo de chamadas + todos os CFGs

map[CFGNode, set[CFGNode]] computeDominators(ProcCFG cfg)
  // Calcula dominadores (algoritmo iterativo)

bool isReachable(CFGNode src, CFGNode tgt, ProcCFG cfg)
  // Consulta de alcançabilidade (BFS)

str toDot(ProcCFG cfg)
  // Exporta para formato DOT (Graphviz)
```

---

### `validation::Gatekeeper`

O coração da ferramenta. Implementa **Taint Analysis Forward, Sensível ao Fluxo**, usando um ponto-fixo sobre o CFG.

#### Algoritmo

```
Para cada UIRProc p:
  1. Inicializa TaintEnv com taint dos parâmetros anotados
  2. Executa worklist algorithm (BFS sobre CFG):
     ∀ nó n, calcula:
       IN[n]  = JOIN(OUT[pred(n)])    // JOIN = união de conjuntos de taint
       OUT[n] = transfer(n, IN[n])   // transfer aplica semântica de taint
  3. Na função transfer:
     - Source  → adiciona label de taint à variável destino
     - Sanitizer → remove label de taint das variáveis limpas
     - Sink     → verifica se algum argumento carrega taint → VULN!
     - Assign/Call/Load → propagação conservadora
```

#### Tipos de vulnerabilidade detectados

| Categoria Sink | Tipo de Vuln | Severidade |
|----------------|-------------|------------|
| `SQL_EXEC` | SQL Injection | CRITICAL |
| `HTML_OUTPUT` | XSS | HIGH |
| `JS_EVAL` | XSS (eval) | CRITICAL |
| `SHELL_EXEC` | Shell Injection | CRITICAL |
| `FILE_PATH` | Path Traversal | HIGH |
| `HTTP_REDIRECT` | Open Redirect | MEDIUM |

---

### `pipeline::TrustTranspiler`

Orquestrador principal. Conecta os módulos e define **fixtures de demonstração** que modelam vulnerabilidades reais:

| Fixture | Linguagem | Vuln esperada |
|---------|-----------|---------------|
| `sqlInjectionDemo()` | PHP | SQL Injection (CRITICAL) |
| `xssDemo()` | JavaScript | XSS (HIGH) |
| `cleanSqlDemo()` | PHP | — (nenhuma, teste negativo) |
| `shellInjectionDemo()` | PHP | Shell Injection (CRITICAL) |

---

## Executando Localmente

### Pré-requisitos

- **JDK 17+** (OpenJDK ou Temurin)
- `rascal-shell-stable.jar` (baixe de `https://update.rascal-mpl.org/console/`)

### Execução

```bash
# 1. Baixar o Rascal shell
curl -fsSL https://update.rascal-mpl.org/console/rascal-shell-stable.jar \
     -o rascal-shell-stable.jar

# 2. Executar o pipeline
java -Xmx2G -Xss32m \
     -cp rascal-shell-stable.jar:src \
     org.rascalmpl.shell.RascalShell \
     pipeline::TrustTranspiler
```

### Saída esperada

```
╔══════════════════════════════════════════════════════╗
║          TRUST-TRANSPILER  v0.1.0                   ║
║   Universal Static Security Analysis (Rascal MPL)   ║
╚══════════════════════════════════════════════════════╝

[TrustTranspiler] Processing: demo_sqli.php (PHP)
═══════════════════════════════════════════════════════
  TRUST-TRANSPILER AUDIT REPORT
═══════════════════════════════════════════════════════
  File   : demo_sqli.php
  Status : ❌  VULNERABILITIES FOUND

  [1] CRITICAL — SQL Injection
      Proc   : fetchUser  Block: entry  Instr#2
      Source : HTTP_PARAM
      Sink   : mysql_query
      Via    : sql
      Detail : Unsanitised SQL_EXEC taint from [HTTP_PARAM] reaches
               `mysql_query` via `sql`. Missing sanitisers: PREPARED_STMT, INTVAL
...
```

---

## CI/CD

O workflow `.github/workflows/main_build.yml` executa três jobs:

| Job | O que faz |
|-----|-----------|
| `audit` | Instala JDK 17, baixa o Rascal JAR, executa o pipeline |
| `lint` | Valida declarações de módulo vs. caminhos de arquivo |
| `security-gate` | Falha a build se houver findings CRITICAL ou HIGH |

O relatório de auditoria é publicado como artefato GitHub Actions com retenção de 30 dias.

---

## Extensibilidade

### Adicionando um novo front-end (nova linguagem)

1. Crie um módulo `src/lang/<linguagem>/Parser.rsc` que produz `UIRUnit`
2. Anote instruções com `Source`, `Sink` e `Sanitizer` conforme o modelo de ameaças da linguagem
3. Adicione a unit ao array `units` em `pipeline::TrustTranspiler`

### Adicionando um novo tipo de sink

Edite `validation::Gatekeeper`, função `classifySink/1`:

```rascal
case "LDAP_QUERY": return <genericTaint("LDAP_INJECTION"), critical()>;
```

---

## Referências Técnicas

- [Rascal MPL — Language Reference](https://www.rascal-mpl.org/docs/)
- [OWASP Top 10 — Injection](https://owasp.org/www-project-top-ten/)
- Khedker, U. P. et al. *Data Flow Analysis: Theory and Practice*. CRC Press, 2009.
- Lhoták, O. *Program Analysis using Binary Decision Diagrams*. PhD Thesis, McGill, 2006.
