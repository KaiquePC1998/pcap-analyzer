# PCAP Analyzer — Manual rápido

Analisador de tráfego (PCAP) para analistas de segurança em **NetSec / proteção DDoS**.
Funciona 100% no navegador: seus arquivos **não são enviados para nenhum servidor**.

---

## O fluxo em 6 passos

```
1. Carregar capturas → 2. Triagem → 3. DDoS (vetor + parecer) → 4. Origem do prefixo
                                      ↓                                        ↓
              5. Salvar caso no Histórico  ←  6. Relatório do Cliente (.MD / PDF)
```

---

## 1. Carregar as capturas

- **Adicionar PCAP** (canto superior direito): seleciona um ou vários `.pcap` / `.pcapng` / `.cap`.
- **Demo Multi-PCAP**: carrega 4 capturas de exemplo para você explorar sem arquivo próprio.
- O seletor ao lado do título escolhe **qual captura analisar** ou "Todos os Arquivos".
  > 💡 Ao trocar o arquivo selecionado, Triagem e DDoS passam a considerar só aquela captura.

## 2. Triagem — "tem algo estranho?" (Nível 1)

Menu → **Triagem**. Responde rápido: pico de pps/bps, alvo mais atingido, número de origens, TTL e tamanhos.

- Cada **sinal** tem nível: crítico, alerta, info. Ex.: *"Pico de 3,1k pps, 1040× acima da mediana"*.
- **Botões do topo:**
  - *Copiar resumo p/ ticket* — texto pronto para o chamado.
  - *Classificar & mitigar →* — leva o alvo principal direto para a aba DDoS.
  - *Salvar caso* — arquiva a análise no Histórico.

> **Exemplo de leitura:** pico 100× acima da mediana + 99% dos pacotes com 42 bytes = ferramenta de flood. Já "pico 2× a mediana, dentro do baseline do cliente" = provável demanda legítima.

## 3. DDoS — classificação e parecer (Nível 2)

Menu → **DDoS**. Para o alvo selecionado, a ferramenta identifica o **vetor** (SYN Flood, UDP Flood, amplificação DNS/NTP/memcached…), mostra os indicadores e a **Mitigação** por características (quando origem é forjada) ou por IP (quando origens são reais).

- **Parecer com contexto**: considera o Perfil de Rede e conclui:
  - ✅ *Compatível com tráfego normal* — não mitigue, registre.
  - ⚠️ *Suspeito* — colete mais contexto antes de mitigar (evita falso positivo).
  - 🚨 *Ataque consistente* — prossiga, com a conduta recomendada (AED / Sightline / TMS).

> **Exemplo:** cliente com DNS (53) e HTTPS (443) expostos, pico na 53 dentro do baseline → parecer "compatível". Mesmo pico com 1 fluxo novo por pacote → "ataque consistente".

## 4. BGP & Mitigação — onde mitigar

Menu → **BGP & Mitigação** → painel **Origem do Prefixo**.

Digite o IP/prefixo do alvo e clique **Consultar RIPEstat**:

| Resultado | O que fazer |
|---|---|
| **Anunciado pela SUA operadora** (verde) | O transbordo passa por vocês: atue no **TMS/Sightline** — filtro do vetor por características do tráfego; FlowSpec/RTBH conforme política. |
| **Anunciado por TERCEIROS** (amarelo) | Sua mitigação **não afeta o caminho** — o tráfego entra pelo AS anunciante. Acione a operadora que anuncia ou corrija a rota na origem. |

> **Exemplo:** alvo 200.160.0.20 anunciado pela NIC.BR (AS22548) e você opera o AS26250 → não adianta filtrar no seu TMS; o chamado é para a operadora anunciante.

## 5. Perfil de Rede — contexto do cliente

Menu → **Perfil de Rede**. Preencha **uma vez por cliente**:

- **ASN da sua operadora** (onde você opera o TMS) e os **blocos do cliente + quem anuncia cada um**;
- **Serviços expostos** (ex.: `53 DNS, 443 HTTPS`) — evita chamar serviço legítimo de ataque;
- **Baseline** (pps médio e pico) — use **"Aprender baseline da captura selecionada"** com uma captura de dia normal;
- **Cenário do cliente:**
  - *AS direcionado à operadora* — cliente com link e proteção DDoS; o transbordo passa por vocês e a atuação é no **TMS**;
  - *Usa bloco da operadora (sem AS)* — a atuação é **apenas a mitigação no TMS**, sem dependência do cliente;
- **AED gerenciado por você** (quando houver): o AED faz o primeiro scrub na borda e, ao **estourar a banda de mitigação**, o **Cloud Signaling manda o transbordo para o TMS** da operadora.

É esse contexto que produz o parecer "ataque ou não" e a conduta correta no TMS.

## 6. Relatórios e histórico

- **Relatório do Cliente** (barra lateral): resumo executivo com índice de conformidade, Triagem, Classificação DDoS e Parecer com contexto. Copiar / **Baixar .MD** / **Baixar PDF**.
- **Dashboard**: KPIs (pico pps, banda, sinais) e **Comparação Baseline × Evento** — escolha as duas capturas e apresente o Δ (ex.: pico 623× maior no evento) pronto para o laudo.
- **Histórico**: cada caso salvo fica arquivado com veredito, vetores, pico e suas notas — reconheça padrões recorrentes e exporte tudo em JSON.
- **Regras Firewall**: gera bloqueios automáticos a partir das ameaças.
- **Checklist de Coleta**: guia pronto (comandos `tcpdump` inclusos) para enviar ao cliente e a captura virar prova.

---

## Exemplo prático (5 minutos)

1. Cliente reclama de lentidão às 14h. Peça uma captura (use o **Checklist de Coleta**).
2. **Adicionar PCAP** → seletor no arquivo do evento → **Triagem**: pico 3,1k pps, 1040× a mediana, 99% dos pacotes com 42 bytes → sinal de alerta.
3. **Classificar & mitigar →** → aba **DDoS**: vetor UDP Flood (porta fixa) + parecer **"Ataque consistente"**, conduta: AED faz o primeiro scrub e, estourando a banda, Cloud Signaling manda o transbordo ao TMS — prepare o filtro do vetor lá.
4. **BGP & Mitigação** → Origem do Prefixo: "anunciado pela SUA operadora" → atuação direta no TMS.
5. **Salvar caso** no Histórico → **Relatório do Cliente** → **Baixar PDF** e anexar ao chamado.

---

## Dicas rápidas

- **Sem conexão?** A análise funciona offline; só as consultas de enriquecimento (geo/reputação/RIPEstat) precisam de internet — e elas são **cacheadas** (repetir a mesma consulta não gera chamada nova).
- **Captura estranha?** Se o cliente capturou depois do scrubbing ou só um sentido, o tráfego pode "parecer" ataque. Compare com um baseline do mesmo ponto.
- **Nada apareceu?** A aba Pacotes fica vazia sem arquivos carregados — carregue um PCAP ou use a demo.

---

*PCAP Analyzer v6 · NetSec / Proteção DDoS*
