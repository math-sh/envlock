# envlock

Criptografa arquivos (`.env`, chaves, qualquer coisa) com **senha + pepper**, para você poder
mandar o arquivo por WhatsApp, Discord, e-mail ou pendrive sem entregar o conteúdo junto.

Tudo roda na sua máquina. Não existe servidor, conta, nuvem ou telemetria — a única porta de rede
que o envlock abre é em `127.0.0.1`, para desenhar a janela, e ela desliga sozinha.

```bash
npm install -g envlock
envlock install          # associa .envlock ao duplo clique (opcional)
```

## Uso

```bash
envlock lock .env --label prod-api     # gera .env.envlock — pede senha e pepper
# ...manda o .env.envlock pelo canal que quiser...
envlock unlock .env.envlock            # na outra máquina, pede senha e pepper
```

Com `envlock install`, dar **duplo clique** num `.envlock` abre uma janela com os dois campos e
grava o arquivo original na mesma pasta. `envlock gui` abre a mesma janela com arraste-e-solte.

| Comando | O que faz |
|---|---|
| `envlock lock <arquivo>` | criptografa; `--label` marca o arquivo, `-o` escolhe a saída |
| `envlock unlock <arquivo.envlock>` | descriptografa e restaura o nome original |
| `envlock info <arquivo.envlock>` | mostra rótulo e parâmetros, sem pedir senha |
| `envlock open [arquivo]` / `gui` | abre a janela gráfica local |
| `envlock install` / `uninstall` | liga/desliga o duplo clique (Linux e Windows) |

Nenhum comando aceita segredo por argumento: isso apareceria no `ps` e no histórico do shell. Em
CI, use `ENVLOCK_PASSWORD` e `ENVLOCK_PEPPER`.

## Senha, pepper e salt

```
chave = scrypt( HMAC-SHA256(chave=pepper, mensagem=senha), salt )
```

- **Senha** e **pepper** são os dois segredos. Os dois são digitados nas duas pontas e podem ser
  diferentes a cada arquivo. **Nenhum dos dois entra no arquivo** — sem os dois, o conteúdo não
  volta, nem para você.
- Ter dois segredos separados permite mandá-los por **canais diferentes**: a senha no Discord, o
  pepper por telefone. Quem interceptar só um dos canais não consegue nada.
- **Salt** não é segredo e por isso fica dentro do arquivo. Ele é sorteado a cada criptografia e
  serve para que o mesmo arquivo com a mesma senha gere resultados diferentes, e para inviabilizar
  tabelas pré-computadas. Você não precisa guardá-lo nem combiná-lo com ninguém.
- **Rótulo** (`--label`) é uma etiqueta opcional em **texto claro**, só para o destinatário saber
  *qual* par senha/pepper usar. Nunca escreva um segredo aí.

## O que o envlock protege, e o que não protege

Protege o conteúdo do arquivo enquanto ele está nos servidores do WhatsApp/Discord, no e-mail, no
pendrive ou no backup de qualquer uma das pontas. O ciphertext é autenticado: se um byte for
alterado no caminho, o envlock recusa o arquivo em vez de devolver lixo.

Não protege contra: senha e pepper fracos (a força vem deles — use um pepper longo e aleatório);
uma máquina já comprometida com keylogger; alguém que leia o arquivo **depois** de descriptografado;
e o tamanho do arquivo, que continua visível. O nome original *é* criptografado, então quem
interceptar não sabe nem que era um `.env`.

## Detalhes técnicos

- **AES-256-GCM** com tag de 16 bytes. O cabeçalho entra como AAD, então mexer no salt, nos
  parâmetros ou no rótulo invalida a autenticação.
- **scrypt** com N=2¹⁷, r=8, p=1 (~128 MiB, 1-2s por operação) — custo alto de propósito, para que
  tentar senhas em massa saia caro. Os parâmetros ficam no cabeçalho, então arquivos antigos
  continuam abrindo se os valores mudarem.
- Zero dependências de terceiros: só a biblioteca padrão do Node (>= 20). Nada de supply chain.
- **Erro genérico por decisão**: "senha ou pepper incorretos, ou arquivo corrompido". Distinguir as
  três causas permitiria testar peppers isoladamente, sem pagar o custo do scrypt.
- O nome original vem de dentro da parte criptografada e é validado antes da gravação: um arquivo
  forjado não consegue gravar em `../../.bashrc`.

### Formato do `.envlock`

```
offset  tam  conteúdo
0       8    "ENVLOCK\0"
8       1    versão do formato
9       2    tamanho do cabeçalho (uint16 BE)
11      N    cabeçalho JSON: { kdf, N, r, p, salt, nonce, label? }
11+N    ...  ciphertext (nome original + conteúdo)
fim-16  16   tag GCM
```

### A janela local

`envlock open` sobe um HTTP em `127.0.0.1` numa porta sorteada, com um token aleatório de 32 bytes
exigido em toda requisição, checagem de `Host`/`Origin` (contra DNS rebinding), CSP sem origens
externas e desligamento automático. A página não referencia nenhuma URL externa — um teste da suíte
falha se alguém colar um CDN nela.

Uma ressalva honesta: strings em JavaScript não podem ser apagadas da memória de forma confiável.
Os buffers de chave são zerados após o uso, mas senha e pepper podem sobreviver na memória do
processo até o coletor de lixo passar. Para a ameaça que o envlock trata — o arquivo em trânsito —
isso não muda nada.

## Licença

MIT
