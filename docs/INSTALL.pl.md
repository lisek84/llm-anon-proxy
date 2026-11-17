# Instalacja

[English](INSTALL.md) · **Polski**

Dwa sposoby uruchomienia: **Docker** (gotowiec, najlepszy na maszynie z Dockerem)
lub **natywnie** (tak działa WSL, bo Dockera tam nie ma). Wybierz jeden. Nic tutaj
nie uruchamia usługi publicznej — proxy nasłuchuje wyłącznie na `127.0.0.1`.

## Docker (gotowiec)

Na maszynie z Dockerem całe środowisko podnosi się jedną komendą, a cały stan
zapisywany jest obok pliku compose.

```bash
git clone <repo> /llm-anon-proxy && cd /llm-anon-proxy
cp dictionary.example.yaml dictionary.yaml     # potem uzupełnij SWOIMI wartościami

# Kontener działa jako DEDYKOWANY UID (991), celowo NIE Twój użytkownik — to ten
# osobny właściciel katalogu vaulta (0700) powstrzymuje agenta Claude Code
# (działającego jako Ty) od odczytu mappings.db / secret.key. Utwórz ./data jako
# ten UID (raz z sudo). NIE mapuj kontenera na $(id -u) — to znosi izolację.
# Nadpisuj tylko na inny UID spoza agenta:  ANONPROXY_UID=… ANONPROXY_GID=…
sudo install -d -o 991 -g 991 -m 0700 data

docker compose up -d                           # buduje + startuje proxy (słownik + regex)
```

Z lokalną warstwą LLM (pobiera model; GPU przez NVIDIA toolkit):

```bash
ANONPROXY_LLM=true docker compose --profile llm up -d
```

Następnie w konsoli roboczej:

```bash
./claude_anon          # lub: export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude
```

* Proxy publikowane jest wyłącznie na `127.0.0.1:8787`. Dashboard: `http://127.0.0.1:8787/ui`.
* Stan (vault, klucz, logi rotacji + audytu) zapisywany jest do **`./data`** obok
  `docker-compose.yml`; słownik montowany jest tylko do odczytu z `./dictionary.yaml`.
* Podgląd logów z kontenera:
  `docker compose exec proxy python -m anonproxy.rotate` (oraz `… anonproxy.audit`).
* Pokaż prawdziwe wartości w dashboardzie: `ANONPROXY_UI_SHOW_ORIGINALS=true docker compose up -d`.
* Zatrzymanie: `docker compose down` (dodaj `--profile llm`, jeśli uruchamiałeś warstwę LLM).
* Uwaga o izolacji: `./data` na hoście zawiera vault do deanonimizacji
  (`mappings.db`, `secret.key`). Kontener działa jako dedykowany UID (991), a
  katalog ma 0700 — więc agent Claude Code, działający jako *Twój* użytkownik, go
  nie odczyta. To działa tylko, jeśli tak zostawisz: nie rób `chown ./data` na
  siebie i nie ustawiaj `ANONPROXY_UID=$(id -u)`. Mocniejszą granicą jest
  uruchomienie proxy w **innej dystrybucji WSL / użytkowniku / hoście** niż Claude
  Code. Słownik (`./dictionary.yaml`) też zawiera Twoje prawdziwe wartości —
  trzymaj go nieczytelnym dla użytkownika agenta, jeśli to dla Ciebie istotne.
  Zobacz [THREAT-MODEL.pl.md](THREAT-MODEL.pl.md).

Reszta tej strony to ścieżka **natywna** (bez Dockera).

## 1. Proxy (natywnie)

```bash
cd ~/llm-anon-proxy
bash scripts/setup-proxy.sh        # venv + zależności + dictionary.yaml do edycji
```

Albo ręcznie:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp dictionary.example.yaml dictionary.yaml && chmod 600 dictionary.yaml
```

Potem uzupełnij `dictionary.yaml` — zobacz [USAGE.pl.md](USAGE.pl.md). Możesz
zasiać go z lokalnych plików:

```bash
python -m anonproxy.gendict auto                                         # przeskanuj maszynę
cat /etc/hosts | python -m anonproxy.gendict ips --merge dictionary.yaml  # albo wrzuć konkrety
# przejrzyj potem dictionary.yaml — wypisuje tylko identyfikatory, nigdy sekrety
```

Warstwy regex + słownik działają samodzielnie. Warstwa Ollama poniżej jest
potrzebna tylko do wyłapywania nazw *kontekstowych* (nagie nazwy hostów, nazwy
organizacji/osób w tekście).

## 2. Ollama (opcjonalna warstwa kontekstowa)

Domyślny model: **`qwen3.5:4b`** — w lokalnym benchmarku wyłapał każdą encję
kontekstową z zerem fałszywych trafień, przy medianie ~0,55 s na wywołanie na GPU
8 GB. Model 9 B był wolniejszy bez zysku.

### Wariant A — Docker

Jeśli wdrożyłeś przez Docker powyżej, po prostu dodaj profil LLM — Ollama działa
jako usługa, a proxy łączy się z nią automatycznie:

```bash
ANONPROXY_LLM=true docker compose --profile llm up -d
```

Zmień model przez `ANONPROXY_OLLAMA_MODEL=qwen3.5:9b`. Brak NVIDIA toolkit?
Usuń blok `deploy:` z usługi `ollama`, by działać na CPU.

### Wariant B — Natywnie (WSL / Linux, bez Dockera) — tak jest tutaj

Instaluje Ollamę jako usługę i pobiera model.

```bash
bash scripts/install-ollama-wsl.sh
```

* Używa oficjalnego instalatora (sam woła `sudo`).
* Działa z systemd lub bez; bez niego startuje `ollama serve` w tle
  (`/tmp/ollama.log`).
* `goose` (agent) **nie** jest wymagany — używany jest tylko zwykły model czatowy.

### Włącz warstwę w proxy

```bash
export ANONPROXY_LLM=true
export ANONPROXY_OLLAMA_MODEL=qwen3.5:4b     # opcjonalnie; to wartość domyślna
python -m anonproxy
```

Gdy warstwa jest włączona, a Ollama nieosiągalna, żądania są **blokowane**
(fail-closed) zamiast wysyłane połowicznie zanonimizowane. Ustaw
`ANONPROXY_LLM_FAIL_CLOSED=false`, by zamiast tego zejść do słownik+regex.

## 3. Odizoluj proxy od agenta (wymagane do realnego użycia)

Pliki proxy to kompletny oracle do deanonimizacji; agent Claude Code nie może móc
ich odczytać. Uruchom proxy jako **dedykowanego użytkownika** (albo w kontenerze /
dystrybucji WSL / na innym hoście). Pomocnik (najpierw przejrzyj; używa sudo, nic
nie uruchamia):

```bash
sudo bash scripts/setup-isolated-user.sh     # tworzy użytkownika 'anonproxy' w /opt/anonproxy
```

Potem wymuś to przy starcie:

```bash
export ANONPROXY_CLIENT_USER=$USER     # użytkownik uruchamiający Claude Code
export ANONPROXY_ISOLATION=enforce     # odmów startu, jeśli brak izolacji
```

Pełne uzasadnienie i słabsze/mocniejsze opcje: [THREAT-MODEL.pl.md](THREAT-MODEL.pl.md).

## Skieruj Claude Code na proxy

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

## Użycie zdalne — szyfruj połączenie (TLS)

Proxy domyślnie serwuje **gołe HTTP**, co jest OK tylko na `127.0.0.1`. Jeśli
uruchamiasz je na jednej maszynie i kierujesz na nie inne hosty
(`ANTHROPIC_BASE_URL=…`), ruch — w tym Twoje prawdziwe dane w drodze powrotnej —
nie może iść po sieci nieszyfrowany. Trzy opcje:

**1. Wbudowany TLS self-signed** (najszybciej):

```bash
ANONPROXY_TLS=true ANONPROXY_HOST=0.0.0.0 ANONPROXY_TLS_SAN=proxy.mojlan \
  ANONPROXY_TOKEN=$(openssl rand -hex 24) python -m anonproxy
```

Generuje `data/tls-cert.pem` / `tls-key.pem` (reużywane po restarcie). Klienci
używają `https://`. Claude Code (Node) odrzuca niezaufany cert, więc na każdym
kliencie wskaż Node na ten cert:

```bash
export NODE_EXTRA_CA_CERTS=/ścieżka/do/tls-cert.pem
export ANTHROPIC_BASE_URL=https://proxy.mojlan:8787/<token>
claude
```

**2. Własny cert** (wewnętrzne CA lub Let's Encrypt): ustaw zamiast tego
`ANONPROXY_TLS_CERT` i `ANONPROXY_TLS_KEY` — wtedy klienci nie potrzebują
`NODE_EXTRA_CA_CERTS`.

**3. Terminacja TLS na reverse proxy** (zalecane produkcyjnie): uruchom to proxy
na loopbacku, a przed nim postaw nginx / haproxy / Caddy z prawdziwym
certyfikatem, przekazując do `127.0.0.1:8787`. Przykład nginx:

```nginx
server {
    listen 443 ssl;
    server_name proxy.mojlan;
    ssl_certificate     /etc/letsencrypt/live/proxy.mojlan/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.mojlan/privkey.pem;
    location / { proxy_pass http://127.0.0.1:8787; proxy_buffering off; }
}
```

W każdym wariancie zdalnym ustaw też `ANONPROXY_TOKEN` (sekret w prefiksie ścieżki)
i regułę firewalla — proxy nie ma własnego uwierzytelniania per-użytkownik. I
pamiętaj, że zasada izolacji nadal obowiązuje: maszyna z proxy trzyma vault, więc
`data/` ma być nieczytelne dla kogokolwiek, kto mógłby sięgnąć też do plików
Claude Code.

## Weryfikacja

```bash
curl -s http://127.0.0.1:8787/health          # {"status":"ok",...}
python -m pytest -q                            # 65 przechodzących
python scripts/dev/bench_llm.py qwen3.5:4b     # wynik warstwy LLM (wymaga Ollamy)
```
