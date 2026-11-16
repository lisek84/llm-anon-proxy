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
* Uwaga o izolacji: `./data` na hoście zawiera vault do deanonimizacji. Kontener
  zapisuje go jako root, ale dla prawdziwej izolacji uruchom Dockera na innym
  hoście/użytkowniku niż Claude Code albo trzymaj `./data` nieczytelne dla
  użytkownika agenta. Zobacz [THREAT-MODEL.pl.md](THREAT-MODEL.pl.md).

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
python scripts/gen_dictionary.py --from .env --hostname --git
# przejrzyj dictionary.generated.yaml, scal to, co chcesz, do dictionary.yaml
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

## Weryfikacja

```bash
curl -s http://127.0.0.1:8787/health          # {"status":"ok",...}
python -m pytest -q                            # 54 przechodzących
python scripts/dev/bench_llm.py qwen3.5:4b     # wynik warstwy LLM (wymaga Ollamy)
```
