# llm-anon-proxy

[English](README.md) · **Polski**

> Trzymaj swoje prywatne dane z dala od ruchu API Claude Code — zamień adresy IP,
> domeny, nazwy hostów i sekrety na odwracalne zamienniki, zanim żądanie opuści
> maszynę, i przywróć je w odpowiedzi.

Lokalne proxy, które stoi między Claude Code a API Anthropic i nie wypuszcza
Twoich danych na zewnątrz. Podmienia Twoje prywatne wartości (domeny, IP, nazwy
hostów, poświadczenia, tokeny…) na deterministyczne zamienniki **zanim** cokolwiek
opuści maszynę, a w odpowiedzi przywraca prawdziwe wartości — również wewnątrz
argumentów `tool_use` — więc komendy nadal działają na Twoich prawdziwych hostach.

```
ty / ssh / pliki ─► Claude Code ─► [to proxy] ─► api.anthropic.com
                                       │  example.com      → aqurel-vous.example
                                       │  185.12.34.56      → 198.18.x.x
                                       │  Sup3rS3cret!      → [CRED_XXXXXXXXXX]
                                       ▼
                        przywraca prawdziwe wartości w drodze powrotnej
```

To **warstwa redukująca ryzyko, a nie gwarancja**. Zaszyfrowanych bloków, danych
wyliczonych z wartości (hashe, base64) ani kontekstu („tabela wypłat twórców") nie
da się usunąć przez podmianę. Rób, co się da, i prowadź rejestr rotacji.

## ⚠️ Nie uruchamiaj proxy tam, gdzie działa Claude Code

Pliki proxy — `data/mappings.db` (pełna tablica oryginał↔zamiennik),
`dictionary.yaml` oraz `data/secret.key` — to kompletny oracle do deanonimizacji.
Jeśli agent Claude Code działa jako **ten sam użytkownik systemu**, po prostu
odczyta je swoimi narzędziami plikowymi i odwróci wszystko; żaden kod nie
powstrzyma czytelnika o tym samym UID. **Uruchamiaj proxy jako inny użytkownik
systemu / w kontenerze / w osobnej dystrybucji WSL / na innym hoście**, żeby
Claude Code sięgał do niego wyłącznie przez port. Preflight przy starcie tego
pilnuje — zobacz **[docs/THREAT-MODEL.pl.md](docs/THREAT-MODEL.pl.md)**.

```bash
export ANONPROXY_CLIENT_USER=<użytkownik-uruchamiający-claude-code>
export ANONPROXY_ISOLATION=enforce      # odmów startu, jeśli brak izolacji
```

## Dlaczego proxy, a nie hooki

Proxy widzi całe żądanie: Twój prompt, pełną historię wiadomości, wejścia
`tool_use` i wyniki narzędzi oraz prompt systemowy. Hooki nie są w stanie
przepisać tego wszystkiego. Tutaj wszystko jest anonimizowane w drodze tam i
przywracane w drodze z powrotem.

## Dokumentacja

* **[docs/INSTALL.pl.md](docs/INSTALL.pl.md)** — instalacja przez Docker (gotowiec) i natywna, plus warstwa Ollama.
* **[docs/USAGE.pl.md](docs/USAGE.pl.md)** — codzienny workflow, słownik, konteksty,
  rejestr rotacji, weryfikacja, rozwiązywanie problemów.
* **[docs/THREAT-MODEL.pl.md](docs/THREAT-MODEL.pl.md)** — dlaczego proxy musi być
  odizolowane od agenta, jak je wdrożyć i przed czym nie chroni.

## Instalacja

**Docker (gotowiec)** — na maszynie z Dockerem jedna komenda podnosi całe
środowisko i zapisuje cały stan obok pliku compose:

```bash
git clone <repo> /llm-anon-proxy && cd /llm-anon-proxy
cp dictionary.example.yaml dictionary.yaml   # uzupełnij SWOIMI wartościami
docker compose up -d                         # proxy (słownik + regex); dodaj: --profile llm dla Ollamy
./claude_anon                                # w konsoli roboczej
```

**Natywnie** (tak działa WSL — bez Dockera):

```bash
cd ~/llm-anon-proxy
bash scripts/setup-proxy.sh                  # venv + zależności + dictionary.yaml
```

Uzupełnij `dictionary.yaml` — Twoje domeny, hosty, IP, nazwy użytkowników,
nazwy firm/marek, wrażliwe ścieżki. To pierwsza, deterministyczna warstwa;
wpisanie domeny rejestrowalnej pokrywa też jej subdomeny. Identyfikatory możesz
zasiać z lokalnych plików:

```bash
python scripts/gen_dictionary.py --from .env --hostname --git   # przejrzyj, potem scal
```

## Uruchomienie

```bash
# terminal 1 — uruchom proxy (tylko loopback)
./start_proxy.sh

# terminal 2 — odpal Claude Code przez proxy
./claude_anon
```

`claude_anon` odmawia startu, jeśli proxy jest nieosiągalne, więc nigdy nie
uruchomisz Claude Code na prawdziwym API przez przypadek. Ręczny odpowiednik:

```bash
python -m anonproxy                                   # terminal 1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787 && claude   # terminal 2
```

Twoje poświadczenia API przechodzą wprost do Anthropic i nigdy nie są logowane.

## Warstwy wykrywania

1. **Słownik** — Twoje dokładne wartości (deterministyczne, najwyższy priorytet).
2. **Regex** — IP, CIDR, MAC, e-maile, domeny, klucze/tokeny API (AWS, GitHub,
   Stripe, Slack, GitLab, Google, JWT), klucze prywatne PEM, hashe crypt/htpasswd
   oraz sekrety w postaci przypisań (`password:`, `PGPASSWORD=`, `mysql -p…`,
   `define('DB_PASSWORD', …)`, `requirepass`, DSN `user:pass@host`, `Bearer …`).
3. **Lokalny LLM (opcjonalny, domyślnie wyłączony)** — kontekstowe nazwy hostów /
   organizacji / osób, których regex nie złapie. Korzysta z Twojej lokalnej
   Ollamy (Docker lub natywnie — zobacz [docs/INSTALL.pl.md](docs/INSTALL.pl.md)):

   ```bash
   export ANONPROXY_LLM=true
   export ANONPROXY_OLLAMA_MODEL=qwen3.5:4b
   ```

   Domyślny model `qwen3.5:4b`: w lokalnym benchmarku (`scripts/dev/bench_llm.py`)
   wyłapał każdą encję kontekstową z zerem fałszywych trafień, przy medianie
   ~0,55 s na wywołanie na GPU 8 GB. Nazwy narzędzi, protokoły, wersje i
   identyfikatory CVE są filtrowane deterministycznie, więc model ich nie psuje.
   Gdy warstwa jest włączona, a Ollama nieosiągalna, żądania są **blokowane**
   zamiast wysyłane połowicznie zanonimizowane (ustaw
   `ANONPROXY_LLM_FAIL_CLOSED=false`, by to zmienić).

## Zamienniki (surogaty)

Deterministyczne (HMAC z lokalnym sekretem w `data/secret.key`, `0600`) i wolne
od kolizji — vault gwarantuje mapę odwrotną 1:1, więc przywrócona komenda nigdy
nie trafi na zły host. Zachowany jest kształt: publiczne IP →
`198.18.0.0/15`, prywatne IP pozostają prywatne, domeny zachowują pod-etykiety,
tokeny zachowują rozpoznawalny prefiks i klasę długości.

## Podgląd tego, co złapane

```bash
python -m anonproxy.audit         # każda złapana wartość: oryginał -> zamiennik, typ, gdzie
python -m anonproxy.preview < .env  # test na sucho offline — co BY opuściło maszynę
python -m anonproxy.rotate        # wartości o kształcie sekretów do rotacji
```

Proxy loguje też każde żądanie na żywo (`anonymized N … (M new)` w stronę API,
`restored N` z powrotem). Szczegóły: [docs/USAGE.pl.md](docs/USAGE.pl.md).

### Dashboard na żywo

Otwórz **`http://127.0.0.1:8787/ui`** w przeglądarce obok okna Claude Code —
kolorowy, automatycznie odświeżający się strumień tego, co proxy łapie podczas
pracy: typ encji, źródło, oryginał → zamiennik oraz liczniki. Bez logowania.

Domyślnie dashboard **maskuje** oryginały (typ, zamaskowany podgląd i pełny
zamiennik), więc widok HTTP nie jest oraclem do deanonimizacji — ważne, gdy proxy
jest odizolowane od agenta. Aby pokazać prawdziwe wartości (tylko loopback; agent
mógłby je wtedy też odczytać): `ANONPROXY_UI_SHOW_ORIGINALS=true`. Całkowicie
wyłącz UI przez `ANONPROXY_UI=false`.

## Rejestr rotacji

Każda napotkana wartość o kształcie sekretu jest dopisywana do
`data/rotate.log.jsonl` (`0600`, tylko typ + zamaskowany podgląd + SHA-256, nigdy
pełna wartość):

* `intercepted` — podmienione przed wysłaniem; zrotuj profilaktycznie.
* `leaked` — znalezione w bajtach faktycznie wysłanych do API; **te zrotuj**.

```bash
python -m anonproxy.rotate
```

Dziennik audytu `data/audit.log.jsonl` (`0600`) zawiera prawdziwe pary
`oryginał -> zamiennik` — jest wrażliwy i nigdy nie jest udostępniany przez HTTP.

## Izolacja per klient

Ustaw `ANONPROXY_CONTEXT=client-x`, aby trzymać mapowania każdego projektu osobno
(to samo IP mapuje się na różne zamienniki w różnych kontekstach).

## Czyszczenie / rotacja vaulta

Mapowania są trwałe (ten sam oryginał → ten sam zamiennik w obrębie kontekstu).
Czyść je **między sesjami, nigdy w trakcie**:

```bash
python -m anonproxy.reset                 # zapomnij wszystkie mapowania (ten sam klucz)
python -m anonproxy.reset --context acme  # zapomnij tylko jeden kontekst
python -m anonproxy.reset --new-key       # też rotacja klucza → wszystkie nowe zamienniki
python -m anonproxy.reset --all --yes     # mapowania + klucz + logi, bez pytania
```

Zapomnienie przy tym samym kluczu odtwarza identyczne zamienniki (to sprzątanie);
`--new-key` to prawdziwa rotacja. `start_proxy.sh` może zrobić to przy starcie:

```bash
ANONPROXY_RESET=1       ./start_proxy.sh   # zapomnij mapowania
ANONPROXY_RESET=new-key ./start_proxy.sh   # zapomnij mapowania + rotacja klucza
ANONPROXY_RESET=all     ./start_proxy.sh   # mapowania + klucz + logi
```

Szczegóły i konsekwencje: [docs/USAGE.pl.md](docs/USAGE.pl.md).

## Konfiguracja (zmienne środowiskowe)

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `ANONPROXY_HOST` / `ANONPROXY_PORT` | `127.0.0.1` / `8787` | adres nasłuchu |
| `ANONPROXY_UPSTREAM` | `https://api.anthropic.com` | prawdziwe API |
| `ANONPROXY_CONTEXT` | `default` | identyfikator izolacji mapowań |
| `ANONPROXY_DICT` | `dictionary.yaml` | Twoje wartości |
| `ANONPROXY_LLM` | `false` | włącz warstwę Ollama |
| `ANONPROXY_OLLAMA_MODEL` | `qwen3.5:4b` | id modelu |
| `ANONPROXY_DATA_DIR` | `./data` | baza, klucz, logi rotacji + audytu |
| `ANONPROXY_AUDIT` | `true` | zapisuj dziennik `oryginał -> zamiennik` |
| `ANONPROXY_ISOLATION` | `warn` | `warn` / `enforce` / `off` (zobacz THREAT-MODEL) |
| `ANONPROXY_UI` | `true` | udostępnij dashboard na `/ui` |
| `ANONPROXY_UI_SHOW_ORIGINALS` | `false` | pokaż prawdziwe wartości w dashboardzie |
| `ANONPROXY_RESET` | _(nieustawione)_ | tylko `start_proxy.sh`: `1` zapomnij mapowania · `new-key` też rotacja klucza · `all` + logi |
| `ANONPROXY_BLOCK_UNSCANNABLE` | `false` | blokuj (503) żądania z blokami image/binarny document zamiast je przekazywać |
| `ANONPROXY_BLOCK_UNKNOWN` | `false` | blokuj (403) endpointy inne niż `/v1/messages[/count_tokens]` |
| `ANONPROXY_TOKEN` | _(nieustawione)_ | wymagaj tego sekretu jako prefiksu ścieżki (`…:8787/<token>`); do użycia poza loopbackiem |
| `ANONPROXY_TLS` | `false` | serwuj HTTPS z auto-generowanym certem self-signed (katalog danych) |
| `ANONPROXY_TLS_CERT` / `ANONPROXY_TLS_KEY` | _(nieustawione)_ | serwuj HTTPS z własnym certem/kluczem |
| `ANONPROXY_TLS_SAN` | _(nieustawione)_ | dodatkowe nazwy hostów/IP do certu self-signed (po przecinku) |

## Ograniczenia

* Tylko podmiana. Dla wartości **zadeklarowanych** łapie też ich typowe kodowania
  (base64/base32/hex/URL/JSON `\uXXXX`) i jest normalizowane unikodowo (NFC/NFD),
  więc np. użytkownik `Łukasz` jest pokryty jawnie i w kodowaniach. Nie usunie
  szyfrowania, kompresji ani dowolnych kodowań wartości niezadeklarowanych.
* Kontekst nadal może Cię zidentyfikować (ścieżki, nazwy schematów, układ usług).
* Lokalne transkrypty w `~/.claude/projects/*.jsonl` nadal zawierają prawdziwe
  wartości; proxy stoi za nimi. Chroń je lub czyść osobno.
* Streaming przywraca wartości na granicach białych znaków; zamiennik nigdy nie
  jest dzielony.

## Testy

```bash
python -m pytest -q
```

Pokrywają obiegi tam-i-z-powrotem, wcześniej przeciekające wzorce sekretów,
wolne od kolizji i stabilne po restarcie zamienniki, listę dozwolonych,
wychodzący skan wycieków oraz pełny obieg przez proxy (żądanie zanonimizowane,
strumieniowa odpowiedź przywrócona) wobec atrapy upstreamu — bez sieci.

## Inspiracje

Projekt powstał po przeglądzie `zeroc00I/DontFeedTheAI` (MIT). Pomysły na regex
oraz zasada blokowania przy niedostępnym LLM pochodzą stamtąd; wolny od kolizji,
deterministyczny vault, pokrycie pełnej historii + `tool_use`, prawdziwe
przywracanie strumieniowe, nasłuch tylko na loopbacku i rejestr rotacji są już
własnym wkładem tego projektu.
