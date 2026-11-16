# Użytkowanie

[English](USAGE.md) · **Polski**

## Codzienny workflow

```bash
# 1. uruchom proxy (jeden terminal, zostaw działające)
cd ~/llm-anon-proxy && . .venv/bin/activate
python -m anonproxy

# 2. w drugim terminalu odpal Claude Code przez proxy
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

Pracuj normalnie — loguj się po ssh na serwery, czytaj pliki `.env`, grepuj
konfiguracje. W drodze na zewnątrz Twoje wartości stają się zamiennikami; w drodze
powrotnej prawdziwe wartości są przywracane, więc komenda proponowana przez Claude
typu `ssh root@<zamiennik>` faktycznie działa na Twoim prawdziwym hoście. Nie
musisz o tym myśleć w trakcie pracy.

Na koniec sesji przejrzyj, co było ujawnione, i zrotuj, co trzeba:

```bash
python -m anonproxy.rotate
```

## Słownik

`dictionary.yaml` to pierwsza, deterministyczna warstwa: Twoje własne wartości,
każda w sekcji, która ustala kształt zamiennika. Dopasowanie jest niewrażliwe na
wielkość liter i oparte na podłańcuchach, najdłuższe najpierw, więc domena
rejestrowalna pokrywa też subdomeny.

```yaml
domains:        # cdn3.site.com jest pokryte przez wpisanie site.com
  - example-prod.pl
hosts:          # nagie nazwy maszyn (bez kropek)
  - of-prod-db01
ips:
  - 185.12.34.56
cidrs:
  - 10.20.0.0/16
emails:
  - admin@example-prod.pl
usernames:
  - of_app
organizations: # nazwy marek / projektów / firm, też jako gołe słowa
  - example
keywords:       # gołe słowa łapane jako komponent gdziekolwiek:
  - example     #   /var/www/example, example.conf, example-worker
paths:          # wrażliwe ścieżki bezwzględne
  - /home/lisek/example-ops
```

`keywords` są dopasowywane jako podłańcuchy wszędzie, gdzie się pojawią, więc
nazwa projektu osadzona w ścieżce lub nazwie pliku zostaje złapana. Dłuższa
wartość i tak wygrywa pierwsza, więc wpisanie zarówno `keywords: example`, jak i
`domains: example.com` sprawia, że pełna domena jest traktowana jako domena
(`cdn3.example.com`), a gołe `/var/www/example` używa zamiennika słowa kluczowego.

Co tu wpisywać: rzeczy wysokiej wartości, których skan nie wywnioskuje — nazwy
marek/projektów, wewnętrzne nazwy hostów, konta usługowe, wrażliwe ścieżki.
Identyfikatory typu domeny/IP/e-maile można zasiać automatycznie:

```bash
python scripts/gen_dictionary.py --from .env --from /etc/nginx/conf.d/app.conf --hostname --git
```

Zapisuje `dictionary.generated.yaml` (nigdy nie rusza Twojego prawdziwego pliku) z
samymi identyfikatorami — **nigdy sekretami**. Przejrzyj i scal.

Zmiany są wczytywane przy restarcie proxy.

> **Nie** wpisuj haseł/tokenów do słownika. Sekrety są łapane dynamicznie przez
> warstwę regex; słownik nie jest magazynem sekretów.

## Co jest podmieniane — a co nie

Podmieniane: wartości ze słownika; IP, CIDR, MAC, e-maile, domeny; klucze i tokeny
API (AWS, GitHub, Stripe, Slack, GitLab, Google, JWT); klucze prywatne PEM; hashe
crypt/htpasswd; oraz sekrety w postaci przypisań (`password:`, `PGPASSWORD=`,
`mysql -p…`, `define('DB_PASSWORD', …)`, `requirepass`, DSN `user:pass@host`,
`Bearer …`).

Celowo nietknięte: loopback i dobrze znane IP (`127.0.0.1`, `8.8.8.8`,
`169.254.169.254`…) oraz domeny narzędziowe (`anthropic.com`, `github.com`,
`pypi.org`…) — żeby porady i odwołania do pakietów nadal działały. Własne usługi
publiczne (żeby model zachował kontekst) dodaj w sekcji `allow:` w słowniku:

```yaml
allow:            # nigdy nie anonimizowane — domeny (też subdomeny) i IP
  - hetzner.com
  - docker.io
  - grafana.com
```

Przy włączonej warstwie LLM łapane są też nagie nazwy hostów oraz nazwy
organizacji/osób w tekście; nazwy narzędzi, protokoły, wersje i identyfikatory CVE
są odfiltrowywane deterministycznie, więc nigdy nie są psute.

## Izolacja per klient

Trzymaj mapowania każdego klienta osobno, aby to samo IP mapowało się na różne
zamienniki u różnych klientów (i nic nie przeciekało między nimi):

```bash
ANONPROXY_CONTEXT=client-acme python -m anonproxy
```

Każdy kontekst to partycja w tym samym vaultcie SQLite (`data/mappings.db`).

## Mapowania są trwałe — czyszczenie i rotacja

Mapowania są zapisywane na stałe: w obrębie kontekstu ten sam oryginał zawsze
mapuje się na ten sam zamiennik, stabilnie między restartami (dobrze — serwer
wygląda tak samo dla modelu w każdej sesji). Sam zamiennik jest **deterministyczny**
z `data/secret.key`, więc vault to tak naprawdę mapa odwrotna + ochrona przed
kolizjami, a nie jedyne źródło wartości.

Czyść je **między sesjami, nigdy w trakcie** (wyczyszczenie w trakcie zepsuje
przywracanie zamienników, które już krążą):

```bash
python -m anonproxy.reset                 # zapomnij wszystkie mapowania (ten sam klucz)
python -m anonproxy.reset --context acme  # zapomnij tylko jeden kontekst
python -m anonproxy.reset --new-key       # też rotacja klucza → wszystkie nowe zamienniki
python -m anonproxy.reset --all --yes     # mapowania + klucz + logi, bez pytania
```

* Zapomnienie mapowań przy **tym samym** kluczu to sprzątanie: te same oryginały
  odtwarzają **te same** zamienniki. Użyj, by zmniejszyć vault lub zrzucić historię.
* `--new-key` rotuje `data/secret.key`; potem każda wartość mapuje się na zupełnie
  nowy zamiennik — prawdziwa rotacja wartości anonimizacyjnych.
* Przełączenie `ANONPROXY_CONTEXT` daje świeżą przestrzeń zamienników bez
  kasowania czegokolwiek.

`start_proxy.sh` może zresetować przy starcie (najpierw zatrzymaj proxy, by zadziałało czysto):

```bash
ANONPROXY_RESET=1       ./start_proxy.sh   # zapomnij mapowania
ANONPROXY_RESET=new-key ./start_proxy.sh   # zapomnij mapowania + rotacja klucza
ANONPROXY_RESET=all     ./start_proxy.sh   # mapowania + klucz + logi
```

W Dockerze `docker compose down` zachowuje `./data`; skasuj ten katalog (albo
uruchom `docker compose exec proxy python -m anonproxy.reset …`), by go wyczyścić.

## Rejestr rotacji

Wszystko o kształcie sekretu, co przechodzi, jest dopisywane do
`data/rotate.log.jsonl` (tryb `600`; przechowuje tylko typ, zamaskowany podgląd i
SHA-256 — nigdy pełnej wartości). Dwie kategorie:

* **intercepted** — podmienione, zanim opuściło maszynę. Nadal dotknęło lokalnej
  historii/logów, więc zrotuj profilaktycznie.
* **leaked** — znalezione w bajtach *faktycznie wysłanych* do API (skan po
  anonimizacji). To trafiło do API — **zrotuj**.

```bash
python -m anonproxy.rotate     # zgrupowany raport, leaked na górze
```

Po dniu pracy przejdź listę i zrotuj każde poświadczenie u źródła.

## Weryfikacja działania — gdzie zobaczyć ślad

Są cztery miejsca, od żywego po forensyczne:

**1. Żywy log proxy (stdout `python -m anonproxy`).** Każde żądanie wypisuje, co
się stało w drodze tam i z powrotem:

```
anonymized 5 value(s) [tool_result] (3 new): credential=1 domain=1 hostname=1 ip_address=2
← restored 4 surrogate(s) in streamed response
```

`(N new)` to wartości widziane po raz pierwszy; ponownie wysyłana historia jest
cicha. Linia `restored` potwierdza, że droga powrotna przywróciła Twoje prawdziwe
wartości. Ostrzeżenie `secret-shaped value still present` oznacza, że coś się
prześlizgnęło (jest też logowane do rotacji — patrz niżej).

**2. Dziennik audytu — zapis dokładnie tego, co złapano.** Każda wartość jest
logowana przy pierwszym wystąpieniu, `oryginał -> zamiennik`, z typem i miejscem
wystąpienia:

```bash
python -m anonproxy.audit            # pełna lista, pogrupowana wg typu
python -m anonproxy.audit -n 20      # tylko ostatnie 20
```

```
2026-11-15T20:33:39Z  [DOMAIN    ] message      'cdn3.example.com' -> 'xzrbxf-ulpor.example'
2026-11-15T20:33:39Z  [CREDENTIAL] tool_result  'Hunter2pass'       -> '[CRED_J9724CV11M]'
```

Ten plik (`data/audit.log.jsonl`) zawiera **prawdziwe wartości**, więc leży w
chronionym katalogu danych (`0600`) i nigdy nie jest udostępniany przez HTTP. To
odpowiedź na pytanie „co proxy faktycznie złapało w tej sesji". Wyłącz przez
`ANONPROXY_AUDIT=false`.

**3. Test na sucho, zanim zaufasz — offline, nic nie wysyła.** Wklej lub przekaż
prawdziwy plik i zobacz dokładnie, co opuściłoby maszynę:

```bash
python -m anonproxy.preview < .env
python -m anonproxy.preview --file /etc/nginx/conf.d/app.conf --llm
```

Wypisuje każde złapanie (`oryginał -> zamiennik`) i w pełni zanonimizowany tekst,
w jednorazowym kontekście, który nigdy nie rusza Twojego prawdziwego vaulta ani
logów. Użyj, by potwierdzić, że `dictionary.yaml` i reguły regex łapią Twoje dane
*przed* prawdziwą sesją.

**4. Zestaw testów — twarda gwarancja.**

```bash
python -m pytest -q    # sprawdza, że znane wzorce sekretów nigdy nie przechodzą, a odpowiedzi wracają 1:1
```

Typowa pierwsza prawdziwa sesja: uruchom `python -m anonproxy.preview < jakiś-prawdziwy-config`,
by potwierdzić, że Twoje wartości są łapane, uruchom proxy, zrób krótką sesję,
potem `python -m anonproxy.audit`, by zobaczyć pełną listę przechwyceń, oraz
`python -m anonproxy.rotate` po cokolwiek do rotacji.

## Rozwiązywanie problemów

| Objaw | Rozwiązanie |
|---|---|
| Claude Code ignoruje proxy | Sprawdź `echo $ANTHROPIC_BASE_URL` = `http://127.0.0.1:8787` w *tej samej* powłoce, która uruchamia `claude`. |
| 503 `anonymizer_unavailable` | Warstwa LLM włączona, ale Ollama padła. Uruchom Ollamę, albo ustaw `ANONPROXY_LLM=false`, albo `ANONPROXY_LLM_FAIL_CLOSED=false`. |
| Przeciekła Twoja wartość | Dodaj ją do `dictionary.yaml` i zrestartuj; sprawdź `python -m anonproxy.rotate`. |
| Narzędzie/domena zostało zepsute | Dodaj je do listy dozwolonych w `anonproxy/regex_detector.py`, albo (jeśli kontekstowe) do `_SAFE_LLM_TERMS` w `anonproxy/anonymizer.py`. |
| Odpowiedzi wolne przy włączonym LLM | Użyj `qwen3.5:4b`; 9B jest wolniejszy bez zysku dokładności w benchmarku. |

## Ograniczenia

Tylko podmiana. Dla wartości **w Twoim słowniku** łapie też ich typowe kodowania
(base64, base32, hex, URL-encoding, JSON `\uXXXX`) i dopasowuje je niezależnie od
normalizacji unikodowej (NFC/NFD) — więc użytkownik o imieniu `Łukasz` jest
pokryty w postaci jawnej i w kodowaniach. Nie usunie danych zaszyfrowanych ani
skompresowanych, dowolnych kodowań wartości, których nie zadeklarowałeś, ani
kontekstu (ścieżki, nazwy schematów, układ usług), który identyfikuje Cię
pośrednio. Lokalne transkrypty Claude Code w `~/.claude/projects/*.jsonl` nadal
zawierają prawdziwe wartości — chroń je lub czyść osobno. Pełna lista:
[THREAT-MODEL.pl.md](THREAT-MODEL.pl.md).
