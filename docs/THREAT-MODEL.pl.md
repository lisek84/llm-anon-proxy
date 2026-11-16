# Model zagrożeń

[English](THREAT-MODEL.md) · **Polski**

## Podstawowe założenie

To narzędzie działa tylko wtedy, gdy to, *przed czym* ukrywa dane, nie może
odczytać danych, których używa do ukrywania.

Proxy trzyma na dysku:

| Plik | Dlaczego jest niebezpieczny |
|---|---|
| `data/mappings.db` | **pełna** tablica oryginał ↔ zamiennik — kompletna mapa odwrotna |
| `dictionary.yaml` | Twoje prawdziwe domeny, hosty, IP, nazwy użytkowników, nazwy firm, ścieżki |
| `data/secret.key` | klucz HMAC, z którego wyliczany jest każdy zamiennik |
| `data/rotate.log.jsonl` | zamaskowany, ale potwierdza, które sekrety istniały |

Każdy — lub każdy proces — kto może to odczytać, może w pełni odwrócić
anonimizację. Najważniejszy jest `mappings.db`: to *jest* klucz odpowiedzi.

## Dlaczego „nie uruchamiaj tam, gdzie działa Claude Code" ma znaczenie

Claude Code to agent z narzędziami plikowymi (`Read`, `Grep`, `Bash`). Jeśli
działa jako **ten sam użytkownik systemu** co proxy, może po prostu odczytać
`mappings.db` i `dictionary.yaml` wprost — anonimizacja sieciowa staje się teatrem.
Model byłby o jedno `cat` od każdej prawdziwej wartości.

**Żaden kod w proxy tego nie powstrzyma**, gdy agent dzieli UID z proxy: ten sam
użytkownik ⇒ te same uprawnienia plików. Ochrona musi pochodzić z systemu
operacyjnego, nie z aplikacji.

## Wymagane wdrożenie: odizoluj proxy

Uruchom proxy tam, gdzie narzędzia plikowe Claude Code nie sięgną do jego plików.
W rosnącej kolejności siły:

1. **Dedykowany użytkownik systemu** (najprościej na jednej maszynie). Proxy działa
   jako `anonproxy` z katalogiem danych `0700`; Claude Code działa jako Ty i nie
   może go odczytać. Pomocnik (najpierw przejrzyj, używa sudo, nic nie uruchamia):

   ```bash
   sudo bash scripts/setup-isolated-user.sh
   ```

2. **Kontener** — Ollama i/lub proxy w Dockerze, dane w wolumenie, którego
   użytkownik hosta nie montuje. Claude Code na hoście sięga tylko do portu.

3. **Osobna dystrybucja WSL** — uruchom proxy w drugiej dystrybucji; agent w Twojej
   dystrybucji roboczej widzi tylko `127.0.0.1:8787` (lub zmapowany port).

4. **Osobny host / VPS** z tunelem SSH — maszyna agenta w ogóle nie ma tych plików.
   Najsilniejsze i właściwe do użycia współdzielonego lub zespołowego.

W każdym przypadku Claude Code rozmawia z proxy **wyłącznie przez port**
(`ANTHROPIC_BASE_URL`), nigdy przez jego system plików.

## Wbudowany preflight

Przy starcie proxy uruchamia `anonproxy/preflight.py`, który:

* utwardza uprawnienia (`data/` → `0700`, pliki sekretów → `0600`) oraz
* sprawdza izolację względem `ANONPROXY_CLIENT_USER` (użytkownik uruchamiający
  Claude Code): odrzuca oczywisty przypadek współlokacji (użytkownik proxy ==
  użytkownik klienta) i weryfikuje, że ten użytkownik nie może odczytać wrażliwych
  plików.

Tryby przez `ANONPROXY_ISOLATION`:

| Tryb | Zachowanie |
|---|---|
| `warn` (domyślny) | utwardź uprawnienia, wyloguj wyraźne ostrzeżenie, jeśli brak izolacji |
| `enforce` | **odmów startu**, dopóki izolacja od `CLIENT_USER` nie jest potwierdzona |
| `off` | pomiń sprawdzenie (niezalecane) |

Uruchom samodzielnie w dowolnej chwili:

```bash
ANONPROXY_CLIENT_USER=$USER python -m anonproxy.preflight ; echo "exit=$?"
# exit 0 = izolowane, 1 = znaleziono problemy
```

Zalecane do realnego użycia:

```bash
export ANONPROXY_CLIENT_USER=<użytkownik-uruchamiający-claude-code>
export ANONPROXY_ISOLATION=enforce
```

Sprawdzenie to zabezpieczenie pomocnicze, nie mechanizm. Potrafi powiedzieć, że
*nie* jesteś izolowany; realną izolację daje wyłącznie granica systemu. Zdeterminowany
agent o tym samym UID, który odczyta pliki przed startem proxy, jest poza zakresem
— odpowiedzią jest inny użytkownik/kontener/host, dlatego `enforce` tego wymaga.

## Kodowania i Unicode

Zwykła podmiana nie trafia w wartość, która została przekodowana. Proxy domyka
typowe przypadki bez klucza **dla wartości zadeklarowanych w słowniku** — rejestruje
też ich formy zakodowane:

* base64 (standard i url-safe, z paddingiem i bez, z i bez końcowego znaku nowej
  linii dodawanego przez `echo`), base32 oraz hex (duże/małe litery);
* URL/percent-encoding oraz escape'y JSON `\uXXXX`.

Formy zakodowane są dopasowywane z granicami tokena, więc kodowanie krótkiej
wartości nigdy nie dopasuje się częściowo wewnątrz dłuższego bloba, a `KEY=<base64>`
nadal pasuje. Jednokierunkowe hashe (md5/sha, standardowe długości) są zasłaniane
przez regułę HASH regex, bo rozpoznawany jest ich *kształt*, nawet jeśli proxy nie
wie, z jakiej wartości pochodzą.

Unicode jest normalizowany do NFC po obu stronach, więc akcentowana lub polska
wartość (`Łukasz`, `Kraków`) pasuje niezależnie od tego, czy wejście przyszło jako
NFC czy NFD, a jej kodowania liczone są z bajtów UTF-8. Deklaruj takie wartości
dokładnie tak, jak się pojawiają; dopasowanie jawnego tekstu jest niewrażliwe na
wielkość liter.

Nadal **nie** pokryte: kodowania wartości, której *nie ma* w słowniku (dowolnego
bloba base64 nie można uznać za wrażliwy bez zalewu fałszywych trafień — ta sama
granica co szyfrowanie); kompresja (gzip/deflate) lub szyfrowanie; podwójne
kodowanie; wartość rozbita między wiadomościami; oraz egzotyczne kodowania (encje
HTML, ROT13, własne schematy). Cokolwiek Ci zależy — wpisz prawdziwą wartość do
słownika.

## Poprawność podmiany

Oba kierunki podmieniają **po pozycji w oryginalnym tekście, jednym przebiegiem**,
z nakładkami rozstrzyganymi najdłuższy-najpierw, więc wartość ani zamiennik nigdy
nie są dopasowywane wewnątrz tekstu, który właśnie podmieniono. Domena zachowuje
subdomeny (`cdn.acme.pl` → `cdn.<zamiennik>`), słowo kluczowe wewnątrz ścieżki jest
podmieniane bez dotykania sąsiedniego TLD `.example` surogatu domeny, a
przywracanie nigdy nie rozwija podwójnie (brak `acme.pl` → `acme.pl.pl`). Zamienniki
nie zawierają białych znaków, więc odpowiedzi strumieniowe są przywracane w całości.
Logowanie złapania jest best-effort i nigdy nie zepsuje ani częściowo nie pominie
anonimizacji.

Jeśli warstwa LLM jest włączona, a Ollama padła, żądanie jest **blokowane**
(fail-closed, domyślnie) albo **schodzi do słownik+regex dla całego żądania**
(fail-open) — nigdy nie jest przekazywane połowicznie zanonimizowane.

## Detekcja jest wartościowa, nie pozycyjna

Regex decyduje per *wartość*, nie per wystąpienie, a anonimizator podmienia potem
każde wystąpienie złapanej wartości w bloku. Warto wiedzieć:

* **Wyjątki zależne od kontekstu działają per-wartość, nie per-pozycja.** Jeśli ten
  sam ciąg wystąpi raz w kontekście pomijanym i raz w łapanym — oba zostaną
  podmienione. `v4.14.5.1 … version 4.14.5.1` — forma z `v` jest pomijana, ale
  drugie wystąpienie jest łapane jako IP, więc podmieniane są *oba*.
* **Dwuczłonowe domeny na niejednoznacznym TLD nie są łapane w zwykłym tekście**
  (`firma.it`, `foo.io`, `bar.es`): kolidują z nazwami plików i kodem, więc są
  łapane tylko przy ≥3 etykietach lub w kontekście sieciowym (`@`, `://`, `:port`,
  `/ścieżka`). Własne takie domeny wpisz do słownika.
* **IP zapisane z myślnikami w nazwach PTR nie są widziane jako IP**
  (`ec2-52-90-38-71.compute-1.amazonaws.com`). **Nie** dodawaj takich domen
  dostawców do `allow:`, bo osadzony adres przejdzie bez anonimizacji.
* **`nazwa.ext:NN` z numerem linii, ale bez końcowego dwukropka** (`see
  deploy.sh:12 for details`) jest kształtowo identyczne z `host.io:8080`, więc
  jest łapane jako domena. `plik:linia:` (z końcowym dwukropkiem, jak drukuje
  grep) już nie — tylko ta forma z gołym numerem linii, nierozstrzygalna bez
  kontekstu.
* **Kosmetyka:** cel scp `git@host.tld:ścieżka` jest łapany w całości jako e-mail,
  więc model widzi `x@y.example:ścieżka` i traci informację, że to git.

## Co przeciekło — rejestr rotacji

Skan po anonimizacji przebiega po **wartościach stringów** wychodzącego ciała (nie
po jego serializacji JSON, która tworzyłaby fałszywe trafienia na granicach escape),
pomijając pola protokołu takie jak `metadata` (leży tam własny identyfikator konta
Anthropic rozmówcy i nie jest sekretem do rotacji). Warte rotacji sekrety nadal
obecne — poświadczenia i tokeny — są zapisywane do `data/rotate.log.jsonl` jako
`leaked` (w odróżnieniu od `intercepted` dla wartości podmienionych przed wysłaniem).
Hashe/checksumy i identyfikatory celowo nie są zapisywane jako wycieki (za dużo
szumu, nie podlegają rotacji). Przejrzyj przez `python -m anonproxy.rotate` i zrotuj
każdy wpis `leaked`. Ciała przekazywane bez zmian przez catch-all (nieznane
endpointy) są logowane jako ostrzeżenie i również skanowane.

## Przed czym to narzędzie nadal nie chroni

* **Dane zaszyfrowane lub skompresowane** — podmienia literały; nie usunie
  wartości, która po tym, jak ją widziałeś, została zaszyfrowana lub spakowana
  gzipem. Odwracalne *kodowania* zadeklarowanych wartości są obsłużone (patrz wyżej);
  dowolne nie.
* **Kontekst** — ścieżki, nazwy schematów i układ usług mogą Cię zidentyfikować
  nawet przy podmienionym każdym literale.
* **Prompt injection** z wyniku narzędzia (baner serwera każący modelowi coś zrobić)
  — nietknięty przez anonimizację.
* **Lokalne transkrypty Claude Code** w `~/.claude/projects/*.jsonl`, które
  przechowują prawdziwe wartości widziane przez agenta. Chroń je lub czyść osobno.
* **Przejęcie samego hosta/użytkownika proxy**.
