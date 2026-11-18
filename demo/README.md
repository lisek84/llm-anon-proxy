# llm-anon-proxy — 5-minute demo

A self-contained way to *see* the proxy work, with no real data and no API key.
It stands up a throwaway "server" full of realistic fake secrets, then shows you
exactly what the proxy would let leave the machine — and what it hides.

> ⚠ **Run this on a disposable Ubuntu VM only.** The setup script installs
> packages, changes the hostname and writes fake secrets under `/var/www`,
> `/opt` and `/etc`. When you're done, just delete the VM.

## What you need

A clean Ubuntu VM (22.04 / 24.04 / 26.04) with `sudo` and internet access.
That's it — no GPU, no API key, nothing leaves the box.

## Run it (3 commands)

```bash
# on the fresh VM
git clone https://github.com/lisek84/llm-anon-proxy.git && cd llm-anon-proxy

sudo bash demo/setup-demo-server.sh     # builds the fake server + the proxy venv
bash demo/run-demo.sh                    # watch it anonymize everything
```

`run-demo.sh` prints, for each source, a list of

```
[DOMAIN      ] 'acme-crm.pl'        -> 'rxsxgm-wqquy.example'
[IP_ADDRESS  ] '10.14.8.12'         -> '10.4.7.9'
[CREDENTIAL  ] 'Pg_s3cr3t!2024'     -> 'CRED-4KQ...'
[PESEL       ] '93022751939'        -> '557...'
...
```

followed by the **fully anonymized text** — literally what Claude / Anthropic
would receive.

## What the demo plants (all fake)

* a company "Acme" with domains `acme-crm.pl`, `sklep-kowalski.pl`, `sniadanie.com`
* internal network `10.14.8.0/24` (+ an IPv6 host), hosts `db-prod-01`,
  `cache-redis-01`, `backup-node-07`, …
* real-shaped secrets in `.env`, `wp-config.php`, `secrets.yml`, `haproxy.cfg`:
  DB passwords, a GitHub token, a Stripe key, an AWS key, a Slack webhook
* customer records with **Polish PESEL / NIP / REGON** numbers (valid checksums)

## The point

Open `demo/dictionary.demo.yaml` and notice what's **not** there: no passwords,
no API tokens, no PESEL/NIP. You list only the things a scanner can't guess —
your domains, hostnames, internal IPs, service accounts and brand names. The
**regex + checksum layers catch the secrets and national IDs on their own.**

Add the local LLM layer to also catch things you never wrote down (a stray
hostname, an organization name in prose):

```bash
bash demo/run-demo.sh --llm      # needs a local Ollama; see docs/INSTALL.md
```

## Try it live (optional)

Point Claude Code at the proxy using this same dictionary:

```bash
cp demo/dictionary.demo.yaml dictionary.yaml
./start_proxy.sh                                   # terminal 1
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787    # terminal 2
claude                                             # ask it to read those files
```

Watch the live dashboard at <http://127.0.0.1:8787/ui>.

## Clean up

Destroy the VM, or:

```bash
sudo bash demo/teardown-demo-server.sh
```

Then build your **own** `dictionary.yaml` (`python -m anonproxy.gendict auto`
is a good start) and you're ready for real work.
