"""
Tests for the dictionary builder (anonproxy.gendict): per-section extraction
from stdin/files, public-domain filtering, and merge-into-existing.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="anonproxy-gendict-test-")
os.environ.setdefault("ANONPROXY_DATA_DIR", _TMP)

from anonproxy import gendict  # noqa: E402


def _ex(section, text, keep_known=False):
    return gendict._extract(section, text, keep_known)


def test_ips_skip_loopback_and_cidr_network():
    text = "127.0.0.1 localhost\n192.168.0.52 host\n10.0.0.5\n172.16.0.0/24\n"
    ips = _ex("ips", text)
    assert "192.168.0.52" in ips and "10.0.0.5" in ips
    assert "127.0.0.1" not in ips          # loopback skipped
    assert "172.16.0.0" not in ips         # that's the CIDR network, not a host


def test_cidr_extracted():
    assert _ex("cidrs", "net 172.16.0.0/24 and 10.0.0.0/8") == ["172.16.0.0/24", "10.0.0.0/8"]


def test_domains_drop_public_keep_private():
    text = "github.com docker.io api.jesiotr.pl shop.sniadanie.com db01.internal"
    doms = _ex("domains", text)
    assert "api.jesiotr.pl" in doms and "shop.sniadanie.com" in doms
    assert "db01.internal" in doms          # private zone kept
    assert "github.com" not in doms and "docker.io" not in doms


def test_domains_keep_known_flag():
    doms = _ex("domains", "github.com api.jesiotr.pl", keep_known=True)
    assert "github.com" in doms and "api.jesiotr.pl" in doms


def test_domains_reject_filenames_and_loopback_zones():
    doms = _ex("domains", "wsl.conf app.yaml notes.txt hp.localdomain printer.local")
    assert doms == []


def test_hosts_from_etc_hosts_skip_localhost_aliases():
    text = ("127.0.0.1 localhost\n"
            "::1 ip6-localhost ip6-loopback\n"
            "192.168.0.52 testenv testenv.jesiotr.pl\n"
            "10.0.0.5 db01\n")
    hosts = _ex("hosts", text)
    assert hosts == ["testenv", "db01"]     # FQDN + localhost/ip6 aliases excluded


def test_hosts_from_ssh_config():
    text = "Host bastion\n    HostName jump01\n    User deploy\n"
    hosts = _ex("hosts", text)
    assert "bastion" in hosts and "jump01" in hosts


def test_usernames_from_passwd():
    text = ("root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "lisek:x:1000:1000:Lisek:/home/lisek:/bin/bash\n"
            "svc:x:999:999::/var/lib/svc:/usr/sbin/nologin\n")
    users = _ex("usernames", text)
    assert users == ["lisek"]               # uid>=1000 with a real shell only


def test_emails_and_urls():
    text = "mail admin@jesiotr.pl visit https://shop.sniadanie.com/page, end"
    assert _ex("emails", text) == ["admin@jesiotr.pl"]
    assert _ex("urls", text) == ["https://shop.sniadanie.com/page"]


def test_to_yaml_preserves_extra_sections():
    out = gendict._to_yaml({"domains": ["a.pl"], "allow": ["mycompany.com"]})
    assert "domains:" in out and "- a.pl" in out
    assert "allow:" in out and "- mycompany.com" in out


def test_merge_into_dedupes_and_keeps_existing(tmp_path):
    d = tmp_path / "dict.yaml"
    d.write_text("domains:\n  - jesiotr.pl\nhosts:\n  - testenv\nallow:\n  - mycompany.com\n")
    added = gendict._merge_into(str(d), {"domains": ["jesiotr.pl", "new.pl"], "ips": ["10.0.0.5"]})
    assert added == 2                       # new.pl + 10.0.0.5; jesiotr.pl deduped
    result = d.read_text()
    assert "new.pl" in result and "10.0.0.5" in result
    assert "mycompany.com" in result        # untouched allow section survives
    assert "testenv" in result
