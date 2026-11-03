# CTF Enum CLI — enumerazione iniziale per laboratori autorizzati

Tool Python **3.11+**, solo standard library: scansione TCP in due passaggi, fingerprint web e ricerca di vulnerabilità **candidate** (con evidenza dei possibili vettori RCE). **Non contiene payload, non esegue exploit, non effettua brute force di credenziali.** Limitare l'uso a CTF, HTB e reti isolate autorizzate. L'enumerazione di directory genera comunque richieste HTTP: rispettare i limiti del laboratorio.

## Installazione su Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap gobuster exploitdb seclists golang-go

# Nella directory del progetto estratto:
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

# Webanalyze: CLI Go, port di Wappalyzer
go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest
export PATH="$(go env GOPATH)/bin:$PATH"
webanalyze -update   # genera technologies.json nella directory corrente
```

**Nota:** `webanalyze -update` va eseguito dalla directory di questo progetto (oppure modificare `webanalyze_apps` in `config.toml`). La wordlist SecLists predefinita è `/usr/share/seclists/Discovery/Web-Content/common.txt`; alcune installazioni la collocano altrove, quindi controllare il percorso e usare `--wordlist`. Per rendere il PATH persistente, aggiungere l'export alla configurazione della propria shell.

Nmap `vulners.nse` è normalmente disponibile nelle versioni recenti: verificare con `nmap --script-help vulners`. Se non è presente, seguire la [documentazione Nmap](https://nmap.org/nsedoc/scripts/vulners.html) o il [repository Vulners](https://github.com/vulnersCom/nmap-vulners). **Lo script NSE interroga un servizio terzo (Vulners): non è una fase offline.**

Test strumenti:

```bash
nmap --version
gobuster version
searchsploit -h
webanalyze -h
ls -l technologies.json /usr/share/seclists/Discovery/Web-Content/common.txt
```

## Esecuzione

```bash
# Esempio CTF/lab (il flag --authorized è obbligatorio)
ctf-enum 10.10.10.10 --authorized

# Scansione rapida su range personalizzato e wordlist custom
ctf-enum orion.htb --ports 22,80,8000-9000 --wordlist /path/to/common.txt --authorized

# Output a scelta e ripresa da checkpoint
ctf-enum 10.10.10.10 --output ./risultati/box1 --authorized
ctf-enum 10.10.10.10 --output ./risultati/box1 --resume --authorized

# Ricerca aggiuntiva NVD, da abilitare esplicitamente
ctf-enum 10.10.10.10 --nvd --authorized

# Stessa CLI anche senza installazione editable:
python3 -m ctf_enum 10.10.10.10 --authorized
```

Opzioni: `--ports`, `--wordlist`, `--config`, `--output`, `--min-rate`, `--threads`, `--nvd`, `--resume`, `--skip-web`, `--authorized` e `--help`.

### Configurazione (`config.toml`)

- `[scan]`: `min_rate` (default 2000), timeout di Nmap e subprocess.
- `[web]`: numero `threads` Gobuster (10), numero `max_concurrency` di servizi web (3), timeout HTTP e TLS (`verify_tls = false` per certificati self-signed di lab).
- `[paths]`: percorsi assoluti/relativi di wordlist e `technologies.json`. I percorsi relativi sono riferiti alla directory di `config.toml`.
- `[lookup]`: numero massimo di query SearchSploit e lookup NVD (default disabilitata).
- Chiave NVD opzionale: impostare la variabile d'ambiente `NVD_API_KEY`. Senza API key viene applicato un intervallo conservativo di 6,5 secondi fra le richieste NVD.

## Pipeline e concorrenza

1. **Nmap discovery**: `-Pn -n -T4 --open -p- --min-rate 2000 -oX ...`. Con `--ports` usa solo il range richiesto.
2. **Nmap servizi**: `-sV --script default,vulners` solo sulle porte TCP aperte (equivale a `-sC` **più** `vulners`; Nmap ignora `-sC` quando è presente `--script`), salva il secondo XML. L'XML viene analizzato con `xml.etree.ElementTree` in un modello Python con porte, CPE, script e dati NSE strutturati.
3. **Web**: rileva HTTP/HTTPS da nome del servizio o porte comuni. Per ogni servizio esegue **in parallelo** Gobuster, Webanalyze della home e un fetch HTML a dimensione limitata. Se trova indizi di form login negli `input type=password`, link, action di form o directory, esegue un nuovo Webanalyze sul path di login.
4. **Vulnerabilità**: per ogni stack/versione rilevata cerca in `searchsploit -j -t`. Conserva anche i CVE restituiti da `vulners.nse`. Opzionalmente aggiunge ricerche `keywordSearch` alla API NVD 2.0. Ordina in cima le voci con indicatori **espliciti** di RCE nel titolo/descrizione, non confonde "remote" con "RCE".
5. **Output**: checkpoint atomici in JSON, XML Nmap, testo Gobuster, `report.json` completo, `report.md` leggibile.

La CLI usa `asyncio.create_subprocess_exec` senza shell, timeout e terminazione dei processi figli; usa `asyncio.to_thread` per le brevi richieste HTTP sincrone della standard library. Le operazioni su servizi web diversi sono limitate da un semaforo. Su errore di un tool opzionale registra un messaggio e prova a completare le altre fasi. Se Nmap fallisce produce comunque un report parziale e restituisce exit code **2**.

### File generati

```text
reports/<target>/
  run_manifest.json
  01_nmap_discovery.xml
  01_nmap_discovery.json
  02_nmap_services.xml
  02_nmap_services.json
  03_gobuster_<porta>.txt
  03_web.json
  04_vulnerabilities.json
  report.json
  report.md
```

I file `.json` contengono anche gli output grezzi dei CLI (con un limite ai campi stdout/stderr per non gonfiare i checkpoint) e le strutture interpretate. Gli XML Nmap e i testi Gobuster restano interi su disco. La fase web salva `03_web.json` dopo **ogni porta**, quindi `--resume` recupera le porte già completate. `--resume` verifica il fingerprint di target, scope e configurazione: se questi cambiano usare un'altra directory output.

## Limiti e raccomandazioni

- **CVE candidati, non confermati**. Confrontare manualmente versioni reali, configurazioni, CPE e patch. I record di SearchSploit possono riguardare versioni differenti e NVD cerca per parole chiave; l'ordine del report non è una prova di sfruttabilità.
- Le pagine di login sono riconosciute con regole euristiche e accessi anonimi senza autenticazione. Il tool non tenta login, POST o exploit.
- L'HTTP del tool Python rimane sullo stesso origin anche in caso di redirect; Gobuster e Webanalyze sono strumenti esterni con gestione delle richieste propria. Usare target e servizi sotto il proprio controllo.
- `vulners.nse` e NVD richiedono accesso Internet; SearchSploit usa un database locale. In lab offline la fase script Vulners potrebbe non restituire CVE, ma il resto funziona.
- Le scansioni con `--min-rate` alto possono congestionare un host piccolo; ridurlo (`--min-rate 500`) se necessario.
- Per siti con virtual host, usare il **nome DNS** del target (configurare DNS/`/etc/hosts` nel laboratorio).
- Su target con certificati self-signed, Webanalyze gestisce autonomamente il TLS; `verify_tls` riguarda il fetch Python e il flag `-k` di Gobuster.

## Test (non eseguono scansioni reali)

```bash
python -m unittest discover -s tests -v
```

I test includono parsing XML NSE, validazione argomenti, scope HTTP, report e un **test end-to-end con CLI fittizi**, senza contattare alcun host.

### Riferimenti ufficiali

- [Webanalyze README](https://github.com/rverton/webanalyze)
- [Nmap NSE Vulners](https://nmap.org/nsedoc/scripts/vulners.html)
- [Kali Gobuster](https://www.kali.org/tools/gobuster/)
- [Kali SecLists](https://www.kali.org/tools/seclists/)
- [Kali ExploitDB/SearchSploit](https://www.kali.org/tools/exploitdb/)
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
