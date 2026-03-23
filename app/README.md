# Guardian LAN Final

Guardian LAN je lokální rodičovská kontrola pro Windows a LAN. Program běží na pozadí, webová správa je dostupná na `localhost` i přes IP počítače v rámci privátní sítě.

## Hlavní funkce

- blokování domén přes Windows `hosts`
- blacklist a whitelist režim pro aplikace
- blokování aplikací podle názvu procesu
- globální časové pravidlo
- týdenní kalendář po dnech v týdnu s vlastními časy a texty
- popup upozornění pro dítě
- logování událostí a export do CSV
- logování navštívených domén z historie podporovaných prohlížečů
- lokální desktop admin okno
- systémová tray ikona (pokud jsou nainstalované `pystray` a `Pillow`)
- autostart přes Plánovač úloh
- watchdog spuštění přes `python run_guarded.py`
- dočasné odblokování celé ochrany
- dočasné povolení konkrétní aplikace

## Podporované prohlížeče pro logování historie

- Google Chrome
- Microsoft Edge
- Brave
- Mozilla Firefox

## Omezení

- nečte, co dítě píše do Google nebo jiných polí
- nefiltruje HTTPS obsah podle textu stránky
- whitelist režim je implementovaný pro **aplikace**, ne pro weby
- pro zápis do `hosts` je potřeba spustit program jako administrátor

## Spuštění ve vývoji

```bash
pip install -r requirements.txt
python run.py
```

Lokální admin okno:

```bash
python -m app.desktop_admin
```

Watchdog:

```bash
python run_guarded.py
```

Výchozí přihlášení:

- uživatel: `admin`
- heslo: `admin123`

## Přístup v síti

- lokálně: `http://127.0.0.1:8787`
- v LAN: `http://IP_PC:8787`

Nepovolovat port do internetu.

## Build Windows EXE

```bat
pyinstaller --noconsole --onedir --add-data "app;app" --hidden-import passlib --hidden-import passlib.handlers --hidden-import passlib.handlers.pbkdf2 run.py
```
