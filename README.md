# Laboratorio Cortex XSIAM — Deep Dive

Simulador de fuentes de log para el curso. Genera trafico realista de WAF, firewall,
EDR y autenticacion, y lo envia a tu tenant por el HTTP Log Collector.

## Puesta en marcha (Dia 2)

Necesitas **Python 3.9 o superior** y salida a Internet hacia el tenant.

```bash
git clone <URL-DE-ESTE-REPO>
cd xsiam-lab/simulator

pip install -r requirements.txt

cp config.example.json config.json     # pega la URL del tenant y tus 4 API keys
python run_lab.py check                # deben salir 4 OK
```

En Windows, si `python` no responde usa `py`, y en vez de `cp` usa `copy`:

```powershell
copy config.example.json config.json
py -m pip install -r requirements.txt
py run_lab.py check
```

Antes de eso tienes que haber creado tus 4 colectores HTTP en XSIAM:

| Nombre | Vendor | Product | Log Format |
|---|---|---|---|
| `EQn-waf` | imperva | securesphere | **CEF** |
| `EQn-fw` | andina | ngfw | **Raw** |
| `EQn-edr` | andina | edr | **JSON** |
| `EQn-auth` | andina | idp | **JSON** |

De cada uno anota **la API key** y **el nombre del dataset**. Ese nombre lo vas a usar
los tres dias siguientes.

## Cargar los datos

```bash
python run_lab.py baseline --hours 48 --eps-scale 0.4
```

Tarda un par de minutos. Ten abierto **Data Management -> Data Ingestion** y mira subir
las barras.

## Comandos

| Comando | Para que |
|---|---|
| `python run_lab.py check` | Mis colectores reciben eventos? |
| `python run_lab.py baseline --hours 48 --eps-scale 0.4` | Trafico normal del negocio |
| `python run_lab.py baseline --hours 2 --eps-scale 0.5` | Chorro corto, para ver llegar los datos |
| cualquiera + `--dry-run` | No envia nada: escribe los eventos en `out/` |

## Si algo falla

| Que ves | Que pasa |
|---|---|
| `No module named requests` | Falto `pip install -r requirements.txt` |
| `python: command not found` | En Windows suele ser `py` en vez de `python` |
| `HTTP 401` | API key mal copiada (casi siempre sobra un espacio) o colector deshabilitado |
| `HTTP 404` | URL del tenant mal escrita en `config.json` |
| 200 pero no ves nada | Espera 1-2 min y revisa que miras el dataset correcto |

## Nota

El comando `attack` existe pero esta deshabilitado en este repositorio: la campana la
controla el instructor. Es a proposito.

Tu `config.json` esta en el `.gitignore`. No lo subas: contiene tus API keys.
