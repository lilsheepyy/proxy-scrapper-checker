# UltraProxy

**UltraProxy** es un scrapper y verificador de proxies en Go, enfocado al alto rendimiento, con soporte para proxies **SOCKS4, SOCKS5 y HTTP**. Por defecto obtiene y sanitiza proxies, y de forma opcional puede probarlos cuando se habilita el modo de verificacion.

Con capacidad de **extraer aproximadamente 350.000 proxies por tipo**, ofrece una base amplia de proxies para trabajar.

---

## Caracteristicas

- Soporte para tipos de proxy **SOCKS4, SOCKS5 y HTTP**
- Obtiene proxies desde URLs en un archivo JSON (`urls.json`)
- **Soporte de concurrencia** con limite configurable de workers
- **Seguimiento de progreso** y logs
- Guarda proxies funcionales en **archivos categorizados**
- Soporte de cancelacion elegante usando **context**
- Un gatito ^^

---

## Instalacion

Asegurate de tener **Go 1.18+** instalado.

```sh
git clone https://github.com/lilsheepyy/proxy-scrapper-checker
cd proxy-scrapper-checker
go run main.go
```

## Opciones

- `-max-checks` -> Cantidad maxima de verificaciones concurrentes de proxies (default: `1000`). Recomiendo bajarlo para un mejor resultado aunque tarde mas; tambien depende de tu servidor.
- `-target` -> IP y puerto para probar proxies (default: `1.1.1.1:80`)
- `-timeout` -> Timeout en segundos para conexiones proxy
- `-check` -> Habilita verificacion de proxies luego de scraping y sanitizado (default: `false`)

## Ejemplo

```sh
go run main.go
```

## Ejemplo con verificacion habilitada

```sh
go run main.go -check -target 1.1.1.1:80 -max-checks 1000 -timeout 5
```

## DESCARGO DE RESPONSABILIDAD

SI SOLO TE ESTAN FUNCIONANDO 5 PROXIES, BAJA TUS AJUSTES.

ESTO SOLO COMPRUEBA SI EL PROXY PUEDE HACER CONEXIONES TCP RAW (estoy trabajando en comprobar trafico a traves del proxy)

## TODO

- Mejorar el sistema de sanitizacion
- Cualquier otra cosa que se me ocurra

---

## Contacto

- Telegram: [t.me/sheepthesillycat](https://t.me/sheepthesillycat)
- Web: [sheepyy.love](https://sheepyy.love)

Gracias por usarlo.
Despues de 2 años he decidido continuar este proyecto.
