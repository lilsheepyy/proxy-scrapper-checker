package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type VerificadorProxies struct {
	URLsProxies        map[string][]string
	Timeout            time.Duration
	ReintentosMax      int
	EsperaReintento    time.Duration
	TrabajadoresMax    int
	CallbackLog        func(string)
	CallbackProgreso   func(int)
	ContextoCancelable context.Context
	FuncionCancelar    context.CancelFunc
	Objetivo           string
	IPObjetivo         string
	PuertoObjetivo     int
}

func NuevoVerificadorProxies(urlsProxies map[string][]string, timeout time.Duration, reintentosMax int, esperaReintento time.Duration, trabajadoresMax int, callbackLog func(string), callbackProgreso func(int), objetivo string) *VerificadorProxies {
	ctx, cancelar := context.WithCancel(context.Background())

	partesObjetivo := strings.Split(objetivo, ":")
	ipObjetivo := partesObjetivo[0]
	puertoObjetivo, _ := strconv.Atoi(partesObjetivo[1])

	return &VerificadorProxies{
		URLsProxies:        urlsProxies,
		Timeout:            timeout,
		ReintentosMax:      reintentosMax,
		EsperaReintento:    esperaReintento,
		TrabajadoresMax:    trabajadoresMax,
		CallbackLog:        callbackLog,
		CallbackProgreso:   callbackProgreso,
		ContextoCancelable: ctx,
		FuncionCancelar:    cancelar,
		Objetivo:           objetivo,
		IPObjetivo:         ipObjetivo,
		PuertoObjetivo:     puertoObjetivo,
	}
}

func (vp *VerificadorProxies) Log(nivel, mensaje string) {
	// Codigos de color ANSI
	rojo := "\033[31m"
	//verde := "\033[32m"
	amarillo := "\033[33m"
	azul := "\033[34m"
	reset := "\033[0m"

	var color string
	switch nivel {
	case "INFO":
		color = azul
	case "WARNING":
		color = amarillo
	case "ERROR":
		color = rojo
	default:
		color = reset
	}

	mensajeCompleto := fmt.Sprintf("%s[%s] %s%s", color, nivel, mensaje, reset)
	if vp.CallbackLog != nil {
		vp.CallbackLog(mensajeCompleto)
	} else {
		log.Println(mensajeCompleto)
	}
}

func (vp *VerificadorProxies) Cancelar() {
	vp.FuncionCancelar()
	vp.Log("INFO", "Cancelacion solicitada")
}

// Verifica proxies SOCKS4
func (vp *VerificadorProxies) VerificarSOCKS4(proxy string) bool {
	ctx, cancelar := context.WithTimeout(vp.ContextoCancelable, vp.Timeout)
	defer cancelar()

	dialer := net.Dialer{Timeout: vp.Timeout}
	conexion, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conexion.Close()

	deadline := time.Now().Add(vp.Timeout)
	conexion.SetDeadline(deadline)

	// Convierte IP y puerto objetivo a bytes para SOCKS4 (usando la flag -target)
	ip := net.ParseIP(vp.IPObjetivo).To4()
	puerto := uint16(vp.PuertoObjetivo)
	bytesPuerto := []byte{byte(puerto >> 8), byte(puerto & 0xFF)}

	// Handshake SOCKS4
	_, err = conexion.Write([]byte{0x04, 0x01, 0x00, 0x50, ip[0], ip[1], ip[2], ip[3], bytesPuerto[0], bytesPuerto[1]})
	if err != nil {
		return false
	}

	respuesta := make([]byte, 2)
	_, err = conexion.Read(respuesta)
	if err != nil {
		return false
	}

	// Verifica si la conexion fue exitosa
	return respuesta[1] == 0x5A
}

// Verifica proxies SOCKS5
func (vp *VerificadorProxies) VerificarSOCKS5(proxy string) bool {
	ctx, cancelar := context.WithTimeout(vp.ContextoCancelable, vp.Timeout)
	defer cancelar()

	dialer := net.Dialer{Timeout: vp.Timeout}
	conexion, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conexion.Close()

	deadline := time.Now().Add(vp.Timeout)
	conexion.SetDeadline(deadline)

	// Handshake SOCKS5
	_, err = conexion.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return false
	}

	respuesta := make([]byte, 2)
	_, err = conexion.Read(respuesta)
	if err != nil {
		return false
	}

	// Verifica si se acepta el metodo de autenticacion
	if respuesta[1] != 0x00 {
		return false
	}

	// Convierte IP y puerto objetivo a bytes para SOCKS5 (usando la flag -target)
	ip := net.ParseIP(vp.IPObjetivo).To4()
	puerto := uint16(vp.PuertoObjetivo)
	bytesPuerto := []byte{byte(puerto >> 8), byte(puerto & 0xFF)}

	// Envia solicitud de conexion
	_, err = conexion.Write([]byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], bytesPuerto[0], bytesPuerto[1]})
	if err != nil {
		return false
	}

	respuesta = make([]byte, 10)
	_, err = conexion.Read(respuesta)
	if err != nil {
		return false
	}

	// Verifica si la conexion fue exitosa
	return respuesta[1] == 0x00
}

// Verifica proxies HTTP
func (vp *VerificadorProxies) VerificarHTTP(proxy string) bool {
	ctx, cancelar := context.WithTimeout(vp.ContextoCancelable, vp.Timeout)
	defer cancelar()

	dialer := net.Dialer{Timeout: vp.Timeout}
	conexion, err := dialer.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return false
	}
	defer conexion.Close()

	deadline := time.Now().Add(vp.Timeout)
	conexion.SetDeadline(deadline)

	// Envia solicitud CONNECT
	solicitudConnect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", vp.Objetivo, vp.Objetivo)
	_, err = conexion.Write([]byte(solicitudConnect))
	if err != nil {
		return false
	}

	lector := bufio.NewReader(conexion)
	respuesta, err := lector.ReadString('\n')
	if err != nil {
		return false
	}

	// Verifica si la conexion fue exitosa
	return strings.HasPrefix(respuesta, "HTTP/1.1 200")
}

func (vp *VerificadorProxies) VerificarProxy(tipoProxy, proxy string) bool {
	switch tipoProxy {
	case "socks4":
		return vp.VerificarSOCKS4(proxy)
	case "socks5":
		return vp.VerificarSOCKS5(proxy)
	case "http":
		return vp.VerificarHTTP(proxy)
	default:
		return false
	}
}

// Obtiene listas de proxies desde las URLs indicadas
func (vp *VerificadorProxies) ObtenerProxies(urls []string) []string {
	var todosLosProxies []string
	for _, url := range urls {
		for intento := 0; intento <= vp.ReintentosMax; intento++ {
			if vp.ContextoCancelable.Err() != nil {
				vp.Log("INFO", "Cancelacion detectada mientras se obtenian proxies")
				return nil
			}
			resp, err := http.Get(url)
			if err == nil && resp.StatusCode == http.StatusOK {
				body, _ := ioutil.ReadAll(resp.Body)
				proxies := strings.Split(string(body), "\n")
				todosLosProxies = append(todosLosProxies, proxies...)
				break
			}
			time.Sleep(vp.EsperaReintento)
		}
	}
	return todosLosProxies
}

// Sanitiza proxies obtenidos y elimina duplicados
func (vp *VerificadorProxies) SanitizarProxies(proxies []string) []string {
	proxiesUnicos := make(map[string]struct{})
	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		proxy = strings.TrimPrefix(proxy, "http://")
		proxy = strings.TrimPrefix(proxy, "https://")
		proxy = strings.TrimPrefix(proxy, "socks4://")
		proxy = strings.TrimPrefix(proxy, "socks5://")

		partes := strings.Split(proxy, ":")
		if len(partes) >= 2 {
			ipPuerto := fmt.Sprintf("%s:%s", partes[0], partes[1])
			proxiesUnicos[ipPuerto] = struct{}{}
		}
	}

	var sanitizados []string
	for proxy := range proxiesUnicos {
		sanitizados = append(sanitizados, proxy)
	}
	return sanitizados
}

// Guarda proxies sanitizados en un archivo temporal
func (vp *VerificadorProxies) GuardarProxiesEnArchivoTemporal(tipoProxy string, proxies []string) string {
	dirTemporal := "temp_proxies"
	os.MkdirAll(dirTemporal, os.ModePerm)
	archivoTemporal := fmt.Sprintf("%s/%s.txt", dirTemporal, tipoProxy)
	archivo, err := os.Create(archivoTemporal)
	if err != nil {
		vp.Log("ERROR", fmt.Sprintf("No se pudieron guardar proxies %s en %s: %v", tipoProxy, archivoTemporal, err))
		return ""
	}
	defer archivo.Close()

	escritor := bufio.NewWriter(archivo)
	for _, proxy := range proxies {
		fmt.Fprintln(escritor, proxy)
	}
	escritor.Flush()
	vp.Log("INFO", fmt.Sprintf("Proxies %s sanitizados guardados en %s", tipoProxy, archivoTemporal))
	return archivoTemporal
}

// Carga proxies desde un archivo temporal
func (vp *VerificadorProxies) CargarProxiesDesdeArchivoTemporal(archivoTemporal string) []string {
	archivo, err := os.Open(archivoTemporal)
	if err != nil {
		vp.Log("ERROR", fmt.Sprintf("No se pudieron cargar proxies desde %s: %v", archivoTemporal, err))
		return nil
	}
	defer archivo.Close()

	var proxies []string
	scanner := bufio.NewScanner(archivo)
	for scanner.Scan() {
		proxies = append(proxies, scanner.Text())
	}
	vp.Log("INFO", fmt.Sprintf("%d proxies cargados desde %s", len(proxies), archivoTemporal))
	return proxies
}

// Barra de progreso
func (vp *VerificadorProxies) ActualizarBarraProgreso(procesados, total int) {
	verde := "\033[32m"
	reset := "\033[0m"

	progreso := float64(procesados) / float64(total)
	largoBarra := 50
	rellenos := int(progreso * float64(largoBarra))
	barra := verde + strings.Repeat("=", rellenos) + reset + strings.Repeat(" ", largoBarra-rellenos)
	fmt.Printf("\r[%s] %.0f%%", barra, progreso*100)
}

// Verifica proxies
func (vp *VerificadorProxies) ProcesarProxies(tipoProxy string, urls []string, maxChecks int) int {
	proxiesCrudos := vp.ObtenerProxies(urls)
	sanitizados := vp.SanitizarProxies(proxiesCrudos)
	rutaTemporal := vp.GuardarProxiesEnArchivoTemporal(tipoProxy, sanitizados)
	if rutaTemporal == "" {
		return 0
	}

	proxies := vp.CargarProxiesDesdeArchivoTemporal(rutaTemporal)
	total := len(proxies)
	if total == 0 {
		return 0
	}

	var wg sync.WaitGroup
	funcionales := make(chan string, total)
	tokens := make(chan struct{}, maxChecks)
	procesados := 0

	go func() {
		for procesados < total {
			vp.ActualizarBarraProgreso(procesados, total)
			time.Sleep(300 * time.Millisecond)
		}
	}()

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			tokens <- struct{}{}
			defer func() { <-tokens }()

			if vp.VerificarProxy(tipoProxy, p) {
				funcionales <- p
			}

			procesados++
		}(proxy)
	}

	wg.Wait()
	close(funcionales)

	vp.ActualizarBarraProgreso(procesados, total)
	fmt.Println()

	var proxiesFuncionales []string
	for funcional := range funcionales {
		proxiesFuncionales = append(proxiesFuncionales, funcional)
	}

	vp.GuardarProxiesFuncionales(tipoProxy, proxiesFuncionales)
	return len(proxiesFuncionales)
}

// Guarda los proxies funcionales
func (vp *VerificadorProxies) GuardarProxiesFuncionales(tipoProxy string, proxies []string) {
	dirFinal := "proxies"
	os.MkdirAll(dirFinal, os.ModePerm)
	rutaFinal := fmt.Sprintf("%s/%s.txt", dirFinal, strings.ToUpper(tipoProxy))

	archivo, err := os.Create(rutaFinal)
	if err != nil {
		vp.Log("ERROR", fmt.Sprintf("No se pudieron guardar proxies %s: %v", tipoProxy, err))
		return
	}
	defer archivo.Close()

	escritor := bufio.NewWriter(archivo)
	for _, proxy := range proxies {
		fmt.Fprintln(escritor, proxy)
	}
	escritor.Flush()
	vp.Log("INFO", fmt.Sprintf("%d proxies %s funcionales guardados en %s", len(proxies), tipoProxy, rutaFinal))
}

// Guarda proxies sanitizados sin verificar
func (vp *VerificadorProxies) GuardarProxiesSanitizados(tipoProxy string, proxies []string) {
	dirFinal := "proxies"
	os.MkdirAll(dirFinal, os.ModePerm)
	rutaFinal := fmt.Sprintf("%s/%s.txt", dirFinal, strings.ToUpper(tipoProxy))

	archivo, err := os.Create(rutaFinal)
	if err != nil {
		vp.Log("ERROR", fmt.Sprintf("No se pudieron guardar proxies %s sanitizados: %v", tipoProxy, err))
		return
	}
	defer archivo.Close()

	escritor := bufio.NewWriter(archivo)
	for _, proxy := range proxies {
		fmt.Fprintln(escritor, proxy)
	}
	escritor.Flush()
	vp.Log("INFO", fmt.Sprintf("%d proxies %s sanitizados guardados en %s", len(proxies), tipoProxy, rutaFinal))
}

// Procesa todos los tipos de proxies y verifica su funcionamiento
func (vp *VerificadorProxies) Ejecutar(maxChecks int, verificar bool) {
	for tipoProxy, urls := range vp.URLsProxies {
		if vp.ContextoCancelable.Err() != nil {
			break
		}
		vp.Log("INFO", fmt.Sprintf("%s", strings.Repeat("=", 40)))
		if verificar {
			vp.Log("INFO", fmt.Sprintf("Procesando proxies %s (scrape + sanitize + check)", strings.ToUpper(tipoProxy)))
		} else {
			vp.Log("INFO", fmt.Sprintf("Procesando proxies %s (solo scrape + sanitize)", strings.ToUpper(tipoProxy)))
		}
		vp.Log("INFO", fmt.Sprintf("%s", strings.Repeat("=", 40)))

		if !verificar {
			proxiesCrudos := vp.ObtenerProxies(urls)
			sanitizados := vp.SanitizarProxies(proxiesCrudos)
			vp.GuardarProxiesSanitizados(tipoProxy, sanitizados)
			continue
		}

		vp.ProcesarProxies(tipoProxy, urls, maxChecks)
	}
}

// Carga URLs de proxies desde el archivo JSON
func CargarURLsDesdeJSON(rutaArchivo string) map[string][]string {
	data, err := ioutil.ReadFile(rutaArchivo)
	if err != nil {
		log.Fatalf("Error cargando %s: %v", rutaArchivo, err)
	}

	var urlsProxies map[string][]string
	if err := json.Unmarshal(data, &urlsProxies); err != nil {
		log.Fatalf("Error parseando JSON: %v", err)
	}
	return urlsProxies
}

func main() {
	maxChecks := flag.Int("max-checks", 1000, "Cantidad maxima de verificaciones concurrentes de proxies")
	objetivo := flag.String("target", "1.1.1.1:80", "IP y puerto objetivo para verificar proxies en formato ip:puerto")
	timeout := flag.Int("timeout", 5, "Timeout en segundos para conexiones proxy")
	verificar := flag.Bool("check", false, "Habilita verificacion de proxies despues de scraping y sanitizado (default: false)")
	flag.Parse()

	urlsProxies := CargarURLsDesdeJSON("urls.json")

	callbackLog := func(msg string) {
		log.Println(msg)
	}
	callbackProgreso := func(progreso int) {
		log.Printf("Progreso: %d%%\n", progreso)
	}

	verificador := NuevoVerificadorProxies(urlsProxies, time.Duration(*timeout)*time.Second, 0, 1*time.Second, 50, callbackLog, callbackProgreso, *objetivo)
	defer verificador.Cancelar()

	// Codigos de color ANSI
	rojo := "\033[31m"
	verde := "\033[32m"
	amarillo := "\033[33m"
	azul := "\033[34m"
	reset := "\033[0m"

	asciiCat := " ~ᓚᘏᗢ~  zZz"

	fmt.Println(amarillo + "============================================" + reset)
	fmt.Println(azul + asciiCat + reset)
	fmt.Println(verde + " Verificador de Proxies por " + rojo + "lilsheepyy" + reset)
	fmt.Println(azul + " GitHub: https://github.com/lilsheepyy" + reset)
	fmt.Println(amarillo + "============================================" + reset)

	verificador.Ejecutar(*maxChecks, *verificar)
	log.Println("Terminado")
}
