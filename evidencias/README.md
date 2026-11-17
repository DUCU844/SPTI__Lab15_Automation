# Evidencias — Lab 15 (Automation)

Capturas de pantalla completas tomadas **dentro de la VM de Kali** (`kali@kali`, IP `10.0.2.15`, VirtualBox)
mientras se ejecutaba cada paso del laboratorio el 16 de noviembre de 2026, entre las 21:42 y las 22:20
(ventana autorizada en `scope.txt`: 21:30 – 01:30). Cada captura muestra el comando y su salida real; el reloj
de Kali aparece arriba a la derecha.

| Captura | Parte | Qué demuestra |
|---|---|---|
| `00_parte0_objetivo_ssh_y_listeners.png` | 0 (analista) | SSH activo y tres `python3 -m http.server` (311, 444, 808) corriendo como root desde directorios vacíos; responden HTTP 200 |
| `01_parte0_scope_y_logs_plantados.png` | 0 | `scope.txt` (Handoff 1), clave de respuestas del analista, generación de `auth.log` y `access.log` con hallazgos plantados y `planted.json` (Handoff 2) |
| `02_parte1_AB_benchmark_secuencial_hilos_asyncio.png` | 1 A/B | Tiempos del escáner secuencial, `ThreadPoolExecutor` (50/200/500/2000) y `asyncio` + `Semaphore` (50/200/500/2000), con puertos conocidos encontrados en cada caso |
| `03_parte1_C_cli_argparse.png` | 1 C | `scanner.py --help` con todos los flags, `--ports 22,80,443`, validación de argumentos y rechazo de un objetivo fuera de `scope.txt` |
| `04_parte1_D_scan_rate200_json.png` | 1 D | Corridas con `--rate 200` y `--rate 2000` (aviso de `ulimit -n`, código de salida 3) y contenido de `scan_rate200.json` |
| `05_parte1_D_scan_rate2000_json_y_handoff3.png` | 1 D / Handoff 3 | `scan_rate2000.json` (6 sondas `EMFILE`, `complete: false`) y comparación del analista contra su clave de respuestas |
| `05a_parte1_primera_version_scanner_falso_positivo_y_timeouts.png` | 1 (hallazgo) | Primera versión del escáner: una corrida pierde el puerto 444; en el rango completo aparece el falso positivo 56846 (auto-conexión TCP) y se pierde el 22 por timeouts. Motivó las correcciones de `scanner.py` |
| `06_parte1_30_corridas_rate2000_falsos_negativos.png` | Handoff 3 | 30 corridas a `--rate 2000`: 6 `EMFILE` en cada una; 1 de 30 pierde un puerto abierto conocido (22) |
| `07_parte1_rango_completo_emfile_y_versiones_ingenuas.png` | 1 (pregunta) | Rango 1-65535: `--rate 200` 5/5, `--rate 2000` 0/5 con 64 517 `EMFILE`, `--retry-unknown` 5/5; y las versiones ingenuas, donde asyncio a 2000 reporta 0/5 sin avisar |
| `08_parte2_A_nmap_sV_xml.png` | 2 A | `nmap -sV --open -oX part2/scan.xml 10.0.2.15` y la estructura del XML (host, address, ports, port, state, service) |
| `09_parte2_BCD_parse_scan_y_ssh_keyscan.png` | 2 B/C/D | `parse_scan.py --help`, salida de `ssh-keyscan`, ejecución con `--input/--output` y manejo de errores (SSH sin respuesta, XML inválido) |
| `09b_parte2_D_hosts_json.png` | 2 D | `part2/hosts.json` con `ssh_host_key_type` |
| `10_parte2_rastro_de_nmap_sV_en_el_objetivo.png` | 2 (pregunta) | Log de un listener: las sondas de `-sV` quedan registradas (`/nmaplowercheck…`, `POST /sdk`, `/HNAP1`); el escaneo connect no dejó nada |
| `11_parte3_A_auth_analysis_v1.png` | 3 A (1ª iteración) | Primer análisis de `auth.log` del analista |
| `12_parte3_CD_log_analysis_v1.png` | 3 C/D (1ª iteración) | Primer análisis de `access.log` con el regex de la teoría y 3-sigma |
| `13_parte3_puntaje_v1_contra_planted.png` | Handoff 4 | Puntaje del ingeniero al primer reporte: 14/27 detectados, 13 fallos, 2 falsos positivos |
| `14_parte3_A_auth_analysis_final.png` | 3 A | `auth_analysis.py` final: IPs con más de 10 fallos, cuentas atacadas (con `invalid user`), razón fallidos:exitosos, login exitoso tras fallos; y el pipeline `grep \| awk \| sort \| uniq -c` de la teoría |
| `15_parte3_C_log_analysis_final_ataques_top5_status.png` | 3 C | `log_analysis.py` final: peticiones por familia de ataque, top 5 IPs, distribución de códigos de estado |
| `16_parte3_D_anomalias_3sigma_y_MAD.png` | 3 D | `[ANOMALY] 19:00 — 950 requests (z≈4.5σ, threshold=3.0σ)` y el detector robusto mediana/MAD que encuentra la ráfaga de las 04:00 |
| `17_parte3_E_report_md_combinado.png` | 3 E | Generación de `part3/report.md` con una sección por categoría de hallazgo |
| `17b_parte3_puntaje_final_contra_planted.png` | 3 (juntos) | Puntaje final tras las correcciones: 27/27 detectados, 2 falsos positivos documentados |
| `18_parte4_cli_argparse.png` | 4 (req. 1) | `recon.py --help`, detección automática de modo y errores de argumentos |
| `19_parte4_corrida_modo_ip.png` | 4 (req. 4) | Corrida en modo IP contra `10.0.2.15` con `--verbose` y archivos generados en `sample_output/` |
| `20_parte4_audit_log_modo_ip.png` | 4 (req. 2) | `audit.log`: cada comando, su resultado y marca de tiempo |
| `21_parte4_results_json_modo_ip_nmap_dig_whois.png` | 4 (req. 5) | `results.json`: llaves `meta`, `nmap`, `dig`, `whois` con datos estructurados |
| `22_parte4_results_json_modo_ip_curl.png` | 4 (req. 5) | `results.json`: llave `curl` con cabeceras y cabeceras de seguridad ausentes |
| `23_parte4_report_md_modo_ip_resumen_y_puertos.png` | 4 (req. 6) | `report.md`: tabla resumen, puertos abiertos, DNS inverso y propietario |
| `24_parte4_report_md_modo_ip_cabeceras.png` | 4 (req. 6) | `report.md`: cabeceras HTTP y cabeceras de seguridad ausentes (CSP, HSTS, X-Frame-Options) |
| `25_parte4_corrida_y_audit_log_modo_dominio.png` | 4 (req. 3) | Corrida en modo dominio (`example.com`) y su `audit.log` |
| `26_parte4_results_json_modo_dominio_1.png`, `27_…_2.png` | 4 (req. 5) | `results.json` del modo dominio: whois, registros A/MX/NS/TXT, cabeceras |
| `28_parte4_report_md_modo_dominio_resumen.png`, `29_…_dns_y_cabeceras.png` | 4 (req. 6) | `report.md` del modo dominio: resumen, registro, registros DNS, cabeceras ausentes |
| `30_parte4_etapas_fallan_de_forma_independiente.png` | 4 (criterio 20 %) | Dominio inexistente (fallan whois y curl, dig sigue) y `nmap` ausente del `PATH` (falla nmap, dig y whois siguen); código de salida 1 y archivos generados |
| `31_parte4_handoff6_report_desde_results_json.png` | Handoff 6 | El analista reconstruye `report.md` sólo desde el `results.json` del ingeniero; resultado idéntico |
| `32_parte4_verificacion_del_audit_log.png` | 4 (juntos) | `part4/verify_audit.py`: los comandos realmente ejecutados coinciden uno a uno con `audit.log` en ambos modos |
| `33_rastro_real_en_sshd_del_objetivo.png` | 2 y 4 (preguntas) | Journal real de sshd en el objetivo durante los escaneos: el reconocimiento activo deja rastro |
| `34_cierre_objetivo_detenido.png` | Cierre | Listeners detenidos y SSH devuelto a su estado inicial |

Las salidas en texto de los mismos pasos quedaron en los archivos del repositorio: `scan_rate*.json`,
`part1/benchmark_results.md`, `part1/benchmark_full_results.md`, `part2/scan.xml`, `part2/hosts.json`,
`part2/target_sshd_journal.log`, `part3/report.md`, `part3/v1/`, `findings_score.md`, `sample_output/` y
`part4/audit_verification_*.txt`.

`transcripciones/` contiene la salida de texto completa de la terminal para cada bloque de pasos (lo mismo que
se ve en las capturas, sin recortar por el alto de la pantalla), por si se necesita copiar una salida al informe.
