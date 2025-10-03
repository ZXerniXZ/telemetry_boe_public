"""
Telemetry Backend - Sistema di monitoraggio boe
==============================================

Backend FastAPI per la gestione e il monitoraggio delle boe telemetriche.
Supporta scansione automatica, connessione/disconnessione, cambio stato e navigazione.
"""

import os
import math
import signal
import sys
import subprocess
import socket
import threading
import time
import atexit
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

import nmap
import logging
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from paho.mqtt import client as mqtt
from pydantic import BaseModel, EmailStr
from pymavlink import mavutil
from datetime import datetime, timedelta
import secrets

load_dotenv()

from fetch_boe.shared import (
    MQTT_HOST, MQTT_PORT, MQTT_TOPIC_FMT, MQTT_QOS, MQTT_RETAIN, LOG_LEVEL, 
    PUBLISH_INTERVAL, HEARTBEAT_HZ, HEARTBEAT_PERIOD, DEVICE_TIMEOUT,
    VAI_A_RETRY_SEC, VAI_A_TOLERANCE_METERS, VAI_A_TIMEOUT_SEC
)
from fetch_boe.database import user_db


# =============================================================================
# CONFIGURAZIONE E INIZIALIZZAZIONE
# =============================================================================

app = FastAPI(
    title="Telemetry Backend",
    description="Backend per il monitoraggio e controllo delle boe telemetriche",
    version="1.0.0"
)

# Configurazione CORS per ambiente Docker/VPN
# In produzione, limitare agli indirizzi specifici necessari
allowed_origins = [
    "http://localhost:5173",
    "http://165.227.133.135:5173",
    "http://18.198.0.86:5173",
    "http://127.0.0.1:5173",
    "http://0.0.0.0:5173",
    "http://10.8.0.9:5173",
    # Docker network addresses
    "http://172.19.0.1:5173",
    "http://172.19.0.2:5173",
    "http://172.19.0.3:5173", 
    "http://172.19.0.4:5173",
    "http://172.19.0.5:5173",
    # Frontend container internal addresses
    "http://telemetry_frontend:5173",
    "http://frontend:5173",
    # Additional VPN and network ranges
    "http://10.19.0.9:5173",
    "http://10.114.0.3:5173",
]

# Per ambiente di sviluppo Docker, essere più permissivi
# Rileva se siamo in ambiente containerizzato
is_docker = os.path.exists('/.dockerenv')
if is_docker:
    # In ambiente Docker, permettiamo più flessibilità
    allowed_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health endpoint semplice per healthcheck Docker
@app.get("/health")
def health() -> str:
    return "healthy"

# Configurazione ambiente
SCAN_SUBNET = os.environ.get("SCAN_SUBNET", "10.8.0.0/24")
MIN_LAST_OCTET = int(os.environ.get("MIN_LAST_OCTET", "30"))

# Thread pool e stato globale
serializer_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="json")
active_boes = {}        # {boa_key: (thread, stop_event)}
active_boes_lock = threading.Lock()
active_vaia = {}        # {boa_key: (thread, stop_event, vaia_info)}
active_vaia_lock = threading.Lock()

# Logging
logger = logging.getLogger("telemetry_backend")
logging.basicConfig(level=logging.INFO)


# =============================================================================
# UTILITIES MQTT
# =============================================================================

def publish_isonline(ip: str, port: int, is_online: bool) -> None:
    """Pubblica lo stato online/offline di una boa tramite MQTT."""
    topic_base = MQTT_TOPIC_FMT.format(f"{ip.replace('.', '_')}_{port}")
    isonline_topic = f"{topic_base}/isonline"
    
    client = mqtt.Client(client_id=f"isonline_{ip}_{port}", clean_session=True)
    try:
        client.connect(MQTT_HOST, MQTT_PORT, keepalive=5)
        client.loop_start()
        client.publish(isonline_topic, str(is_online).lower(), qos=MQTT_QOS, retain=True)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        logger.warning(f"[MQTT] Errore pubblicando isonline={is_online} per {ip}:{port}: {e}")


# =============================================================================
# UTILITIES MAVLINK
# =============================================================================

def _pid_to_str(pid) -> str:
    """Converte parameter ID MAVLink in stringa."""
    if isinstance(pid, (bytes, bytearray)):
        return pid.decode(errors="ignore").rstrip("\x00")
    return str(pid).rstrip("\x00")


def _name_to_pid(name: str) -> bytes:
    """Converte nome parametro in parameter ID MAVLink."""
    return name.encode()[:16]


def _set_param(ip: str, port: int, param_name: str, value: float, timeout: float = 2.0) -> None:
    """
    Imposta un parametro MAVLink sulla boa specificata.
    
    Args:
        ip: Indirizzo IP della boa
        port: Porta della boa
        param_name: Nome del parametro da impostare
        value: Valore da assegnare al parametro
        timeout: Timeout per l'operazione
        
    Raises:
        RuntimeError: Se l'operazione fallisce
    """
    mav = mavutil.mavlink_connection(
        f"udpout:{ip}:{port}",
        dialect="ardupilotmega",
        source_system=255,
        autoreconnect=True,
        timeout=2,
    )

    # Ping iniziale per stabilire connessione UDP
    for _ in range(3):
        mav.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID,
            0, 0, 0
        )
        time.sleep(0.2)

    mav.wait_heartbeat(timeout=2)

    # Rileva tipo parametro attuale
    try:
        mav.mav.param_request_read_send(
            mav.target_system,
            mav.target_component,
            _name_to_pid(param_name), 
            -1
        )
        msg = mav.recv_match(type="PARAM_VALUE", blocking=True, timeout=2)
        ptype = msg.param_type if msg else mavutil.mavlink.MAV_PARAM_TYPE_REAL32
    except Exception:
        ptype = mavutil.mavlink.MAV_PARAM_TYPE_REAL32

    # Imposta parametro
    mav.mav.param_set_send(
        mav.target_system, 
        mav.target_component,
        _name_to_pid(param_name), 
        float(value), 
        ptype
    )

    # Attende conferma
    deadline = time.time() + timeout
    ok = False
    while time.time() < deadline:
        msg = mav.recv_match(type="PARAM_VALUE", blocking=True, timeout=1)
        if msg and _pid_to_str(msg.param_id) == param_name:
            ok = abs(msg.param_value - float(value)) < 1e-4
            break
    
    mav.close()
    if not ok:
        raise RuntimeError(f"Set {param_name}={value} non confermato")


# =============================================================================
# THREAD DI MONITORAGGIO BOA
# =============================================================================

def thread_wrapper(ip: str, port: int, pool, stop_event: threading.Event) -> None:
    """
    Thread principale per il monitoraggio di una boa.
    Gestisce connessione, riconnessione automatica e aggiornamento stato MQTT.
    """
    boa_key = f"{ip}:{port}"
    from fetch_boe.fetch_script import handle_device
    
    was_online = False
    fail_count = 0
    MAX_FAILS = 3
    
    while not stop_event.is_set():
        sysid_set = False
        try:
            logger.info(f"[{boa_key}] Tentativo connessione e set SYSID_THISMAV → 21")
            _set_param(ip, port, "SYSID_THISMAV", 21, timeout=2.0)
            sysid_set = True
            logger.info(f"[{boa_key}] SYSID_THISMAV impostato. Avvio telemetria.")
            
            if not was_online:
                publish_isonline(ip, port, True)
                was_online = True
            
            fail_count = 0
            handle_device(ip, port, pool, stop_event=stop_event)
            
        except Exception as e:
            logger.error(f"[{boa_key}] Errore/Disconnessione: {e}")
            fail_count += 1
            
            if fail_count >= MAX_FAILS and was_online:
                publish_isonline(ip, port, False)
                was_online = False
            
            # Attendi prima di riprovare
            for _ in range(10):
                if stop_event.is_set():
                    break
                time.sleep(0.1)
                
        finally:
            # Ripristina SYSID solo se era stato impostato
            if sysid_set:
                try:
                    logger.info(f"[{boa_key}] Ripristino SYSID_THISMAV → 1")
                    _set_param(ip, port, "SYSID_THISMAV", 1, timeout=2.0)
                except Exception as e:
                    logger.warning(f"[{boa_key}] Ripristino SYSID fallito: {e}")
    
    # Cleanup finale
    publish_isonline(ip, port, False)
    with active_boes_lock:
        active_boes.pop(boa_key, None)
    logger.info(f"[{boa_key}] Thread terminato.")


# =============================================================================
# GESTIONE SHUTDOWN
# =============================================================================

def set_all_boes_offline() -> None:
    """Marca tutte le boe come offline all'arresto del sistema."""
    for boa_key in list(active_boes.keys()):
        ip, port = boa_key.split(":")
        topic_base = MQTT_TOPIC_FMT.format(f"{ip.replace('.', '_')}_{port}")
        isonline_topic = f"{topic_base}/isonline"
        
        client = mqtt.Client(client_id=f"shutdown_{ip}_{port}", clean_session=True)
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=5)
            client.loop_start()
            client.publish(isonline_topic, "false", qos=MQTT_QOS, retain=True)
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass


def handle_shutdown_signal(signum, frame) -> None:
    """Gestisce i segnali di shutdown per un arresto pulito."""
    logger.info(f"Ricevuto segnale {signum}, setto tutte le boe offline prima di uscire...")
    set_all_boes_offline()
    sys.exit(0)


atexit.register(set_all_boes_offline)
signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)


# =============================================================================
# MODELLI PYDANTIC
# =============================================================================

class BoaRequest(BaseModel):
    """Richiesta per operazioni su una boa."""
    ip: str
    port: int


class StatoEnum(str, Enum):
    """Stati operativi disponibili per le boe."""
    hold = "hold"
    loiter = "loiter"


class CambiaStatoRequest(BaseModel):
    """Richiesta per cambio stato di una boa."""
    ip: str
    port: int
    stato: StatoEnum


class VaiaRequest(BaseModel):
    """Richiesta per comando di navigazione."""
    ip: str
    port: int
    lat: float
    lon: float
    alt: float = 10.0


class VaiaStopRequest(BaseModel):
    """Richiesta per fermare comando di navigazione."""
    ip: str
    port: int

# =============================================================================
# MODELLI PER AUTENTICAZIONE E GESTIONE UTENTI
# =============================================================================

class UserLoginRequest(BaseModel):
    """Richiesta di login."""
    username: str
    password: str

class UserRegisterRequest(BaseModel):
    """Richiesta di registrazione."""
    username: str
    password: str
    email: str
    full_name: str
    phone: str = None

class UserResponse(BaseModel):
    """Risposta con dati utente."""
    id: int
    username: str
    email: str
    role: str
    full_name: str
    created_at: str
    last_login: str | None = None
    is_active: bool

class TokenResponse(BaseModel):
    """Risposta con token di accesso."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# =============================================================================
# ENDPOINT API - GESTIONE BASE
# =============================================================================

@app.get("/scan")
def scan_boes():
    """Scansiona la rete alla ricerca di boe disponibili."""
    # Test temporaneo: prova a connettere direttamente alla boa nota
    test_ips = ["10.8.0.54", "192.168.50.1", "192.168.50.10"]
    test_ports = [14550, 14551, 5760]  # Porte comuni per MAVLink
    
    found = []
    for ip in test_ips:
        try:
            # Test connessione TCP sulla porta MAVLink
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 14550))
            sock.close()
            
            if result == 0:
                found.append(ip)
                logger.info(f"[scan] IP {ip} raggiungibile sulla porta 14550")
            else:
                logger.info(f"[scan] IP {ip} non raggiungibile sulla porta 14550")
        except Exception as e:
            logger.warning(f"[scan] Errore testando {ip}: {e}")
    
    # Test anche con nmap sulla subnet originale
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=SCAN_SUBNET, arguments='-sn -n -T4')
        
        for host in nm.all_hosts():
            try:
                last_octet = int(host.strip().split('.')[-1])
                if last_octet > MIN_LAST_OCTET and host not in found:
                    found.append(host)
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"[scan] Errore nmap: {e}")
    
    logger.info(f"[scan] Risultato scan: {found}")
    return {"found": found}


@app.get("/scan-test")
def scan_test():
    """Endpoint di test che simula la presenza di boe per verificare il sistema."""
    # Simula la presenza di boe note per test
    test_boes = [
        {
            "ip": "10.8.0.54",
            "port": 14550,
            "name": "Boa Test 1",
            "status": "simulated"
        },
        {
            "ip": "192.168.50.1", 
            "port": 14550,
            "name": "Boa Test 2",
            "status": "simulated"
        }
    ]
    
    logger.info(f"[scan-test] Restituendo boe di test: {len(test_boes)} boe")
    return {
        "found": [boa["ip"] for boa in test_boes],
        "boes": test_boes,
        "message": "Test endpoint - boe simulate per verifica sistema"
    }


@app.post("/aggiungiboa")
def aggiungi_boa(req: BoaRequest):
    """Aggiunge una boa al monitoraggio attivo."""
    boa_key = f"{req.ip}:{req.port}"
    
    with active_boes_lock:
        if boa_key in active_boes:
            raise HTTPException(400, "Boa già monitorata")

        stop_event = threading.Event()
        t = threading.Thread(
            target=thread_wrapper,
            name=f"dev-{boa_key}",
            args=(req.ip, req.port, serializer_pool, stop_event),
            daemon=True,
        )
        t.start()
        active_boes[boa_key] = (t, stop_event)
    
    logger.info(f"[{boa_key}] Boa aggiunta e thread avviato")
    return {"status": "started", "boa": boa_key}


@app.delete("/rimuoviboa")
def rimuovi_boa(ip: str, port: int):
    """Rimuove una boa dal monitoraggio attivo."""
    boa_key = f"{ip}:{port}"
    
    with active_boes_lock:
        entry = active_boes.get(boa_key)
        if not entry:
            raise HTTPException(404, "Boa non trovata")

        t, stop_event = entry
        stop_event.set()
        t.join(timeout=5)
        active_boes.pop(boa_key, None)
    
    logger.info(f"[{boa_key}] Thread fermato da API")
    return {"status": "stopped", "boa": boa_key}


# =============================================================================
# ENDPOINT API - CONTROLLO STATO
# =============================================================================

# Mapping modalità ArduPilot
ARDUPILOT_MODE_MAP = {
    "hold": 0,      # HOLD
    "loiter": 5,    # LOITER
}


def set_boa_state(ip: str, port: int, stato: StatoEnum) -> None:
    """Imposta lo stato operativo di una boa."""
    mode_id = ARDUPILOT_MODE_MAP[stato.value]
    logger.info(f"[set_boa_state] Cambio modalità: {stato.value} (id={mode_id}) su {ip}:{port}")
    
    # Connessione MAVLink
    mav = mavutil.mavlink_connection(
        f"udpout:{ip}:{port}",
        dialect="ardupilotmega",
        source_system=255,
        autoreconnect=True,
        timeout=2,
    )
    
    # Ping iniziale
    for _ in range(3):
        mav.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID,
            0, 0, 0
        )
        time.sleep(0.2)
    
    mav.wait_heartbeat(timeout=10)
    mav.set_mode(mode_id)
    logger.info(f"[set_boa_state] Comando set_mode({mode_id}) inviato, attendo conferma...")
    
    # Attendi conferma
    deadline = time.time() + 10
    ok = False
    while time.time() < deadline:
        msg = mav.recv_match(type="HEARTBEAT", blocking=True, timeout=1)
        if msg and hasattr(msg, "custom_mode"):
            logger.info(f"[set_boa_state] Heartbeat ricevuto: custom_mode={msg.custom_mode}")
            if msg.custom_mode == mode_id:
                ok = True
                logger.info("[set_boa_state] Cambio modalità confermato!")
                break
    
    mav.close()
    if not ok:
        logger.warning("[set_boa_state] Cambio modalità NON confermato")
        raise RuntimeError(f"Cambio modalità a {stato.value} non confermato")


@app.post("/cambia_stato")
def cambia_stato(req: CambiaStatoRequest):
    """Cambia lo stato operativo di una boa."""
    try:
        set_boa_state(req.ip, req.port, req.stato)
        return {"status": "ok", "stato": req.stato}
    except Exception as e:
        logger.error(f"Errore nel cambiare stato: {e}")
        raise HTTPException(500, f"Errore nel cambiare stato: {e}")


# =============================================================================
# ENDPOINT API - NAVIGAZIONE
# =============================================================================

# Costanti per navigazione
GUIDED_MODE_ID = 15         # GUIDED mode
LOITER_MODE_ID = 5          # LOITER mode
DO_REPOSITION = 192         # Comando MAVLink per reposition
BITMASK_LLA = 1             # Bitmask per lat/lon/alt
ARM_MAGIC = 21196           # Magic number per ARM bypass


def wait_mode(mav, mode_id: int, timeout: int = 8) -> bool:
    """Attende che la boa entri nella modalità specificata."""
    end = time.time() + timeout
    while time.time() < end:
        hb = mav.recv_match(type="HEARTBEAT", blocking=True, timeout=1)
        if hb and hb.custom_mode == mode_id:
            return True
    return False


def wait_arm(mav, want_arm: bool, timeout: int = 8) -> bool:
    """Attende che la boa si armi/disarmi."""
    end = time.time() + timeout
    while time.time() < end:
        mav.recv_match(blocking=False)
        if mav.motors_armed() == want_arm:
            return True
        time.sleep(0.3)
    return False


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calcola la distanza tra due coordinate geografiche."""
    R = 6371000  # Raggio Terra in metri
    phi1, phi2 = map(math.radians, (lat1, lat2))
    dphi = math.radians(lat2 - lat1)
    dlamb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlamb/2)**2
    return 2*R*math.atan2(math.sqrt(a), math.sqrt(1-a))


def open_mavlink(ip: str, port: int):
    """Apre una connessione MAVLink configurata per navigazione."""
    mav = mavutil.mavlink_connection(
        f"udpout:{ip}:{port}",
        dialect="ardupilotmega",
        source_system=255,
        autoreconnect=True,
        timeout=2
    )
    
    # Ping iniziale
    for _ in range(3):
        mav.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS,
            mavutil.mavlink.MAV_AUTOPILOT_INVALID, 
            0, 0, 0
        )
        time.sleep(0.2)
    
    # Ricevi heartbeat
    msg = mav.recv_match(type="HEARTBEAT", blocking=True, timeout=10)
    logger.info(f"[vaia] Heartbeat: {msg}")
    logger.info(f"[vaia] SYSID: {mav.target_system}, COMPID: {mav.target_component}")
    
    # Forza SYSID se necessario
    if mav.target_system == 0:
        mav.target_system = 21
        logger.info("[vaia] SYSID forzato a 21")
    
    mav.target_component = 0
    logger.info(f"[vaia] SYSID finale: {mav.target_system}, COMPID: {mav.target_component}")
    return mav


def set_mode(mav, mode_id: int, label: str) -> bool:
    """Imposta modalità e attende conferma."""
    logger.info(f"[vaia] set_mode → {label} (id={mode_id})")
    mav.set_mode(mode_id)
    if wait_mode(mav, mode_id):
        logger.info(f"[vaia] Mode {label} confermato.")
        return True
    logger.warning(f"[vaia] Mode {label} NON confermato!")
    return False


def arm(mav, timeout: int = 8) -> bool:
    """Arma la boa con bypass dei controlli di sicurezza."""
    logger.info("[vaia] ARM (force)")
    mav.mav.command_long_send(
        mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0,
        1,           # ARM
        ARM_MAGIC,   # Bypass safety
        0, 0, 0, 0, 0
    )

    end = time.time() + timeout
    ack_seen = False
    
    while time.time() < end:
        msg = mav.recv_match(blocking=True, timeout=1)
        if not msg:
            continue

        if (msg.get_type() == "COMMAND_ACK" and 
            msg.command == mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM):
            desc = mavutil.mavlink.enums['MAV_RESULT'][msg.result].description
            logger.info(f"[vaia] ARM ACK: {desc}")
            ack_seen = True

        if msg.get_type() == "STATUSTEXT":
            logger.info(f"[vaia] STATUSTEXT: {msg.text}")

        if mav.motors_armed():
            logger.info("[vaia] ARM confermato.")
            return True

    logger.warning("[vaia] ARM NON confermato!")
    if not ack_seen:
        logger.warning("[vaia] (nessun COMMAND_ACK ricevuto)")
    return False


def disarm(mav) -> None:
    """Disarma la boa."""
    logger.info("[vaia] DISARM")
    mav.mav.command_long_send(
        mav.target_system, mav.target_component,
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        0, 0, 0, 0, 0, 0, 0, 0
    )
    wait_arm(mav, False)


def do_reposition(mav, lat: float, lon: float, alt: float) -> None:
    """Invia comando di riposizionamento alla boa."""
    # Primo tentativo
    mav.mav.command_long_send(
        mav.target_system, mav.target_component,
        DO_REPOSITION, 0,
        1.0,                    # ground speed
        BITMASK_LLA,           # bitmask: use position
        0, 0,                  # reserved, yaw
        float(lat), float(lon), float(alt)
    )
    logger.info("[vaia] DO_REPOSITION inviato (ground speed 1.0)")
    
    # Secondo tentativo con velocità diversa
    mav.mav.command_long_send(
        mav.target_system, mav.target_component,
        DO_REPOSITION, 0,
        2.0,                    # ground speed
        BITMASK_LLA,           # bitmask: use position
        0, 0,                  # reserved, yaw
        float(lat), float(lon), float(alt)
    )
    logger.info("[vaia] DO_REPOSITION inviato (ground speed 2.0)")


def set_position_target_global_int(mav, lat: float, lon: float, alt: float) -> None:
    """Invia target di posizione globale."""
    time_boot_ms = int((time.time() * 1e3) % 4294967295)
    mav.mav.set_position_target_global_int_send(
        time_boot_ms,
        mav.target_system,
        mav.target_component,
        mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
        0b0000111111111000,     # type_mask: ignora velocità, accel, yaw
        int(lat * 1e7),         # lat in 1E7
        int(lon * 1e7),         # lon in 1E7
        float(alt),             # alt in metri
        0, 0, 0,               # vx, vy, vz
        0, 0, 0,               # afx, afy, afz
        0, 0                   # yaw, yaw_rate
    )
    logger.info("[vaia] SET_POSITION_TARGET_GLOBAL_INT inviato")


def vaia_thread(ip: str, port: int, lat: float, lon: float, alt: float, stop_event: threading.Event) -> None:
    """Thread per gestire il comando di navigazione di una boa."""
    boa_key = f"{ip}:{port}"
    
    try:
        mav = open_mavlink(ip, port)
    except Exception as e:
        logger.error(f"[vaia] {boa_key}: Connessione fallita: {e}")
        return

    try:
        # Entra in modalità GUIDED e arma
        if not set_mode(mav, GUIDED_MODE_ID, "GUIDED") or not arm(mav):
            logger.error(f"[vaia] {boa_key}: impossibile entrare in GUIDED armato.")
            mav.close()
            return

        logger.info(f"[vaia] Target: lat={lat}, lon={lon}, alt={alt}")
        start = time.time()
        last_tx = 0
        arrived = False

        # Loop di navigazione
        while time.time() - start < VAI_A_TIMEOUT_SEC:
            if stop_event.is_set():
                logger.info(f"[vaia] Stop richiesto per {boa_key}")
                break

            now = time.time()
            if now - last_tx > VAI_A_RETRY_SEC:
                logger.info(f"[vaia] Invio comandi navigazione a lat={lat}, lon={lon}, alt={alt}")
                do_reposition(mav, lat, lon, alt)
                set_position_target_global_int(mav, lat, lon, alt)
                last_tx = now

            # Controlla posizione attuale
            msg = mav.recv_match(type="GLOBAL_POSITION_INT", blocking=True, timeout=1)
            if msg:
                clat, clon = msg.lat / 1e7, msg.lon / 1e7
                logger.info(f"[vaia] Posizione attuale: lat={clat}, lon={clon}")
                dist = haversine(clat, clon, lat, lon)
                logger.info(f"[vaia] Distanza dal target: {dist:.1f} m")
                
                if dist < VAI_A_TOLERANCE_METERS:
                    arrived = True
                    break

        # Torna in LOITER e disarma
        set_mode(mav, LOITER_MODE_ID, "LOITER")
        disarm(mav)

        if arrived:
            logger.info(f"[vaia] {boa_key}: Arrivata al punto.")
        else:
            logger.warning(f"[vaia] {boa_key}: Non arrivata (timeout/stop).")
            
    finally:
        mav.close()


@app.post("/vaia")
def vaia(req: VaiaRequest):
    """Avvia comando di navigazione per una boa."""
    boa_key = f"{req.ip}:{req.port}"
    
    with active_vaia_lock:
        if boa_key in active_vaia:
            raise HTTPException(400, "Vaia già attivo per questa boa")
        
        stop_event = threading.Event()
        
        # Crea le informazioni del comando vaia
        vaia_info = {
            "lat": req.lat,
            "lon": req.lon,
            "alt": req.alt,
            "started_at": time.time(),
            "status": "active"
        }
        
        t = threading.Thread(
            target=vaia_thread,
            name=f"vaia-{boa_key}",
            args=(req.ip, req.port, req.lat, req.lon, req.alt, stop_event),
            daemon=True,
        )
        t.start()
        active_vaia[boa_key] = (t, stop_event, vaia_info)
    
    return {"status": "started", "boa": boa_key}


@app.post("/stop_vaia")
def stop_vaia(req: VaiaStopRequest):
    """Ferma comando di navigazione per una boa."""
    boa_key = f"{req.ip}:{req.port}"
    
    with active_vaia_lock:
        entry = active_vaia.get(boa_key)
        if not entry:
            raise HTTPException(404, "Nessun vaia attivo per questa boa")
        
        t, stop_event, vaia_info = entry
        stop_event.set()
        t.join(timeout=5)
        active_vaia.pop(boa_key, None)
    
    return {"status": "stopped", "boa": boa_key}


@app.get("/isgoing/{ip}/{port}")
def isgoing(ip: str, port: int):
    """Verifica se una boa ha un comando di navigazione attivo."""
    boa_key = f"{ip}:{port}"
    
    with active_vaia_lock:
        is_active = boa_key in active_vaia
        if is_active:
            t, stop_event, vaia_info = active_vaia[boa_key]
            # Verifica se il thread è ancora vivo
            is_active = t.is_alive()
            if not is_active:
                # Thread morto, rimuovi dall'elenco
                active_vaia.pop(boa_key, None)
                return {"isgoing": False, "boa": boa_key, "destination": None}
            
            # Calcola tempo trascorso
            elapsed_time = time.time() - vaia_info["started_at"]
            
            return {
                "isgoing": True,
                "boa": boa_key,
                "destination": {
                    "lat": vaia_info["lat"],
                    "lon": vaia_info["lon"],
                    "alt": vaia_info["alt"]
                },
                "started_at": vaia_info["started_at"],
                "elapsed_time": elapsed_time,
                "status": vaia_info["status"]
            }
    
    return {"isgoing": False, "boa": boa_key, "destination": None}


@app.get("/isgoing")
def isgoing_all():
    """Verifica lo stato di navigazione di tutte le boe."""
    with active_vaia_lock:
        result = {}
        # Crea una copia delle chiavi per evitare modifiche durante l'iterazione
        active_keys = list(active_vaia.keys())
        
        for boa_key in active_keys:
            t, stop_event, vaia_info = active_vaia[boa_key]
            is_active = t.is_alive()
            if not is_active:
                # Thread morto, rimuovi dall'elenco
                active_vaia.pop(boa_key, None)
            else:
                # Calcola tempo trascorso
                elapsed_time = time.time() - vaia_info["started_at"]
                result[boa_key] = {
                    "isgoing": True,
                    "destination": {
                        "lat": vaia_info["lat"],
                        "lon": vaia_info["lon"],
                        "alt": vaia_info["alt"]
                    },
                    "started_at": vaia_info["started_at"],
                    "elapsed_time": elapsed_time,
                    "status": vaia_info["status"]
                }
        
        # Aggiungi tutte le boe attive (anche quelle senza vaia)
        with active_boes_lock:
            for boa_key in active_boes.keys():
                if boa_key not in result:
                    result[boa_key] = {"isgoing": False}
    
    return {"boes": result}


@app.get("/boe_status")
def boe_status():
    """Verifica lo stato di connessione di tutte le boe."""
    result = {}
    
    with active_boes_lock:
        for boa_key in active_boes.keys():
            t, stop_event = active_boes[boa_key]
            is_connected = t.is_alive()
            if not is_connected:
                # Thread morto, rimuovi dall'elenco
                active_boes.pop(boa_key, None)
                result[boa_key] = {"connected": False, "status": "disconnected"}
            else:
                result[boa_key] = {"connected": True, "status": "active"}
    
    return {"boes": result}


# =============================================================================
# API PER AUTENTICAZIONE E GESTIONE UTENTI
# =============================================================================

def create_access_token(user_id: int, username: str) -> str:
    """Crea un token di accesso JWT-like."""
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    # Per semplicità, usiamo un token base64 (in produzione usare JWT)
    import base64
    import json
    return base64.b64encode(json.dumps(payload).encode()).decode()

@app.post("/auth/login", response_model=TokenResponse)
def login(request: UserLoginRequest, client_ip: str = None, user_agent: str = None):
    """Endpoint per il login degli utenti."""
    try:
        # Autentica l'utente
        user = user_db.authenticate_user(request.username, request.password)
        
        if user:
            # Log del tentativo di login riuscito
            user_db.log_login_attempt(
                username=request.username,
                success=True,
                ip_address=client_ip,
                user_agent=user_agent,
                user_id=user['id']
            )
            
            # Crea token di accesso
            access_token = create_access_token(user['id'], user['username'])
            
            # Prepara risposta utente (senza password)
            user_response = UserResponse(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                role=user['role'],
                full_name=user['full_name'],
                created_at=user['created_at'] or '',
                last_login=user['last_login'] or '',
                is_active=user['is_active']
            )
            
            return TokenResponse(access_token=access_token, user=user_response)
        else:
            # Log del tentativo di login fallito
            user_db.log_login_attempt(
                username=request.username,
                success=False,
                ip_address=client_ip,
                user_agent=user_agent
            )
            raise HTTPException(status_code=401, detail="Credenziali non valide")
            
    except Exception as e:
        logger.error(f"Errore durante il login: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.post("/auth/register", response_model=UserResponse)
def register(request: UserRegisterRequest):
    """Endpoint per la registrazione di nuovi utenti."""
    try:
        # Crea il nuovo utente
        user = user_db.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            role='user',  # Ruolo di default per nuovi utenti
            full_name=request.full_name,
            phone=request.phone
        )
        
        # Prepara risposta (senza password)
        return UserResponse(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            role=user['role'],
            full_name=user['full_name'],
            created_at=user['created_at'] or '',
            is_active=True
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Errore durante la registrazione: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.get("/auth/users", response_model=list[UserResponse])
def get_users():
    """Endpoint per ottenere tutti gli utenti (solo per admin)."""
    try:
        users = user_db.get_all_users()
        return [
            UserResponse(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                role=user['role'],
                full_name=user['full_name'],
                created_at=user['created_at'] or '',
                last_login=user['last_login'] or '',
                is_active=user['is_active']
            )
            for user in users
        ]
    except Exception as e:
        logger.error(f"Errore nel recupero utenti: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.get("/auth/profile/{user_id}", response_model=UserResponse)
def get_user_profile(user_id: int):
    """Endpoint per ottenere il profilo di un utente specifico."""
    try:
        users = user_db.get_all_users()
        user = next((u for u in users if u['id'] == user_id), None)
        
        if not user:
            raise HTTPException(status_code=404, detail="Utente non trovato")
        
        return UserResponse(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            role=user['role'],
            full_name=user['full_name'],
            created_at=user['created_at'] or '',
            last_login=user['last_login'] or '',
            is_active=user['is_active']
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Errore nel recupero profilo utente: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.get("/auth/users/list")
def list_users_with_passwords():
    """Endpoint per visualizzare tutti gli utenti con password (solo per debug)."""
    try:
        # Query diretta per ottenere anche le password (solo per debug)
        import sqlite3
        with sqlite3.connect(user_db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, password_hash, role, created_at, 
                       last_login, is_active, full_name, phone
                FROM users ORDER BY created_at DESC
            ''')
            
            users = []
            for row in cursor.fetchall():
                users.append({
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password_hash': row[3][:20] + '...' if row[3] else None,  # Mostra solo i primi 20 caratteri
                    'role': row[4],
                    'created_at': row[5] if row[5] else None,
                    'last_login': row[6] if row[6] else None,
                    'is_active': bool(row[7]),
                    'full_name': row[8],
                    'phone': row[9]
                })
            
            return {
                "total_users": len(users),
                "users": users
            }
    except Exception as e:
        logger.error(f"Errore nel recupero lista utenti: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.delete("/auth/users/{user_id}")
def delete_user(user_id: int):
    """Elimina un utente (solo per admin)."""
    try:
        success = user_db.delete_user(user_id)
        if success:
            return {"message": f"Utente {user_id} eliminato con successo"}
        else:
            raise HTTPException(status_code=404, detail="Utente non trovato")
    except Exception as e:
        logger.error(f"Errore nell'eliminazione utente: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.put("/auth/users/{user_id}")
def update_user(user_id: int, user_data: dict):
    """Aggiorna i dati di un utente (solo per admin)."""
    try:
        # Rimuovi campi non modificabili
        allowed_fields = ['email', 'role', 'full_name', 'phone', 'is_active']
        update_data = {k: v for k, v in user_data.items() if k in allowed_fields}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="Nessun campo valido da aggiornare")
        
        success = user_db.update_user(user_id, **update_data)
        if success:
            return {"message": f"Utente {user_id} aggiornato con successo"}
        else:
            raise HTTPException(status_code=404, detail="Utente non trovato")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Errore nell'aggiornamento utente: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")

@app.delete("/auth/reset-database")
def reset_database():
    """Endpoint per resettare completamente il database (solo per debug)."""
    try:
        import sqlite3
        import os
        
        # Chiudi la connessione al database se aperta
        if hasattr(user_db, '_conn') and user_db._conn:
            user_db._conn.close()
        
        # Elimina il file del database
        if os.path.exists(user_db.db_path):
            os.remove(user_db.db_path)
            logger.info(f"Database eliminato: {user_db.db_path}")
        
        # Reinizializza il database (creerà l'utente admin di default)
        user_db.init_database()
        
        return {
            "message": "Database resettato con successo",
            "admin_created": True,
            "admin_credentials": {
                "username": "admin",
                "password": "admin123"
            }
        }
    except Exception as e:
        logger.error(f"Errore nel reset del database: {e}")
        raise HTTPException(status_code=500, detail="Errore interno del server")
