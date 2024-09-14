use libc::{self, setsockopt, socket, SOCKET};
use std::net::IpAddr;
use std::os::raw::c_int;
use std::str::FromStr;
use std::time::Duration;
use winapi::shared::inaddr::IN_ADDR;

use winapi::shared::ws2def::{AF_INET, SOCKADDR_IN, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO};
use winapi::um::winsock2::{
    recvfrom, sendto, WSACleanup, WSAGetLastError, WSAStartup, SOCKET_ERROR, WSADATA
};

#[derive(Debug)]
pub struct Config {
    pub addr: IpAddr,
}

fn makeword(low: u8, high: u8) -> u16 {
    ((high as u16) << 8) | (low as u16)
}

// fn type_of<T>(_: T) -> String {
//     std::any::type_name::<T>().to_string()
// }

impl Config {
    pub fn build(mut args: impl Iterator<Item = String>) -> Result<Config, &'static str> {
        args.next();

        let addr = match args.next() {
            Some(arg) => IpAddr::from_str(&arg).map_err(|_| "Direccion IP inválida")?,
            None => return Err("No se proporcionó dirección IP"),
        };
        Ok(Config { addr })
    }
}

pub fn create_icmp_echo_request(seq: u16) -> Vec<u8> {
    let mut buffer = vec![0u8; 8];

    buffer[0] = 8; // Header 8: Echo request
    buffer[1] = 0; // Codigo 0

    // Identificador (arbitrario)
    buffer[4] = 0x12;
    buffer[5] = 0x34;

    // Número de secuencia
    buffer[6] = (seq >> 8) as u8;
    buffer[7] = (seq & 0xff) as u8;

    // Calcular checksum
    let checksum = calculate_checksum(&buffer);
    buffer[2] = (checksum >> 8) as u8;
    buffer[3] = (checksum & 0xff) as u8;

    buffer
}

pub fn create_raw_socket() -> Result<c_int, &'static str> {
    // Inicializar la biblioteca de sockets de Windows
    let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
    let ret = unsafe { WSAStartup(makeword(2, 2), &mut wsa_data) };
    if ret != 0 {
        return Err("Error al inicializar la biblioteca de sockets de Windows");
    }

    let sock = unsafe { socket(AF_INET, 3, 1) };

    let timeout = Duration::from_secs(1);

    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as i32,
        tv_usec: 0,
    };

    // Configurar tiempo de espera para enviar
    let ret = unsafe {
        setsockopt(
            sock,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeval as *const _ as *const i8,
            std::mem::size_of::<libc::timeval>() as i32,
        )
    };

    if ret == SOCKET_ERROR {
        let err_code = unsafe { WSAGetLastError() };
        eprintln!("Error {}", err_code);
        unsafe {
            WSACleanup();
            libc::close(sock as i32)
        };
        return Err("Error configurando el tiempo de espera para recepción");
    }

    // unsafe { WSACleanup() };
    Ok(sock as i32)
}

pub fn send_icmp_packet(socket: SOCKET, dest: &IpAddr, packet: &[u8]) -> Result<(), String> {
    let mut dest_addr: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    dest_addr.sin_family = AF_INET as u16;

    match dest {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            dest_addr.sin_addr = IN_ADDR {
                S_un: unsafe { std::mem::transmute(u32::from_ne_bytes(octets)) },
            };
        }
        IpAddr::V6(_) => return Err("IPv6 no soportado".to_string()),
    }

    let sent_bytes = unsafe {
        sendto(
            socket,
            packet.as_ptr() as *const i8,
            packet.len() as i32,
            0,
            &dest_addr as *const SOCKADDR_IN as *const _,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
        )
    };


    println!("Bytes enviados: {}", sent_bytes);
    if sent_bytes == SOCKET_ERROR {
        let err = unsafe { WSAGetLastError() };
        Err(format!("Error al enviar el paquete. Código de error: {}. Mensaje: {}", err, get_error_message(err)))
    } else {
        Ok(())
    }
}

pub fn receive_icpm_packet(socket: SOCKET) -> Result<Vec<u8>, String>{
    let mut buffer = vec![0u8; 1024];
    let mut from_addr: SOCKADDR_IN = unsafe {
        std::mem::zeroed()
    };
    let mut from_len = std::mem::size_of::<SOCKADDR_IN>() as i32;

    let timeout = Duration::from_secs(5);
    let timeval = libc::timeval {
        tv_sec: timeout.as_secs() as i32,
        tv_usec: 0,
    };

    unsafe {
        setsockopt(
            socket as SOCKET,
            SOL_SOCKET, 
            SO_RCVTIMEO, 
            &timeval as *const _ as *const i8, 
            std::mem::size_of::<libc::timeval>() as i32
        )
    };

    let received_bytes = unsafe {
        recvfrom(
            socket,
            buffer.as_mut_ptr() as *mut i8, 
            buffer.len() as i32, 
            0, 
            &mut from_addr as *mut SOCKADDR_IN as *mut _, 
            &mut from_len
        )
    };
    if received_bytes == SOCKET_ERROR {
        let err = unsafe { WSAGetLastError() };
        Err(format!("Error al recibir el paquete. Código de error: {}. Mensaje: {}", err, get_error_message(err)))
    } else {
        buffer.truncate(received_bytes as usize);
        Ok(buffer)
    }
}

fn calculate_checksum(buffer: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < buffer.len() - 1 {
        let word = ((buffer[i] as u32) << 8) + (buffer[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }

    if buffer.len() % 2 == 1 {
        sum = sum.wrapping_add((buffer[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

fn get_error_message(error_code: i32) -> &'static str {
    match error_code {
        10013 => "Permiso denegado. Asegúrate de ejecutar el programa como administrador.",
        10022 => "Argumento inválido. Verifica la dirección IP de destino.",
        10036 => "Operación en progreso. Intenta nuevamente.",
        10040 => "Mensaje demasiado largo.",
        10050 => "Red caída. Verifica tu conexión a Internet.",
        10051 => "Red inalcanzable. Verifica tu conexión a Internet o la dirección IP de destino.",
        10065 => "No hay ruta al host. Verifica la dirección IP de destino.",
        _ => "Error desconocido al enviar el paquete.",
    }
}