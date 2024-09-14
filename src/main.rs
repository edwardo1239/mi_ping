use std::{env, process};

use mi_ping::{create_icmp_echo_request, create_raw_socket, receive_icpm_packet, send_icmp_packet, Config};

fn main() {
    let config = Config::build(env::args()).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });
    println!("Creando socket raw con la IP: {}", config.addr);


    match create_raw_socket() {
        Ok(socket) => {
            let packet = create_icmp_echo_request(0);

            match send_icmp_packet(socket as usize, &config.addr, &packet) {
                Ok(_) => {
                    println!("Paquete enviado correctamente");
                    match receive_icpm_packet(socket as usize) {
                        Ok(response) => println!("Respuesta recibida: {:?}", response),
                        Err(e) => eprintln!("Error al recibir la respuesta: {}", e),
                    }
                },
                Err(e) => eprintln!("Error al enviar el paquete: {}", e),
            }
        }
        Err(e) => eprintln!("Error al crear el socket: {e}")
    }

}
