use ssh2::Session;
use std::env;
use std::net::TcpStream;

fn make_session(
    ip: &str,
    port: &str,
    user: &str,
    pass: &str,
) -> Result<Session, Box<dyn std::error::Error>> {
    let tcp = TcpStream::connect(format!("{}:{}", ip, port))?;
    let mut sess = Session::new()?;

    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_password(user, pass)?;

    Ok(sess)
}

fn load_env() -> (&'static str, &'static str, &'static str, &'static str) {
    let host = env!("MT_SSH_HOST");
    let port = env!("MT_SSH_PORT");
    let user = env!("MT_SSH_USER");
    let pass = env!("MT_SSH_PASS");

    return (host, port, user, pass);
}

fn get_user_input() -> String {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    return input.trim().to_uppercase();
}

fn valid_param(input: &str) -> bool {
    return input == "Y" || input == "N";
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, user, pass) = load_env();

    println!("¿Desabilitar el filtro de bloqueo de internet?");
    let input = get_user_input();

    if !valid_param(&input) {
        println!("Opción no válida");
        return Ok(());
    }

    let sess = make_session(&host, &port, &user, &pass)?;
    if !sess.authenticated() {
        println!("failed to authenticate");

        return Ok(());
    }
    let mut channel = sess.channel_session()?;

    if input == "Y" {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=yes",
        )?;
        println!("Filtro de bloqueo de internet desactivado");
    } else {
        channel.exec(
            "/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=no",
        )?;
        println!("Filtro de bloqueo de internet activado");
    }

    println!("Presione ENTER para terminar");
    get_user_input();

    Ok(())
}
