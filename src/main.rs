use ssh2::Session;
use std::io::Read;
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

fn load_env() -> Option<(String, String, String, String)> {
    let host = std::env::var("MT_SSH_HOST").ok()?;
    let port = std::env::var("MT_SSH_PORT").ok()?;
    let user = std::env::var("MT_SSH_USER").ok()?;
    let pass = std::env::var("MT_SSH_PASS").ok()?;

    Some((host, port, user, pass))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, user, pass) = load_env().unwrap();

    let sess = make_session(&host, &port, &user, &pass)?;

    if !sess.authenticated() {
        println!("failed to authenticate");

        return Ok(());
    }

    if !sess.authenticated() {
        println!("failed to authenticate");

        return Ok(());
    }

    let mut channel = sess.channel_session()?;

    channel
        .exec("/ip firewall filter set [find comment=\"Bloqueo Internet LAB 3\"] disabled=yes")?;

    let mut s = String::new();
    channel.read_to_string(&mut s)?;
    println!("Salida: {}", s);

    channel.wait_close()?;
    println!("Código de salida: {}", channel.exit_status()?);

    Ok(())
}
