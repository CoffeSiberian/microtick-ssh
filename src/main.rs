use ssh2::Session;
use std::env;
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

fn load_env() -> (&'static str, &'static str, &'static str, &'static str) {
    let host = env!("MT_SSH_HOST");
    let port = env!("MT_SSH_PORT");
    let user = env!("MT_SSH_USER");
    let pass = env!("MT_SSH_PASS");

    return (host, port, user, pass);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (host, port, user, pass) = load_env();

    let sess = make_session(&host, &port, &user, &pass)?;

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
