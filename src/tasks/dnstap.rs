use tokio::process::{Child, Command};

// # dnstap -h
// Usage: dnstap [OPTION]...
//   -T value
//     	write dnstap payloads to tcp/ip address
//   -U value
//     	write dnstap payloads to unix socket
//   -a	append to the given file, do not overwrite. valid only when outputting a text or YAML file.
//   -j	use verbose JSON output
//   -l value
//     	read dnstap payloads from tcp/ip
//   -q	use quiet text output
//   -r value
//     	read dnstap payloads from file
//   -t duration
//     	I/O timeout for tcp/ip and unix domain sockets
//   -u value
//     	read dnstap payloads from unix socket
//   -w string
//     	write output to file
//   -y	use verbose YAML output

// Quiet text output format mnemonics:
//     AQ: AUTH_QUERY
//     AR: AUTH_RESPONSE
//     RQ: RESOLVER_QUERY
//     RR: RESOLVER_RESPONSE
//     CQ: CLIENT_QUERY
//     CR: CLIENT_RESPONSE
//     FQ: FORWARDER_QUERY
//     FR: FORWARDER_RESPONSE
//     SQ: STUB_QUERY
//     SR: STUB_RESPONSE
//     TQ: TOOL_QUERY
//     TR: TOOL_RESPONSE

pub fn spawn_dnstap() -> Result<Child, anyhow::Error> {
    let child = Command::new("dnstap")
        .arg("-y")
        .arg("-u")
        .arg("dnstap.sock")
        .arg("-a")
        .arg("-w")
        .arg("logs.yaml")
        .kill_on_drop(true)
        .spawn()?;

    Ok(child)
}

pub async fn read_dnstap_logs() -> String {
    let content = tokio::fs::read_to_string("./logs.yaml")
        .await
        .unwrap_or_default();
    let _ = tokio::fs::write("./logs.yaml", "").await;

    content
}
