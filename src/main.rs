mod protocol;

use anyhow::Result;
use serde_json::de::from_str;
use structopt::StructOpt;

use protocol::Client;
use protocol::Injection;

#[derive(StructOpt)]
#[structopt(about = "the stupid content tracker")]
enum KChaos {
    Version {},
    Inject { content: String },
    Recover { id: libc::c_ulong },
}

fn main() -> Result<()> {
    let commands = KChaos::from_args();
    match commands {
        KChaos::Version {} => {
            let client = Client::build()?;
            let server_version = client.get_version()?;
            println!("Driver Version: {}", server_version);
            println!("Client Version: {}", protocol::VERSION);
        }
        KChaos::Inject { content } => {
            let client = Client::build()?;

            let injection: Injection = from_str(&content)?;

            let id = client.inject(injection)?;
            println!("Injected Chaos ID: {}", id);
        }
        KChaos::Recover { id } => {
            let client = Client::build()?;

            client.recover(id)?;
        }
    }

    Ok(())
}
