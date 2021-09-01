mod protocol;

use anyhow::Result;
use structopt::StructOpt;

use protocol::Client;

#[derive(StructOpt)]
#[structopt(about = "the stupid content tracker")]
enum KChaos {
    Version {},
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
    }

    Ok(())
}
