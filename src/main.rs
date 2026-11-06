use code::prelude::ConfigCLI;

fn main() {
    match ConfigCLI::new() {
        Ok(config) => println!("{config:#?}"),
        Err(error) => error.exit(),
    }
}
