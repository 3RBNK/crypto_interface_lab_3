use crypto::prelude::{Application, ConfigCLI, Errors, WorkMode};

fn main() -> Result<(), Errors> {
    let config = match ConfigCLI::new() {
        Ok(config) => config,
        Err(error) => error.exit(),
    };
    let application = Application::new(config);

    match application.get_work_mode() {
        WorkMode::Keygen => application.keygen(),
        WorkMode::Encrypt => application.encrypt(),
        WorkMode::Decrypt => application.decrypt(),
    }
}
