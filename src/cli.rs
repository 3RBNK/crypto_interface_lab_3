use clap::builder::NonEmptyStringValueParser;
use clap::{Arg, ArgMatches, Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkMode {
    Keygen,
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    ECB,
    InnerCBC,
    OuterCBC,
    Pad,
}

#[derive(Debug)]
pub struct ConfigCLI {
    work_mode: WorkMode,
    cipher_mode: Option<CipherMode>,
    input_file: Option<String>,
    output_file: Option<String>,
    iv_file: Option<String>,
    key_file: String,
}

impl ConfigCLI {
    pub fn new() -> Result<ConfigCLI, clap::Error> {
        Self::from_args(std::env::args().skip(1))
    }

    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<ConfigCLI, clap::Error> {
        let args = std::iter::once(String::from("code")).chain(args);
        let matches = Self::command().try_get_matches_from(args)?;
        Ok(Self::from_matches(matches))
    }

    fn command() -> Command {
        let mut cli = Command::new("code")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Шифрование файлов с помощью 3DES")
            .subcommand_required(true)
            .subcommand(
                Command::new("keygen")
                    .about("Генерация ключа 3DES")
                    .arg(Self::file_arg("key_file", "Файл ключа")),
            );

        for (name, about) in [
            ("encrypt", "Шифрование файла"),
            ("decrypt", "Расшифровка файла"),
        ] {
            let mut command = Command::new(name).about(about).subcommand_required(true);

            for (mode, alias) in [
                ("ECB", "ecb"),
                ("ICBC", "icbc"),
                ("OCBC", "ocbc"),
                ("PAD", "pad"),
            ] {
                let mut cipher = Command::new(mode).alias(alias);
                if name != "keygen" {
                    cipher = cipher
                        .arg(Self::file_arg("input_file", "Входной файл"))
                        .arg(Self::file_arg("output_file", "Выходной файл"));

                    if matches!(mode, "ICBC" | "OCBC") {
                        let help = if mode == "ICBC" {
                            "Файл трёх IV: 24 байта (по 8 байт на стадию)"
                        } else {
                            "Файл IV: 8 байт"
                        };
                        cipher = cipher.arg(Self::file_arg("iv_file", help));
                    }
                }

                cipher = cipher.arg(Self::file_arg("key_file", "Файл ключа"));
                command = command.subcommand(cipher);
            }

            cli = cli.subcommand(command);
        }

        cli
    }

    fn file_arg(name: &'static str, help: &'static str) -> Arg {
        Arg::new(name)
            .help(help)
            .required(true)
            .value_parser(NonEmptyStringValueParser::new())
    }

    fn from_matches(matches: ArgMatches) -> ConfigCLI {
        let (command, args) = matches.subcommand().unwrap();
        let work_mode = match command {
            "keygen" => WorkMode::Keygen,
            "encrypt" => WorkMode::Encrypt,
            "decrypt" => WorkMode::Decrypt,
            _ => unreachable!(),
        };
        if work_mode == WorkMode::Keygen {
            return ConfigCLI {
                work_mode,
                cipher_mode: None,
                input_file: None,
                output_file: None,
                iv_file: None,
                key_file: args.get_one::<String>("key_file").unwrap().clone(),
            };
        }

        let (mode, args) = args.subcommand().unwrap();
        let cipher_mode = match mode {
            "ECB" => CipherMode::ECB,
            "ICBC" => CipherMode::InnerCBC,
            "OCBC" => CipherMode::OuterCBC,
            "PAD" => CipherMode::Pad,
            _ => unreachable!(),
        };

        ConfigCLI {
            work_mode,
            cipher_mode: Some(cipher_mode),
            input_file: args
                .try_get_one::<String>("input_file")
                .ok()
                .flatten()
                .cloned(),
            output_file: args
                .try_get_one::<String>("output_file")
                .ok()
                .flatten()
                .cloned(),
            iv_file: args
                .try_get_one::<String>("iv_file")
                .ok()
                .flatten()
                .cloned(),
            key_file: args.get_one::<String>("key_file").unwrap().clone(),
        }
    }

    pub fn get_work_mode(&self) -> WorkMode {
        self.work_mode
    }

    pub fn get_cipher_mode(&self) -> Option<CipherMode> {
        self.cipher_mode
    }

    pub fn get_input_file(&self) -> Option<&str> {
        self.input_file.as_deref()
    }

    pub fn get_output_file(&self) -> Option<&str> {
        self.output_file.as_deref()
    }

    pub fn get_iv_file(&self) -> Option<&str> {
        self.iv_file.as_deref()
    }

    pub fn get_key_file(&self) -> &str {
        &self.key_file
    }
}
