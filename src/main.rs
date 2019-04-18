extern crate clap;

use clap::{App, Arg};

use std::boxed::Box;
use std::fs::File;
use std::io::{stdout, Write};
use std::path::Path;
use waves_gg::generator_settings::GeneratorSettings;
use waves_gg::genesis_config::{print_account_info, print_config, GenesisConfig};

fn main() {
    let opts = App::new("waves-gg")
        .version("1.0")
        .author("Alexandr M. <amakoed@wavesplatform.com>")
        .about("Genesis config generator for custom Waves network")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Sets a custom output file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Print additional info"),
        )
        .get_matches();

    let config_file_path = opts.value_of("config").unwrap();
    let output_file_path = opts.value_of("output");
    let verbose = opts.occurrences_of("verbose") > 0;

    let mut out_writer = match output_file_path {
        Some(x) => {
            let path = Path::new(x);
            Box::new(File::create(&path).unwrap()) as Box<Write>
        }
        None => Box::new(stdout()) as Box<Write>,
    };

    let settings = match GeneratorSettings::load(config_file_path) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Error parsing config file: {}", err);
            return;
        }
    };

    match GenesisConfig::generate(&settings) {
        Ok(config) => {
            if verbose {
                out_writer
                    .write(print_account_info(&config).as_bytes())
                    .unwrap();
            }

            out_writer.write(print_config(&config).as_bytes()).unwrap();
        }
        Err(err) => eprintln!("Error: {}", err),
    };
}
