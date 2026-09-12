//! Debug error logging.

use std::ffi::OsStr;

use nu_ansi_term::{Color, AnsiString};


/// Sets the internal logger, changing the log level based on the value of an
/// environment variable.
pub fn configure<T: AsRef<OsStr>>(ev: Option<T>) {
    let Some(ev) = ev else { return };

    let env_var = ev.as_ref();
    if env_var.is_empty() {
        return;
    }

    if env_var == "trace" {
        log::set_max_level(log::LevelFilter::Trace);
    }
    else {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let result = log::set_logger(GLOBAL_LOGGER);
    if let Err(e) = result {
        eprintln!("Failed to initialise logger: {e}");
    }
}


#[derive(Debug)]
struct Logger;

const GLOBAL_LOGGER: &Logger = &Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true  // no need to filter after using ‘set_max_level’.
    }

    fn log(&self, record: &log::Record<'_>) {
        let open = Color::Fixed(243).paint("[");
        let level = level(record.level());
        let close = Color::Fixed(243).paint("]");

        eprintln!("{}{} {}{} {}", open, level, record.target(), close, record.args());
    }

    fn flush(&self) {
        // no need to flush with ‘eprintln!’.
    }
}

fn level(level: log::Level) -> AnsiString<'static> {
    match level {
        log::Level::Error => Color::Red.paint("ERROR"),
        log::Level::Warn  => Color::Yellow.paint("WARN"),
        log::Level::Info  => Color::Cyan.paint("INFO"),
        log::Level::Debug => Color::Blue.paint("DEBUG"),
        log::Level::Trace => Color::Fixed(245).paint("TRACE"),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use log::Log;

    #[test]
    fn level_labels_escape_sequences() {
        assert_eq!(level(log::Level::Error).to_string(), "\x1b[31mERROR\x1b[0m");
        assert_eq!(level(log::Level::Warn).to_string(),  "\x1b[33mWARN\x1b[0m");
        assert_eq!(level(log::Level::Info).to_string(),  "\x1b[36mINFO\x1b[0m");
        assert_eq!(level(log::Level::Debug).to_string(), "\x1b[34mDEBUG\x1b[0m");
        assert_eq!(level(log::Level::Trace).to_string(), "\x1b[38;5;245mTRACE\x1b[0m");
        assert_eq!(Color::Fixed(243).paint("[").to_string(), "\x1b[38;5;243m[\x1b[0m");
    }

    /// Configuring changes process-wide state, so every step is tested here,
    /// in order: a missing or empty value leaves logging off, a value turns
    /// it on, and a second attempt to install the logger is reported rather
    /// than fatal. Logging is switched off again at the end.
    #[test]
    fn configuring_levels() {
        configure::<&str>(None);
        configure(Some(""));
        assert_eq!(log::max_level(), log::LevelFilter::Off);

        configure(Some("1"));
        assert_eq!(log::max_level(), log::LevelFilter::Debug);

        configure(Some("trace"));
        assert_eq!(log::max_level(), log::LevelFilter::Trace);

        log::set_max_level(log::LevelFilter::Off);
    }

    #[test]
    fn the_logger_takes_every_record() {
        let metadata = log::Metadata::builder().level(log::Level::Info).target("dog").build();
        assert!(GLOBAL_LOGGER.enabled(&metadata));
        GLOBAL_LOGGER.log(&log::Record::builder().metadata(metadata).args(format_args!("a message")).build());
        GLOBAL_LOGGER.flush();
    }
}
