// ksl_logger.rs
// Provides a standardized logging framework for KSL tools, supporting log levels,
// multiple output destinations, and distributed tracing integration.

use crate::ksl_errors::{KslError, SourcePosition};
use log::{Level, LevelFilter, Metadata, Record};
use syslog::{Facility, Formatter3164, Logger as SyslogLogger, LoggerBackend};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

// Logger configuration
#[derive(Debug)]
pub struct LoggerConfig {
    level: LevelFilter, // Log level (e.g., Debug, Info, Warn, Error)
    console: bool, // Output to console
    file_path: Option<PathBuf>, // Output to file
    syslog: bool, // Output to syslog
}

// Global logger instance
static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

// KSL logger implementation
pub struct Logger {
    config: LoggerConfig,
    file: Option<File>,
    syslog: Option<SyslogLogger<LoggerBackend>>,
}

impl Logger {
    pub fn new(config: LoggerConfig) -> Result<Self, KslError> {
        let pos = SourcePosition::new(1, 1);
        let file = if let Some(path) = &config.file_path {
            let file = File::options().create(true).append(true).open(path)
                .map_err(|e| KslError::type_error(
                    format!("Failed to open log file {}: {}", path.display(), e),
                    pos,
                ))?;
            Some(file)
        } else {
            None
        };

        let syslog = if config.syslog {
            let formatter = Formatter3164 {
                facility: Facility::LOG_USER,
                hostname: None,
                process: "ksl".to_string(),
                pid: std::process::id() as i32,
            };
            Some(syslog::unix(formatter)
                .map_err(|e| KslError::type_error(
                    format!("Failed to initialize syslog: {}", e),
                    pos,
                ))?)
        } else {
            None
        };

        let logger = Logger { config, file, syslog };
        log::set_boxed_logger(Box::new(logger.clone()))
            .map_err(|e| KslError::type_error(
                format!("Failed to set logger: {}", e),
                pos,
            ))?;
        log::set_max_level(config.level);

        let mut global_logger = LOGGER.lock().unwrap();
        *global_logger = Some(logger.clone());

        Ok(logger)
    }

    // Set log level dynamically
    pub fn set_level(level: LevelFilter) -> Result<(), KslError> {
        let pos = SourcePosition::new(1, 1);
        let mut global_logger = LOGGER.lock().unwrap();
        if let Some(logger) = global_logger.as_mut() {
            logger.config.level = level;
            log::set_max_level(level);
            Ok(())
        } else {
            Err(KslError::type_error(
                "Logger not initialized".to_string(),
                pos,
            ))
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.config.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let trace_id = record.metadata().target().strip_prefix("trace-");
        let message = format!(
            "[{}] {}: {}",
            record.level(),
            trace_id.unwrap_or(""),
            record.args()
        );

        // Console output
        if self.config.console {
            println!("{}", message);
        }

        // File output
        if let Some(file) = &self.file {
            let mut file = file.try_clone().unwrap();
            writeln!(file, "{}", message).ok();
        }

        // Syslog output
        if let Some(syslog) = &self.syslog {
            let level = match record.level() {
                Level::Error => syslog::Severity::LOG_ERR,
                Level::Warn => syslog::Severity::LOG_WARNING,
                Level::Info => syslog::Severity::LOG_INFO,
                Level::Debug => syslog::Severity::LOG_DEBUG,
                Level::Trace => syslog::Severity::LOG_DEBUG,
            };
            syslog.log(&message, level).ok();
        }
    }

    fn flush(&self) {
        if let Some(file) = &self.file {
            let mut file = file.try_clone().unwrap();
            file.flush().ok();
        }
    }
}

// Public API to initialize logger
pub fn init_logger(level: LevelFilter, console: bool, file_path: Option<PathBuf>, syslog: bool) -> Result<(), KslError> {
    let config = LoggerConfig {
        level,
        console,
        file_path,
        syslog,
    };
    Logger::new(config)?;
    Ok(())
}

// Public API to set log level via command
pub fn set_log_level(level: &str) -> Result<(), KslError> {
    let pos = SourcePosition::new(1, 1);
    let level_filter = match level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => return Err(KslError::type_error(
            format!("Invalid log level: {}", level),
            pos,
        )),
    };
    Logger::set_level(level_filter)
}

// Public API to log with trace ID
pub fn log_with_trace(level: Level, message: &str, trace_id: Option<&str>) {
    match level {
        Level::Debug => debug!(target: trace_id.unwrap_or(""), "{}", message),
        Level::Info => info!(target: trace_id.unwrap_or(""), "{}", message),
        Level::Warn => warn!(target: trace_id.unwrap_or(""), "{}", message),
        Level::Error => error!(target: trace_id.unwrap_or(""), "{}", message),
        Level::Trace => trace!(target: trace_id.unwrap_or(""), "{}", message),
    }
}

// Assume ksl_errors.rs is in the same crate
mod ksl_errors {
    pub use super::{KslError, SourcePosition};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_logger_init() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let result = init_logger(LevelFilter::Info, true, Some(log_path.clone()), false);
        assert!(result.is_ok());

        info!("Test message");
        let mut file = File::open(&log_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("[INFO] : Test message"));
    }

    #[test]
    fn test_set_log_level() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let _ = init_logger(LevelFilter::Error, false, Some(log_path.clone()), false);
        info!("This should not be logged");

        let result = set_log_level("info");
        assert!(result.is_ok());
        info!("This should be logged");

        let mut file = File::open(&log_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(!content.contains("This should not be logged"));
        assert!(content.contains("This should be logged"));
    }

    #[test]
    fn test_log_with_trace() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let _ = init_logger(LevelFilter::Info, false, Some(log_path.clone()), false);
        log_with_trace(Level::Info, "Test with trace", Some("trace-123"));

        let mut file = File::open(&log_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("[INFO] trace-123: Test with trace"));
    }

    #[test]
    fn test_invalid_log_level() {
        let result = set_log_level("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid log level"));
    }
}