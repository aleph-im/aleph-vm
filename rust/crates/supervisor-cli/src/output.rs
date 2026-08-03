//! Human-readable rendering: aligned tables, key-value blocks, durations,
//! proto enum names, and the --json writer.

use std::io::Write;

use supervisor_proto::pb;

/// Pad columns to their widest cell, two spaces between columns, no
/// trailing whitespace.
pub fn write_table(
    out: &mut impl Write,
    headers: &[&str],
    rows: &[Vec<String>],
) -> std::io::Result<()> {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(widths.len()) {
            widths[index] = widths[index].max(cell.len());
        }
    }
    let render = |cells: &[String]| -> String {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        padded.join("  ").trim_end().to_string()
    };
    let header_row: Vec<String> = headers.iter().map(|header| header.to_string()).collect();
    writeln!(out, "{}", render(&header_row))?;
    for row in rows {
        writeln!(out, "{}", render(row))?;
    }
    Ok(())
}

/// Pretty JSON plus a trailing newline: the --json output of unary calls.
pub fn write_json(out: &mut impl Write, value: &impl serde::Serialize) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

/// The two most significant units: "45s", "2m 5s", "2h 2m", "2d 3h".
pub fn format_duration_secs(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
    } else if secs >= 3_600 {
        format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// "-" for empty proto string fields in key-value blocks.
pub fn or_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

/// fn(i32) -> String rendering a proto enum by name, minus the proto
/// prefix; out-of-range values render as UNKNOWN(n) instead of panicking.
macro_rules! enum_name {
    ($fn_name:ident, $enum_type:ty, $prefix:literal) => {
        pub fn $fn_name(value: i32) -> String {
            <$enum_type>::try_from(value)
                .map(|variant| {
                    variant
                        .as_str_name()
                        .trim_start_matches($prefix)
                        .to_string()
                })
                .unwrap_or_else(|_| format!("UNKNOWN({value})"))
        }
    };
}

enum_name!(vm_status_name, pb::VmStatus, "VM_STATUS_");
enum_name!(backend_name, pb::Backend, "BACKEND_");
enum_name!(health_status_name, pb::HealthStatus, "HEALTH_STATUS_");
enum_name!(protocol_name, pb::Protocol, "PROTOCOL_");
enum_name!(
    confidential_mode_name,
    pb::ConfidentialMode,
    "CONFIDENTIAL_MODE_"
);
enum_name!(tee_backend_name, pb::TeeBackend, "TEE_BACKEND_");
enum_name!(disk_format_name, pb::disk_config::Format, "FORMAT_");
enum_name!(disk_role_name, pb::disk_config::DiskRole, "DISK_ROLE_");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_pads_columns_and_trims_trailing_space() {
        let mut out = Vec::new();
        write_table(
            &mut out,
            &["ID", "STATUS"],
            &[
                vec!["vm-1".to_string(), "RUNNING".to_string()],
                vec!["a-much-longer-id".to_string(), "STOPPED".to_string()],
            ],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "ID                STATUS\n\
             vm-1              RUNNING\n\
             a-much-longer-id  STOPPED\n"
        );
    }

    #[test]
    fn durations_use_the_two_most_significant_units() {
        assert_eq!(format_duration_secs(0), "0s");
        assert_eq!(format_duration_secs(45), "45s");
        assert_eq!(format_duration_secs(125), "2m 5s");
        assert_eq!(format_duration_secs(7320), "2h 2m");
        assert_eq!(format_duration_secs(183_600), "2d 3h");
    }

    #[test]
    fn enum_names_strip_the_proto_prefix() {
        use supervisor_proto::pb;
        assert_eq!(vm_status_name(pb::VmStatus::Running as i32), "RUNNING");
        assert_eq!(backend_name(pb::Backend::Qemu as i32), "QEMU");
        assert_eq!(health_status_name(pb::HealthStatus::Ok as i32), "OK");
        assert_eq!(protocol_name(pb::Protocol::Tcp as i32), "TCP");
        assert_eq!(
            confidential_mode_name(pb::ConfidentialMode::SevSnp as i32),
            "SEV_SNP"
        );
        assert_eq!(
            disk_format_name(pb::disk_config::Format::Qcow2 as i32),
            "QCOW2"
        );
        assert_eq!(
            disk_role_name(pb::disk_config::DiskRole::Rootfs as i32),
            "ROOTFS"
        );
        assert_eq!(vm_status_name(999), "UNKNOWN(999)");
    }

    #[test]
    fn or_dash_replaces_empty_strings() {
        assert_eq!(or_dash(""), "-");
        assert_eq!(or_dash("value"), "value");
    }

    #[test]
    fn write_json_is_pretty_with_a_trailing_newline() {
        let mut out = Vec::new();
        write_json(&mut out, &serde_json::json!({"a": 1})).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\n  \"a\": 1\n}\n");
    }
}
