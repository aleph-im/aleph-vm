//! The local TDREPORT: the TD's own view of its registers, straight from the
//! TDX module over `/dev/tdx_guest`, with no host round trip.
//!
//! A TDREPORT is 1024 bytes: REPORTMACSTRUCT (256), TEE_TCB_INFO (239),
//! reserved (17), TDINFO (512). It is MACed with a CPU-local key, so it
//! proves nothing to a remote party; a quote wraps it in a signature for
//! that. In the guest it answers "which MRCONFIGID was I launched with"
//! before anything else runs, which is all the descriptor check needs.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// The TDX guest device the report ioctl is issued on.
pub const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";

pub const TDREPORT_SIZE: usize = 1024;
pub const REPORTDATA_SIZE: usize = 64;

/// `TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)`: direction
/// read|write, size 1088, type 'T', number 1.
pub const TDX_CMD_GET_REPORT0: libc::c_ulong =
    (3 << 30) | ((std::mem::size_of::<TdxReportReq>() as libc::c_ulong) << 16) | (0x54 << 8) | 1;

/// `struct tdx_report_req` from `<uapi/linux/tdx-guest.h>`.
#[repr(C)]
pub struct TdxReportReq {
    pub reportdata: [u8; REPORTDATA_SIZE],
    pub tdreport: [u8; TDREPORT_SIZE],
}

// Absolute offsets in the 1024-byte report.
const REPORTMACSTRUCT_REPORT_TYPE: usize = 0;
const REPORTMACSTRUCT_REPORTDATA: usize = 128;
const TEE_TCB_INFO: usize = 256;
const TEE_TCB_SVN: usize = TEE_TCB_INFO + 8;
const MRSEAM: usize = TEE_TCB_INFO + 24;
const TDINFO: usize = 512;
const TD_ATTRIBUTES: usize = TDINFO;
const XFAM: usize = TDINFO + 8;
const MRTD: usize = TDINFO + 16;
const MRCONFIGID: usize = TDINFO + 64;
const MROWNER: usize = TDINFO + 112;
const MROWNERCONFIG: usize = TDINFO + 160;
const RTMR0: usize = TDINFO + 208;
const SERVTD_HASH: usize = TDINFO + 400;

/// The fields of a TDREPORT a guest acts on. Everything is copied out of the
/// raw buffer; nothing here is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReport {
    /// REPORTMACSTRUCT report type: `{type, subtype, version, reserved}`,
    /// type 0x81 for a TDX report.
    pub report_type: [u8; 4],
    /// The 64 bytes the caller passed in, echoed by the module.
    pub reportdata: [u8; REPORTDATA_SIZE],
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    /// RTMR0 to RTMR3, in order.
    pub rtmr: [[u8; 48]; 4],
    pub servtd_hash: [u8; 48],
}

fn field<const N: usize>(raw: &[u8; TDREPORT_SIZE], offset: usize) -> [u8; N] {
    raw[offset..offset + N]
        .try_into()
        .expect("offsets are constants inside the report")
}

/// Pick the fields out of a raw TDREPORT.
pub fn parse_tdreport(raw: &[u8; TDREPORT_SIZE]) -> TdReport {
    TdReport {
        report_type: field(raw, REPORTMACSTRUCT_REPORT_TYPE),
        reportdata: field(raw, REPORTMACSTRUCT_REPORTDATA),
        tee_tcb_svn: field(raw, TEE_TCB_SVN),
        mrseam: field(raw, MRSEAM),
        attributes: field(raw, TD_ATTRIBUTES),
        xfam: field(raw, XFAM),
        mrtd: field(raw, MRTD),
        mrconfigid: field(raw, MRCONFIGID),
        mrowner: field(raw, MROWNER),
        mrownerconfig: field(raw, MROWNERCONFIG),
        rtmr: std::array::from_fn(|i| field(raw, RTMR0 + 48 * i)),
        servtd_hash: field(raw, SERVTD_HASH),
    }
}

/// Issue `TDX_CMD_GET_REPORT0` on `device` and return the raw TDREPORT.
pub fn local_tdreport_bytes_from(
    device: &Path,
    reportdata: &[u8; REPORTDATA_SIZE],
) -> Result<[u8; TDREPORT_SIZE]> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device)
            .with_context(|| format!("cannot open {}", device.display()))?;
        let mut req = TdxReportReq {
            reportdata: *reportdata,
            tdreport: [0u8; TDREPORT_SIZE],
        };
        // SAFETY: the fd is open for the call's duration and `req` is a
        // live, correctly sized struct tdx_report_req the kernel fills.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TDX_CMD_GET_REPORT0, &mut req) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            bail!("TDX_CMD_GET_REPORT0 on {} failed: {e}", device.display());
        }
        Ok(req.tdreport)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (device, reportdata);
        bail!("the TDREPORT ioctl is only available on Linux")
    }
}

/// The TD's own report from [`TDX_GUEST_DEVICE`], with `reportdata` bound in.
pub fn local_tdreport(reportdata: &[u8; REPORTDATA_SIZE]) -> Result<TdReport> {
    let raw = local_tdreport_bytes_from(Path::new(TDX_GUEST_DEVICE), reportdata)?;
    let report = parse_tdreport(&raw);
    // A report whose echoed reportdata differs came from something other
    // than the TDX module answering this request.
    if &report.reportdata != reportdata {
        bail!("TDREPORT does not echo the requested reportdata");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report where every byte is its own absolute offset modulo 251,
    /// so any field read at the wrong offset shows a different pattern.
    fn synthetic() -> [u8; TDREPORT_SIZE] {
        std::array::from_fn(|i| (i % 251) as u8)
    }

    fn pattern<const N: usize>(offset: usize) -> [u8; N] {
        std::array::from_fn(|i| ((offset + i) % 251) as u8)
    }

    #[test]
    fn ioctl_number_matches_the_uapi_header() {
        assert_eq!(std::mem::size_of::<TdxReportReq>(), 1088);
        assert_eq!(TDX_CMD_GET_REPORT0, 0xc440_5401);
    }

    #[test]
    fn fields_sit_at_the_hardware_verified_offsets() {
        let report = parse_tdreport(&synthetic());
        assert_eq!(report.report_type, pattern::<4>(0));
        assert_eq!(report.reportdata, pattern::<64>(128));
        assert_eq!(report.tee_tcb_svn, pattern::<16>(264));
        assert_eq!(report.mrseam, pattern::<48>(280));
        assert_eq!(report.attributes, pattern::<8>(512));
        assert_eq!(report.xfam, pattern::<8>(520));
        assert_eq!(report.mrtd, pattern::<48>(528));
        assert_eq!(report.mrconfigid, pattern::<48>(576));
        assert_eq!(report.mrowner, pattern::<48>(624));
        assert_eq!(report.mrownerconfig, pattern::<48>(672));
        assert_eq!(report.rtmr[0], pattern::<48>(720));
        assert_eq!(report.rtmr[1], pattern::<48>(768));
        assert_eq!(report.rtmr[2], pattern::<48>(816));
        assert_eq!(report.rtmr[3], pattern::<48>(864));
        assert_eq!(report.servtd_hash, pattern::<48>(912));
    }

    #[test]
    fn mrconfigid_is_read_where_qemu_puts_it() {
        // The one field the descriptor check depends on, pinned on its own.
        let mut raw = [0u8; TDREPORT_SIZE];
        raw[576..624].copy_from_slice(&[0xC1; 48]);
        let report = parse_tdreport(&raw);
        assert_eq!(report.mrconfigid, [0xC1; 48]);
        assert_eq!(report.mrtd, [0u8; 48]);
        assert_eq!(report.rtmr, [[0u8; 48]; 4]);
    }

    #[test]
    fn a_missing_device_is_an_error_not_a_panic() {
        let err = local_tdreport_bytes_from(Path::new("/nonexistent/tdx_guest"), &[0u8; 64])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot open"), "got: {err}");
    }
}
