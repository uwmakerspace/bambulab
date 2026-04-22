//! LAN live camera (OpenBambuAPI `video.md`): JPEG/TLS on port 6000, RTSPS URL for X1/P2S.
//!
//! Does not include HTTP MJPEG or ffmpeg; consumers adapt frames to their transport.

use std::io;

use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::tls;

/// TCP port for A1/P1-style TLS JPEG stream.
pub const JPEG_VIDEO_PORT: u16 = 6000;
/// TLS port for X1/P2S `rtsps` camera path [`RTSPS_CAMERA_PATH`].
pub const RTSPS_CAMERA_PORT: u16 = 322;
/// Path segment after host:port for the RTSP stream (see OpenBambuAPI `video.md`).
pub const RTSPS_CAMERA_PATH: &str = "streaming/live/1";

/// Failures from [`JpegTcpCameraConnection`] and [`rtsps_camera_url`].
#[derive(Debug, Error)]
pub enum CameraError {
    #[error("TLS config: {0}")]
    TlsConfig(String),
    #[error("invalid printer serial for TLS SNI")]
    InvalidSni,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("camera frame length {len} exceeds maximum {max} bytes")]
    FrameTooLarge { len: usize, max: usize },
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error("rtsps URL: cannot set username or password")]
    RtspsCredentials,
}

/// 80-byte auth block for the JPEG/TLS camera (see `OpenBambuAPI/video.md`, `bambu-mcp` `camera.ts`).
#[must_use]
pub fn jpeg_tcp_auth_packet(username: &str, password: &str) -> [u8; 80] {
    let mut pkt = [0u8; 80];
    pkt[0..4].copy_from_slice(&0x40u32.to_le_bytes());
    pkt[4..8].copy_from_slice(&0x3000u32.to_le_bytes());
    let u = username.as_bytes();
    let p = password.as_bytes();
    let un = u.len().min(32);
    pkt[16..16 + un].copy_from_slice(&u[..un]);
    let pn = p.len().min(32);
    pkt[48..48 + pn].copy_from_slice(&p[..pn]);
    pkt
}

/// Build `rtsps://bblp:{access_code}@{host}:{RTSPS_CAMERA_PORT}/{RTSPS_CAMERA_PATH}` for ffmpeg or other RTSP clients.
///
/// Password is URL-encoded by the `url` crate via `set_password`.
#[must_use = "URL may fail to build"]
pub fn rtsps_camera_url(host: &str, access_code: &str) -> Result<Url, CameraError> {
    let mut url = Url::parse(&format!(
        "rtsps://{host}:{RTSPS_CAMERA_PORT}/{RTSPS_CAMERA_PATH}"
    ))?;
    url.set_username("bblp")
        .map_err(|()| CameraError::RtspsCredentials)?;
    url.set_password(Some(access_code))
        .map_err(|()| CameraError::RtspsCredentials)?;
    Ok(url)
}

/// TLS connection to the printer JPEG camera, after authentication.
pub struct JpegTcpCameraConnection {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    pending: Vec<u8>,
}

impl JpegTcpCameraConnection {
    /// Connect to `{host}:{port}`, perform TLS with SNI = `serial`, send [`jpeg_tcp_auth_packet`] for `bblp` / `access_code`.
    pub async fn connect(
        host: &str,
        port: u16,
        serial: &str,
        access_code: &str,
    ) -> Result<Self, CameraError> {
        let tls_cfg =
            tls::build_lan_tls_config().map_err(|e| CameraError::TlsConfig(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(tls_cfg);
        let sn = ServerName::try_from(serial.to_string()).map_err(|_| CameraError::InvalidSni)?;

        let tcp = TcpStream::connect((host, port)).await?;
        let mut tls = connector.connect(sn, tcp).await?;

        let auth = jpeg_tcp_auth_packet("bblp", access_code);
        tls.write_all(&auth).await?;

        Ok(Self {
            tls,
            pending: Vec::with_capacity(256 * 1024),
        })
    }

    /// Read the next framed JPEG payload (16-byte little-endian header per OpenBambuAPI).
    ///
    /// Returns `Ok(None)` on clean EOF before another frame. Skips payloads that do not start with JPEG SOI (`FF D8`).
    pub async fn read_next_jpeg(
        &mut self,
        max_payload_bytes: usize,
        read_scratch: &mut [u8],
    ) -> Result<Option<Vec<u8>>, CameraError> {
        loop {
            while self.pending.len() >= 16 {
                let payload_len = u32::from_le_bytes([
                    self.pending[0],
                    self.pending[1],
                    self.pending[2],
                    self.pending[3],
                ]) as usize;
                if payload_len > max_payload_bytes {
                    return Err(CameraError::FrameTooLarge {
                        len: payload_len,
                        max: max_payload_bytes,
                    });
                }
                let total = 16usize.saturating_add(payload_len);
                if self.pending.len() < total {
                    break;
                }
                let jpeg = self.pending[16..total].to_vec();
                self.pending.drain(..total);

                if jpeg.len() >= 2 && jpeg.starts_with(&[0xFF, 0xD8]) {
                    return Ok(Some(jpeg));
                }
            }

            let n = self.tls.read(read_scratch).await?;
            if n == 0 {
                return Ok(None);
            }
            self.pending.extend_from_slice(&read_scratch[..n]);
        }
    }
}
