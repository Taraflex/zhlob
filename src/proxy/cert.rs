use crate::{cli::APP_NAME, initable_static};
use directories::BaseDirs;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct CertifiedKeyDer<'a>(pub(crate) &'a [u8]);

impl<'a> CertifiedKeyDer<'a> {
    const KEY_SIZE: usize = 138;

    pub fn key_der(&self) -> &'a [u8] {
        &self.0[..Self::KEY_SIZE]
    }

    pub fn cert_der(&self) -> &'a [u8] {
        &self.0[Self::KEY_SIZE..]
    }

    pub fn generate_cert(
        host: String,
        issuer: &rcgen::Issuer<rcgen::KeyPair>,
    ) -> Result<Vec<u8>, rcgen::Error> {
        let mut cert_params = rcgen::CertificateParams::new(vec![host.clone()])?;
        cert_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::DigitalSignature);
        cert_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        cert_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        cert_params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, host);
            dn
        };

        let key_pair = rcgen::KeyPair::generate()?;

        let cert = cert_params.signed_by(&key_pair, issuer)?;

        let mut key = key_pair.serialize_der();
        debug_assert_eq!(key.len(), Self::KEY_SIZE);
        key.extend_from_slice(&cert.der().to_vec());
        Ok(key)
    }
}

pub struct CertPaths {
    pub cert_cer_path: PathBuf,
    pub cert_pem_path: PathBuf,
    key_pem_path: PathBuf,
}

initable_static! {
    BASE_DIRS: BaseDirs = || {
        BaseDirs::new().expect("Failed to determine base directories. Ensure HOME environment variable is set.")
    };
    CERT_PATHS: CertPaths = || {
        let cert_dir = BASE_DIRS.home_dir().join(const_str::concat!(".", APP_NAME));

        fs::create_dir_all(&cert_dir).expect(&format!(
            "Failed to create certificate directory: {}",
            cert_dir.display()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cert_dir, fs::Permissions::from_mode(0o700)).expect(&format!(
                "Failed to set directory permissions for: {}",
                cert_dir.display()
            ));
        }

        let key_pem_path = cert_dir.join(const_str::concat!(APP_NAME, "-ca-secret-signing-key.pem"));
        let cert_cer_path = cert_dir.join(const_str::concat!(APP_NAME, "-ca-cert.cer"));
        let cert_pem_path = cert_dir.join(const_str::concat!(APP_NAME, "-ca-cert.pem"));
        CertPaths {
            cert_cer_path,
            cert_pem_path,
            key_pem_path,
        }
    };
}

fn write_file_with_permissions(path: &Path, content: &[u8], description: &str) {
    fs::write(path, content).expect(&format!(
        "Failed to write {} to {}",
        description,
        path.display()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect(&format!(
            "Failed to set permissions for {}: {}",
            description,
            path.display()
        ));
    }
}

pub fn load_root_issuer() -> Issuer<'static, KeyPair> {
    let issuer = match (|| -> Result<Issuer<KeyPair>, Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = fs::read_to_string(&CERT_PATHS.cert_pem_path)?;
        let key_pem = fs::read_to_string(&CERT_PATHS.key_pem_path)?;
        let signing_key = KeyPair::from_pem(&key_pem)?;
        Ok(Issuer::from_ca_cert_pem(&cert_pem, signing_key)?)
    })() {
        Ok(issuer) => issuer,
        Err(e) => {
            tracing::warn!(
                "Failed to read or parse existing certificates ({}). Generating new CA certificate and key...",
                e
            );
            let mut params = CertificateParams::default();
            params.distinguished_name = DistinguishedName::new();
            params.distinguished_name.push(
                DnType::CommonName,
                DnValue::Utf8String("Setup cert help: http://mitm.it".to_string()),
            );
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

            let signing_key = KeyPair::generate().unwrap();
            write_file_with_permissions(
                &CERT_PATHS.key_pem_path,
                signing_key.serialize_pem().as_bytes(),
                "key PEM file",
            );

            let cert = params.self_signed(&signing_key).unwrap();
            write_file_with_permissions(
                &CERT_PATHS.cert_pem_path,
                cert.pem().as_bytes(),
                "certificate CRT file",
            );
            write_file_with_permissions(
                &CERT_PATHS.cert_cer_path,
                cert.der(),
                "certificate CER file",
            );

            Issuer::new(params, signing_key)
        }
    };

    issuer
}
