pub mod fscrypt;
pub mod gatekeeper;
pub mod keystore;
pub mod locksettings;
pub mod sharedsecret;
pub mod token;
pub mod user;
pub mod weaver;
#[cfg(target_os = "android")]
pub mod data;
#[cfg(target_os = "android")]
pub mod keymaster;
#[cfg(target_os = "android")]
pub mod keymint;
#[cfg(target_os = "android")]
pub mod keystore2;

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymint::KeyMint<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to
        // any user, so none of them is guarded by a screen lock.
        keymint::KeyMint::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymaster::Keymaster<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        keymaster::Keymaster::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for Service<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to any
        // user, so none of them is guarded by a screen lock.
        Service::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}

/// The phone's key service, whichever generation of it is running. A phone
/// whose system is recent enough has keystore2, which speaks over the
/// ordinary binder; an older one keeps its keys through the hardware key
/// service, which speaks over the hardware binder and hands over addresses
/// rather than values.
///
/// Both are reached the same way from here, so what reads the wrapped keys
/// does not have to know which kind it is talking to.
#[cfg(target_os = "android")]
pub enum Service<'a> {
    New(keymint::KeyMint<'a>),
    Old(keymaster::Keymaster<'a>),
}

#[cfg(target_os = "android")]
impl<'a> Service<'a> {
    /// Reach whichever key service is running. `binder` is the ordinary one
    /// the newer service registers with, `hardware` the one the older
    /// service does.
    pub fn open(binder: &'a skyward_binder::driver::Binder, hardware: &'a skyward_binder::driver::Binder) -> anyhow::Result<Service<'a>> {
        match keymint::KeyMint::open(binder) {
            Ok(new) => Ok(Service::New(new)),
            Err(new) => match keymaster::Keymaster::open(hardware) {
                Ok(old) => Ok(Service::Old(old)),
                // Neither service answered: the newer one's absence is the
                // one worth naming, since that is the one a phone of this
                // age is expected to have.
                Err(old) => Err(new.context(format!("and no older one either: {old:#}"))),
            },
        }
    }

    pub fn hardware(&self) -> anyhow::Result<keymint::Hardware> {
        match self {
            Service::New(service) => service.hardware(),
            Service::Old(service) => {
                let said = service.hardware()?;
                Ok(keymint::Hardware {
                    version: said.version,
                    security_level: said.security_level,
                    name: said.name,
                    author: said.author,
                })
            }
        }
    }

    /// Turn a key only the storage hardware can use into the form it takes
    /// for this start of the phone.
    pub fn ephemeral_storage_key(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Service::New(service) => service.ephemeral_storage_key(key),
            // The older service already keeps the key as the hardware takes
            // it, under a key it makes for every start of the phone, so
            // there is nothing to convert.
            Service::Old(_) => Ok(key.to_vec()),
        }
    }

    /// What the key service says a key may be used for.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> anyhow::Result<Vec<(i32, i64)>> {
        match self {
            Service::New(service) => service.authorizations(key_blob, app_id),
            Service::Old(service) => service.authorizations(key_blob, app_id),
        }
    }

    /// Undo an AES-GCM encryption the key service did with `key_blob`.
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&token::Token>) -> anyhow::Result<Vec<u8>> {
        match self {
            Service::New(service) => service.gcm_decrypt(key_blob, app_id, nonce, body, note),
            Service::Old(service) => service.gcm_decrypt(key_blob, app_id, nonce, body, note),
        }
    }

    /// Whether the secure world will unwrap the key at all.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> anyhow::Result<()> {
        match self {
            Service::New(service) => service.usable(key_blob, app_id),
            Service::Old(service) => service.usable(key_blob, app_id),
        }
    }
}