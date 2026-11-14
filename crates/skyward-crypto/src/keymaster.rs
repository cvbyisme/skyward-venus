//! The phone's key service of the older kind: the hardware service that
//! wraps every key the phone keeps, spoken to the way the hardware services
//! of its generation are -- each call handing over the addresses of what it
//! carries rather than the bytes themselves.
//!
//! Where the newer key service keeps the group of keys it belongs to as a
//! name of its own, this one puts the wrapped key straight into every call,
//! and where the newer one answers about a key with a list it hands out, this
//! one answers with a pair of runs: what the phone's own software enforces,
//! and what its hardware does.
use crate::token::Token;
use anyhow::{bail, Context, Result};
use skyward_binder::driver::{Binder, Handle};
use skyward_binder::hidl::{self, Answer, Message};
use skyward_binder::status::Fault;

/// The newest version of the service, and the one before it: a phone whose
/// system is recent enough for keystore2 still serves this kind of key
/// service for the keys its storage was wrapped with.
pub const SERVICE: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";
const OLDER: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const INSTANCE: &str = "default";
/// The version of the interface this program speaks, which is what the
/// service was reached by.
const GENERATION: i32 = 4;

/// The methods, numbered in the order the interface declares them.
const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const UPGRADE_KEY: u32 = 12;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

/// How far a tag is shifted to say what kind of value it carries. The tags
/// are the same numbers the newer key service uses, which is why they look
/// arbitrary: the top four bits say what the value is, the rest what it is
/// called.
const TAG_TYPE: u32 = 28;
const KIND_ENUM: u32 = 1;
const KIND_UINT: u32 = 3;
const KIND_BYTES: u32 = 9;

const TAG_PURPOSE: u32 = (KIND_ENUM << TAG_TYPE) | 1;
const TAG_BLOCK_MODE: u32 = (KIND_ENUM << TAG_TYPE) | 4;
const TAG_PADDING: u32 = (KIND_ENUM << TAG_TYPE) | 6;
const TAG_MAC_LENGTH: u32 = (KIND_UINT << TAG_TYPE) | 1003;
const TAG_APPLICATION_ID: u32 = (KIND_BYTES << TAG_TYPE) | 601;
const TAG_NONCE: u32 = (KIND_BYTES << TAG_TYPE) | 1001;

const PURPOSE_DECRYPT: u32 = 1;
const BLOCK_MODE_GCM: u32 = 32;
const PADDING_NONE: u32 = 1;
const MAC_BITS: u64 = 128;
/// How long the nonce of an AES-GCM key is here.
const NONCE_BYTES: usize = 12;
/// The key service's way of saying the key was wrapped under an older build
/// of the phone's own firmware and has to be renewed before it will be used.
const KEY_REQUIRES_UPGRADE: i32 = -62;

/// A parameter as the phone holds one: the tag, then (after four bytes of
/// room nothing is written in) the value, then the frame of a run of bytes
/// where the value is one. Thirty-two bytes in all.
const PARAM_BYTES: usize = 32;
/// Where in a parameter the frame of a run of bytes starts.
const PARAM_POINTS: usize = 16;
/// A note of an unlocked screen: the numbers, then the signature, which is a
/// run of bytes of its own.
const AUTH_BYTES: usize = 56;
const AUTH_POINTS: usize = 40;
/// A note saying another part of the secure world checked what is asked for:
/// its own run of parameters, and a signature that is a run of bytes.
const CHECK_BYTES: usize = 56;
const CHECK_PARAMS: usize = 16;
const CHECK_POINTS: usize = 40;
/// How long the frame of a run of bytes is: where they are, how many, and
/// whether whoever holds it frees them.
const FRAME_BYTES: usize = 16;

/// A parameter of an operation.
enum Param<'a> {
    /// A tag whose value names one of a fixed list.
    Choice(u32, u32),
    /// A tag whose value is a number.
    Number(u32, u64),
    /// A tag whose value is a run of bytes.
    Bytes(u32, &'a [u8]),
}

/// What the phone says about its key hardware.
pub struct Hardware {
    pub version: i32,
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// Write a run of parameters as the call carries one: each in its own frame
/// of thirty-two bytes, and every run of bytes a parameter points at handed
/// over the way a run of its own is.
///
/// Every parameter has the field for a run of bytes, so every one of them
/// writes the place for it, even the ones that point at nothing.
fn params(call: &mut Message, run: &[Param]) {
    let mut body = Vec::with_capacity(run.len() * PARAM_BYTES);
    let mut inside: Vec<(usize, Vec<u8>)> = Vec::with_capacity(run.len());
    for param in run {
        let (tag, value, bytes) = match param {
            Param::Choice(tag, value) => (*tag, u64::from(*value), None),
            Param::Number(tag, value) => (*tag, *value, None),
            Param::Bytes(tag, bytes) => (*tag, 0, Some(bytes.to_vec())),
        };
        let start = body.len();
        body.extend_from_slice(&tag.to_le_bytes());
        // Four bytes of room nothing is written in.
        body.extend_from_slice(&[0; 4]);
        body.extend_from_slice(&value.to_le_bytes());
        body.extend_from_slice(&[0; PARAM_POINTS]);
        inside.push((start + PARAM_POINTS, bytes.unwrap_or_default()));
    }
    call.run(run.len() as u32, body, &inside);
}

/// The parameters that say how an AES-GCM key is used: how it is used, how
/// long its tag is, what it is bound to, and the nonce it was wrapped under.
///
/// What a key is bound to is named only where there is something: the secure
/// world folds the binding into the key it unwraps the blob with, and a
/// binding to nothing named is not the same to it as none named at all.
fn gcm_params<'a>(app_id: &'a [u8], nonce: &'a [u8]) -> Vec<Param<'a>> {
    let mut run = vec![
        Param::Choice(TAG_BLOCK_MODE, BLOCK_MODE_GCM),
        Param::Choice(TAG_PADDING, PADDING_NONE),
        Param::Number(TAG_MAC_LENGTH, MAC_BITS),
    ];
    if !app_id.is_empty() {
        run.push(Param::Bytes(TAG_APPLICATION_ID, app_id));
    }
    run.push(Param::Bytes(TAG_NONCE, nonce));
    run.push(Param::Choice(TAG_PURPOSE, PURPOSE_DECRYPT));
    run
}

/// Hand over the note the secure world wrote when the user answered their
/// screen lock. A key no screen lock guards takes a note all of whose
/// numbers are zero and whose signature is empty, and is refused nothing for
/// carrying it.
fn auth_note(call: &mut Message, note: Option<&Token>) {
    let mut body = vec![0u8; AUTH_BYTES];
    let mut mac = Vec::new();
    if let Some(note) = note {
        body[0..8].copy_from_slice(&(note.challenge as u64).to_le_bytes());
        body[8..16].copy_from_slice(&(note.user as u64).to_le_bytes());
        body[16..24].copy_from_slice(&(note.authenticator as u64).to_le_bytes());
        body[24..28].copy_from_slice(&(note.kind as u32).to_le_bytes());
        body[32..40].copy_from_slice(&(note.when as u64).to_le_bytes());
        mac = note.mac.clone();
    }
    call.structure(body, &[(AUTH_POINTS, mac)]);
}

/// Hand over the note that says another part of the secure world has checked
/// what this one is asked to do. Nothing was checked, so it is empty.
fn nothing_checked(call: &mut Message) {
    let body = vec![0u8; CHECK_BYTES];
    call.structure(body, &[(CHECK_PARAMS, Vec::new()), (CHECK_POINTS, Vec::new())]);
}

/// Read the code a method answered with, and turn it into a reason.
fn refused(read: &mut Answer, what: &str) -> Result<()> {
    let code = read.i32().with_context(|| what.to_string())?;
    if code == 0 {
        return Ok(());
    }
    // The service numbers its refusals as the older kind does, so that the
    // one this program acts on -- a key that has to be renewed -- reads the
    // same here as it does from the newer kind.
    Err(Fault::Service { code, said: String::new() }.into())
}

/// The phone's key service of the older kind, as this program talks to it.
pub struct Keymaster<'a> {
    device: Handle<'a>,
    /// The version the service was reached by, which every call is made by.
    name: &'static str,
}

impl<'a> Keymaster<'a> {
    /// Reach the running key service of the older kind, or say that none is.
    pub fn open(binder: &'a Binder) -> Result<Keymaster<'a>> {
        for name in [SERVICE, OLDER] {
            if let Some(device) = hidl::find(binder, name, INSTANCE)? {
                return Ok(Keymaster { device, name });
            }
        }
        bail!("{SERVICE} is not running; the phone's key service has to be started first")
    }

    /// What the phone says of the hardware that keeps its keys.
    pub fn hardware(&self) -> Result<Hardware> {
        let what = "ask the key service about itself";
        let reply = self.device.transact(GET_HARDWARE_INFO, &Message::call(self.name)).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        let hardware = Hardware {
            version: GENERATION,
            security_level: read.i32().context(what)?,
            name: read.said().context(what)?,
            author: read.said().context(what)?,
        };
        Ok(hardware)
    }

    /// What the key service says a key may be used for: each entry is a tag
    /// and the number or length that came with it.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let what = "ask what the key may be used for";
        let mut call = Message::call(self.name);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self.device.transact(GET_KEY_CHARACTERISTICS, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)?;
        // What the key may be used for is two runs of parameters side by
        // side, one after the other: what the phone's own software enforces,
        // then what its hardware does.
        let both = read.pointed().with_context(|| what.to_string())?;
        if both.len() < 2 * FRAME_BYTES {
            bail!("the key service answered {} bytes about the key", both.len());
        }
        let mut out = Vec::new();
        for half in 0..2 {
            let frame = half * FRAME_BYTES;
            let count = u32::from_le_bytes(both[frame + 8..frame + 12].try_into().expect("four bytes"));
            // The run of parameters itself, which the frame says how to read.
            let (_, said) = read.pair_count().with_context(|| what.to_string())?;
            for one in 0..count as usize {
                let at = one * PARAM_BYTES;
                let Some(held) = said.get(at..at + PARAM_BYTES) else {
                    bail!("the key service answered {} bytes where {count} parameters were named", said.len());
                };
                let tag = i32::from_le_bytes(held[0..4].try_into().expect("four bytes"));
                let value = u64::from_le_bytes(held[8..16].try_into().expect("eight bytes")) as i64;
                // A parameter whose value is a run of bytes says only how
                // long it is, as the newer kind of service does.
                let length = u32::from_le_bytes(held[24..28].try_into().expect("four bytes"));
                let worth = if (tag as u32 >> TAG_TYPE) & 0xF == KIND_BYTES {
                    i64::from(length)
                } else {
                    value
                };
                out.push((tag, worth));
            }
        }
        Ok(out)
    }

    /// Undo an AES-GCM encryption the key service did with the key in
    /// `key_blob`. The service only hands back the plaintext when `app_id` is
    /// the one the key was made for, so a wrong secret fails here rather than
    /// yielding something that looks like a key.
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&Token>) -> Result<Vec<u8>> {
        let operation = match self.begin(key_blob, app_id, nonce, note) {
            Ok(operation) => operation,
            Err(e) if skyward_binder::status::refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                // The phone's firmware has moved on since this key was made.
                // Renewing it gives a key for the firmware running now; the
                // one on disk is left as it is, so nothing of the phone's own
                // is changed by reading it here.
                let run = gcm_params(app_id, nonce);
                let renewed = self.upgrade(key_blob, &run).context("renew the key for the firmware running now")?;
                self.begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e),
        };
        let mut out = self.update(operation, body)?;
        out.extend_from_slice(&self.finish(operation)?);
        Ok(out)
    }

    /// Open a decryption with the key service and keep the number it gives
    /// for it, which every call that carries the decryption along repeats.
    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<u64> {
        let what = "start a decryption";
        let mut call = Message::call(self.name);
        call.u32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        params(&mut call, &gcm_params(app_id, nonce));
        // A key guarded by the screen lock takes the note the secure world
        // wrote when the user answered it; one that is not guarded takes a
        // note of nothing, and is refused nothing for carrying it.
        let marker = note.cloned();
        auth_note(&mut call, marker.as_ref());
        let reply = self.device.transact(BEGIN, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)?;
        // What the decryption is set up to do, which is nothing new here.
        read.pair_count().with_context(|| what.to_string())?;
        read.u64().context("read which decryption the key service opened")
    }

    /// A key for the firmware running now, from one made under an older
    /// build. What it is bound to has to be given again, or the service
    /// cannot tell it is the right key.
    fn upgrade(&self, key_blob: &[u8], run: &[Param]) -> Result<Vec<u8>> {
        let what = "renew the key";
        let mut call = Message::call(self.name);
        call.bytes(key_blob);
        params(&mut call, run);
        let reply = self.device.transact(UPGRADE_KEY, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)?;
        Ok(read.pair().with_context(|| what.to_string())?.to_vec())
    }

    fn update(&self, operation: u64, input: &[u8]) -> Result<Vec<u8>> {
        let what = "feed the decryption";
        let mut call = Message::call(self.name);
        call.u64(operation);
        params(&mut call, &[]);
        call.bytes(input);
        auth_note(&mut call, None);
        nothing_checked(&mut call);
        let reply = self.device.transact(UPDATE, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)?;
        read.u32().context("read how much of what was fed was used")?;
        read.pair_count().with_context(|| what.to_string())?;
        Ok(read.pair().with_context(|| what.to_string())?.to_vec())
    }

    fn finish(&self, operation: u64) -> Result<Vec<u8>> {
        let what = "close the decryption, which is where a wrong key is refused";
        let mut call = Message::call(self.name);
        call.u64(operation);
        params(&mut call, &[]);
        call.bytes(&[]);
        call.bytes(&[]);
        auth_note(&mut call, None);
        nothing_checked(&mut call);
        let reply = self.device.transact(FINISH, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)?;
        read.pair_count().with_context(|| what.to_string())?;
        Ok(read.pair().with_context(|| what.to_string())?.to_vec())
    }

    fn abort(&self, operation: u64) -> Result<()> {
        let what = "drop the decryption";
        let mut call = Message::call(self.name);
        call.u64(operation);
        let reply = self.device.transact(ABORT, &call).context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        refused(&mut read, what)
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing. It tells a key the secure world cannot
    /// unwrap, as one made under another build or bound to something not
    /// given back to it is, apart from one that merely decrypts to nothing.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        self.abort(operation)
    }

    /// A key the storage hardware can use as it is. This generation of the
    /// service keeps the key wrapped under a key of its own for every start
    /// of the phone, so the wrapped key is handed over as it is.
    pub fn ephemeral_storage_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        Ok(key.to_vec())
    }
}
