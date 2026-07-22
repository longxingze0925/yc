use serde::{Deserialize, Serialize};

use crate::{CanonicalError, CanonicalWriter};

// Kept for the existing pre-freeze Signal/store skeleton. New code must use SessionPermissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub remote_desktop: bool,
    pub input_control: bool,
    pub clipboard: bool,
    pub file_transfer: bool,
    pub unattended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPermissions {
    pub remote_desktop: bool,
    pub input_control: bool,
    pub clipboard: bool,
    pub file_transfer: bool,
    pub unattended: bool,
    pub privacy_screen: bool,
    pub block_local_input: bool,
    pub require_prompt: bool,
    pub allow_relay: bool,
}

impl Default for SessionPermissions {
    fn default() -> Self {
        Self {
            remote_desktop: false,
            input_control: false,
            clipboard: false,
            file_transfer: false,
            unattended: false,
            privacy_screen: false,
            block_local_input: false,
            require_prompt: true,
            allow_relay: false,
        }
    }
}

impl From<Permissions> for SessionPermissions {
    fn from(value: Permissions) -> Self {
        Self {
            remote_desktop: value.remote_desktop,
            input_control: value.input_control,
            clipboard: value.clipboard,
            file_transfer: value.file_transfer,
            unattended: value.unattended,
            ..Self::default()
        }
    }
}

impl SessionPermissions {
    pub const FIELD_NAMES: [&'static str; 9] = [
        "remote_desktop",
        "input_control",
        "clipboard",
        "file_transfer",
        "unattended",
        "privacy_screen",
        "block_local_input",
        "require_prompt",
        "allow_relay",
    ];

    pub fn canonical_bytes(self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::without_domain();
        writer
            .push_bool("remote_desktop", self.remote_desktop)?
            .push_bool("input_control", self.input_control)?
            .push_bool("clipboard", self.clipboard)?
            .push_bool("file_transfer", self.file_transfer)?
            .push_bool("unattended", self.unattended)?
            .push_bool("privacy_screen", self.privacy_screen)?
            .push_bool("block_local_input", self.block_local_input)?
            .push_bool("require_prompt", self.require_prompt)?
            .push_bool("allow_relay", self.allow_relay)?;
        Ok(writer.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_defaults_materialize_all_nine_permissions() {
        let permissions = SessionPermissions::default();
        let bytes = permissions.canonical_bytes().expect("canonical");

        assert!(permissions.require_prompt);
        assert!(!permissions.allow_relay);
        assert_eq!(SessionPermissions::FIELD_NAMES.len(), 9);

        let mut cursor = 0;
        let mut values = Vec::new();
        for expected_name in SessionPermissions::FIELD_NAMES {
            let name_len =
                u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().expect("name length"))
                    as usize;
            cursor += 4;
            assert_eq!(&bytes[cursor..cursor + name_len], expected_name.as_bytes());
            cursor += name_len;

            let value_len =
                u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().expect("value length"))
                    as usize;
            cursor += 4;
            assert_eq!(value_len, 1);
            values.push(bytes[cursor]);
            cursor += value_len;
        }

        assert_eq!(cursor, bytes.len());
        assert_eq!(values, [0, 0, 0, 0, 0, 0, 0, 1, 0]);
    }

    #[test]
    fn privacy_permissions_change_canonical_bytes() {
        let baseline = SessionPermissions::default()
            .canonical_bytes()
            .expect("canonical");
        let changed = SessionPermissions {
            privacy_screen: true,
            ..SessionPermissions::default()
        }
        .canonical_bytes()
        .expect("canonical");

        assert_ne!(baseline, changed);
    }
}
