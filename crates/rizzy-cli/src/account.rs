//! The account commands of `rv`: a new master password or Secret Key (CRYPTO.md §11.5) and
//! server-side 2FA (§5.10, §11.15). The flows are [`Device::change_credentials`],
//! [`Device::totp_enable`] and [`Device::totp_disable`]; this module opens the device and
//! tells the user what happened.
//!
//! - `rv password --name <login> [--rotate]`: a new master password, asked twice. The keys
//!   are not rotated unless `--rotate` ("also rotate keys", for a password that leaked); with
//!   it and recovery on, the current recovery code is asked for and kept.
//! - `rv secret-key --name <login> [--skip-rotation]`: a new Secret Key and a new Emergency
//!   Kit, with a standard rotation by default (and then a new recovery code when recovery is
//!   on). `--skip-rotation` is the explicit opt-out.
//! - `rv 2fa enable --name <login>` / `rv 2fa disable --name <login>`: server-side TOTP. The
//!   code is read from the terminal without echo, or from standard input; never from the
//!   command line.
//!
//! Every one of them re-authenticates with the current master password (and the current
//! second factor, if 2FA is on). Other devices are asked for the new password, and the new
//! Secret Key if it changed, the next time they go online (CRYPTO.md §11.3 step 5).

use crate::device::{CredentialChange, Device, Env};
use crate::error::CliError;

/// `rv password` and `rv secret-key`.
///
/// # Errors
/// As [`Device::open`] and [`Device::change_credentials`].
pub async fn change(
    env: &mut Env<'_>,
    name: &str,
    change: CredentialChange,
) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    let outcome = Box::pin(device.change_credentials(env.ui, name, change)).await?;
    let dropped = outcome.dropped_items;
    env.ui.note(match change {
        CredentialChange::Password { .. } => "The master password was changed.",
        // CRYPTO.md §11.5 step 4: the kit carries a new recovery code only when the rotation
        // issues one, so without it the old kit's code is still the account's.
        CredentialChange::SecretKey { .. } if outcome.old_recovery_code_kept => {
            "The Secret Key was changed: the Secret Key of your earlier Emergency Kit no longer \
             works, but its recovery code stays valid and is the only copy. Keep it with the \
             new kit."
        }
        CredentialChange::SecretKey { .. } => {
            "The Secret Key was changed; only the new Emergency Kit works from now on."
        }
    });
    if matches!(
        change,
        CredentialChange::Password { rotate: true } | CredentialChange::SecretKey { rotate: true }
    ) {
        env.ui
            .note("The account key and the vault key were rotated.");
    }
    if dropped > 0 {
        env.ui.note(&format!(
            "{dropped} item keys could not be opened and were dropped: those items are no \
             longer readable on any device."
        ));
    }
    env.ui
        .note("Your other devices ask for the new credentials the next time they go online.");
    Ok(())
}

/// `rv 2fa enable` and `rv 2fa disable`.
///
/// # Errors
/// As [`Device::open`], [`Device::totp_enable`] and [`Device::totp_disable`].
pub async fn two_factor(env: &mut Env<'_>, name: &str, enable: bool) -> Result<(), CliError> {
    let mut device = Device::open(env).await?;
    if enable {
        Box::pin(device.totp_enable(env.ui, name)).await
    } else {
        Box::pin(device.totp_disable(env.ui, name)).await
    }
}
