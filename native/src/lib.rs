use neon::prelude::*;

mod party_i;

register_module!(mut cx, {
    cx.export_function("initKeygen", party_i::keygen::keygen_task)?;
    cx.export_function("getPubkey", party_i::hd_keys::get_pubkey)?;
    cx.export_function("signMessage", party_i::sign::sign_message_task)
});
