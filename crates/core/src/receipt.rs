use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReceiptState {
    Delivered,
    Read,
}

pub fn advance_receipt(previous: Option<ReceiptState>, incoming: ReceiptState) -> ReceiptState {
    if previous == Some(ReceiptState::Read) {
        ReceiptState::Read
    } else {
        incoming
    }
}
