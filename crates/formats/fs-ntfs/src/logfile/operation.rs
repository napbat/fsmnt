use super::records::NtfsLogOperation;

impl NtfsLogOperation {
    /// Returns the numeric operation code stored in an NTFS log record.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Noop => 0x00,
            Self::CompensationLogRecord => 0x01,
            Self::InitializeFileRecordSegment => 0x02,
            Self::DeallocateFileRecordSegment => 0x03,
            Self::WriteEndOfFileRecordSegment => 0x04,
            Self::CreateAttribute => 0x05,
            Self::DeleteAttribute => 0x06,
            Self::UpdateResidentValue => 0x07,
            Self::UpdateNonresidentValue => 0x08,
            Self::UpdateMappingPairs => 0x09,
            Self::DeleteDirtyClusters => 0x0A,
            Self::SetNewAttributeSizes => 0x0B,
            Self::AddIndexEntryRoot => 0x0C,
            Self::DeleteIndexEntryRoot => 0x0D,
            Self::AddIndexEntryAllocation => 0x0E,
            Self::DeleteIndexEntryAllocation => 0x0F,
            Self::WriteEndOfIndexBuffer => 0x10,
            Self::SetIndexEntryVcnRoot => 0x11,
            Self::SetIndexEntryVcnAllocation => 0x12,
            Self::UpdateFileNameRoot => 0x13,
            Self::UpdateFileNameAllocation => 0x14,
            Self::SetBitsInNonresidentBitMap => 0x15,
            Self::ClearBitsInNonresidentBitMap => 0x16,
            Self::HotFix => 0x17,
            Self::EndTopLevelAction => 0x18,
            Self::PrepareTransaction => 0x19,
            Self::CommitTransaction => 0x1A,
            Self::ForgetTransaction => 0x1B,
            Self::OpenNonresidentAttribute => 0x1C,
            Self::OpenAttributeTableDump => 0x1D,
            Self::AttributeNamesDump => 0x1E,
            Self::DirtyPageTableDump => 0x1F,
            Self::TransactionTableDump => 0x20,
            Self::UpdateRecordDataRoot => 0x21,
            Self::UpdateRecordDataAllocation => 0x22,
            Self::UpdateRelativeDataIndex => 0x23,
            Self::UpdateRelativeDataAllocation => 0x24,
            Self::ZeroEndOfFileRecord => 0x25,
        }
    }
}
