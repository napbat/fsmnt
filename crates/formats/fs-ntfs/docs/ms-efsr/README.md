# MS-EFSR Reference (v21.0, May 2014)

Split from `[MS-EFSR].pdf` — Microsoft Encrypting File System Remote (EFSRPC) Protocol specification.
Use this index to find the right file for a given topic.

## Files

| File | What to find here |
|------|-------------------|
| `00-introduction.md` | **Glossary** (DDF, DRF, FEK, DRA, VDL, sparse file), normative/informative references, spec overview, protocol relationships, RPC endpoints (`\pipe\efsrpc` UUID `df1941c5-...`, `\pipe\lsarpc` UUID `c681d488-...`) |
| `01-metadata-v1.md` | **EFSRPC Metadata V1** (§2.2.2) — on-disk format for EFS Version 1–3 (Win2000/XP/2003). 84-byte header (Length, EFS_Version, EFS_ID GUID, DDF_Offset, DRF_Offset), **Key List** structure, **Key List Entry** (encrypted FEK offset, RSA/AES-256 flags), **Public Key Information** (owner SID, credential type), **Certificate Data** (SHA-1 thumbprint, container/provider/display names in UTF-16LE), **Encrypted FEK** (Key_Length, Entropy, ALG_ID, Key bytes) |
| `02-metadata-v2.md` | **EFSRPC Metadata V2** (§2.2.2.2) — on-disk format for EFS Version 4–5 (Vista+). 52-byte header with FekInfo_Datum. **EFSX Datum** tagged structures (StructureSize, Role, Type, Flags), **Blob Datum**, **Descriptor Datum**, **Protector List Entry** (RSA/ECC/DPAPI-NG types), **Protector Info**, **Key Agreement Datum** (ECC), **FekInfo Datum** (AES keywrap per RFC 3394) |
| `03-raw-data-format.md` | **EFSRPC Raw Data Format** (§2.2.3) — marshaled stream for backup/restore (`ReadEncryptedFileRaw`/`WriteEncryptedFileRaw`). Marshaled Stream, Stream Data Segment, Data Segment Encryption Header, Extended Header. Also: RPC types (§2.2.4–2.2.18) including `ALG_ID` values, `EFS_KEY_INFO`, `ENCRYPTION_CERTIFICATE`, `EFS_COMPATIBILITY_INFO`, `ENCRYPTED_FILE_METADATA_SIGNATURE` |
| `04-protocol-details.md` | **Transport** (§2.1) — RPC over named pipes/SMB. **Protocol Details** (§3) — abstract data model, user-certificate binding, EFS certificate enrollment, EFSRPC interface (18 opcodes: OpenFileRaw, ReadFileRaw, WriteFileRaw, CloseRaw, EncryptFileSrv, DecryptFileSrv, QueryUsersOnFile, QueryRecoveryAgents, RemoveUsersFromFile, AddUsersToFile, FileKeyInfo, DuplicateEncryptionInfoFile, AddUsersToFileEx, FileKeyInfoEx, GetEncryptedFileMetadata, SetEncryptedFileMetadata, FlushEfsCache) |
| `05-idl.md` | **Full IDL** (§6) — Microsoft Interface Definition Language for the EFSRPC interface |
| `06-product-behavior.md` | **Product Behavior** (§7) — Windows version-specific behavior footnotes. Maps `<N>` references to Windows versions |

## Quick Lookup

| Question | File |
|----------|------|
| EFS on-disk metadata header layout? | `01-metadata-v1.md` (V1) or `02-metadata-v2.md` (V2) |
| DDF/DRF key list structure? | `01-metadata-v1.md` §2.2.2.1.1 |
| Encrypted FEK format (ALG_ID, key bytes)? | `01-metadata-v1.md` §2.2.2.1.5 |
| Certificate thumbprint and container names? | `01-metadata-v1.md` §2.2.2.1.4 |
| EFSX Datum types and roles (V2)? | `02-metadata-v2.md` §2.2.2.2.2 |
| Protector types (RSA, ECC, DPAPI-NG)? | `02-metadata-v2.md` §2.2.2.2.5 |
| AES keywrap FEK/IV (V2)? | `02-metadata-v2.md` §2.2.2.2.8 |
| Raw backup stream format? | `03-raw-data-format.md` §2.2.3 |
| ALG_ID values (DESX, 3DES, AES-256)? | `03-raw-data-format.md` §2.2.13 |
| RPC opcode behavior? | `04-protocol-details.md` §3.1.4.2 |
| Which EFS version introduced what? | `06-product-behavior.md` |
| EFS glossary terms (FEK, DDF, DRF, DRA)? | `00-introduction.md` §1.1 |
