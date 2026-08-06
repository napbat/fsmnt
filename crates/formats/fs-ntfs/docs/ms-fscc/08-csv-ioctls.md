<!-- MS-FSCC Reference: Cluster Shared Volume IOCTLs -->
<!-- IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_VOLUME_GET_GPT_ATTRIBUTES request/reply structures for CSV filesystems. -->

**2.8** **Cluster Shared Volume File System IOCTLs**

SQL Server Remote Storage Profile [MS-SQLRS] relies on the **I/O control (IOCTL)** code structures,
and definitions in this section, to interpret certain fields that can be sent or received as part of its
processing. See section 2.3 for more information about processing.

**2.8.1** **IOCTL_STORAGE_QUERY_PROPERTY Request**

The IOCTL_STORAGE_QUERY_PROPERTY Request message requests that the server return the
properties of a storage device or verify that the request is supported.

```
  PropertyId (32 bits)
  QueryType (32 bits)
```

**PropertyId (4 bytes):** This field MUST be set to 0x00000006.

**QueryType (4 bytes):** Contains flags indicating the type of query to be performed.

|Value|Meaning|
|---|---|
|0x00000000<br>PropertyStandardQuery|Query to return the<br>IOCTL_STORAGE_QUERY_PROPERTY Reply message.|
|0x00000001<br>PropertyExistsQuery|Query to see whether**PropertyId** is supported.|

**2.8.2** **IOCTL_STORAGE_QUERY_PROPERTY Reply**

The IOCTL_STORAGE_QUERY_PROPERTY Reply message contains the storage alignment information.
```
  Version (32 bits)
  Size (32 bits)
  BytesPerCacheLine (32 bits)
  BytesOffsetForCacheAlignment (32 bits)
  BytesPerLogicalSector (32 bits)
  BytesPerPhysicalSector (32 bits)
  BytesOffsetForSectorAlignment (32 bits)
```

**Version (4 bytes):** Contains the size of this structure, in bytes.

**Size (4 bytes):** Specifies the total size of the data returned, in bytes.

**BytesPerCacheLine (4 bytes):** The number of bytes in a cache line of the device.

**BytesOffsetForCacheAlignment (4 bytes):** The address offset necessary for proper cache access

alignment, in bytes.

**BytesPerLogicalSector (4 bytes):** The number of bytes in a logical sector of the device.

**BytesPerPhysicalSector (4 bytes):** The number of bytes in a physical sector of the device.

**BytesOffsetForSectorAlignment (4 bytes):** The logical sector offset within the first physical sector

where the first logical sector is placed, in bytes.

**2.8.3** **IOCTL_VOLUME_GET_GPT_ATTRIBUTES Request**

The IOCTL_VOLUME_GET_GPT_ATTRIBUTES Request message retrieves the attributes for a volume.

This message does not contain any additional data elements.

**2.8.4** **IOCTL_VOLUME_GET_GPT_ATTRIBUTES Reply**

The IOCTL_VOLUME_GET_GPT_ATTRIBUTES Reply message returns the attributes of the volume.

```
  GptAttributes (32 bits)
  … (32 bits)
```
**GptAttributes (4 bytes):** Specifies all of the attributes associated with a volume.

|Value|Meaning|
|---|---|
|GPT_BASIC_DATA_ATTRIBUTE_READ_ONLY<br>0x1000000000000000|The volume is read-only.|
|GPT_BASIC_DATA_ATTRIBUTE_SHADOW_COPY<br>0x2000000000000000|The volume is a shadow copy of another volume.|
|GPT_BASIC_DATA_ATTRIBUTE_HIDDEN<br>0x4000000000000000|The volume is hidden.|
|GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER<br>0x8000000000000000|The volume is not assigned a default drive letter.|
