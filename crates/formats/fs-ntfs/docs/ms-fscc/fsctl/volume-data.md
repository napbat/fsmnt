<!-- MS-FSCC: Volume Data (NTFS and ReFS) -->
<!-- GET_NTFS_VOLUME_DATA (MFT start LCN, MFT zone, clusters, serial). GET_REFS_VOLUME_DATA (ReFS geometry). -->

**2.3.21** **FSCTL_GET_NTFS_VOLUME_DATA Request**

This message requests that the server return information about the **NTFS** file system **volume** that
contains the file or directory that is associated with the handle on which this **FSCTL** was invoked.

This message does not contain any parameters.

**2.3.22** **FSCTL_GET_NTFS_VOLUME_DATA Reply**

The FSCTL_GET_NTFS_VOLUME_DATA reply message returns the results of the
FSCTL_GET_NTFS_VOLUME_DATA request as an NTFS_VOLUME_DATA_BUFFER element.

The NTFS_VOLUME_DATA_BUFFER contains information on a **volume** . For more information about the
**NTFS** file system, see [[MSFT-NTFS].](https://go.microsoft.com/fwlink/?LinkId=90200)

```
  VolumeSerialNumber (32 bits)
  NumberSectors (32 bits)
  ...
```
**VolumeSerialNumber (8 bytes):** A 64-bit signed integer that contains the serial number of the

volume. This is a unique number assigned to the volume media by the operating system when the
volume is formatted.

**NumberSectors (8 bytes):** A 64-bit signed integer that contains the number of **sectors** in the

specified volume.

**TotalClusters (8 bytes):** A 64-bit signed integer that contains the total number of **clusters** in the

specified volume.
**FreeClusters (8 bytes):** A 64-bit signed integer that contains the number of free clusters in the

specified volume.

**TotalReserved (8 bytes):** A 64-bit signed integer that contains the number of reserved clusters in

the specified volume. Reserved clusters are free clusters reserved for when the volume becomes
full. Reserved clusters used to guarantee clusters are available at points when the file system can't
properly report allocation failures.

**BytesPerSector (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in a sector

on the specified volume.

**BytesPerCluster (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in a cluster

on the specified volume. This value is also known as the cluster factor.

**BytesPerFileRecordSegment (4 bytes):** A 32-bit unsigned integer that contains the number of

bytes in a **file record segment** .

**ClustersPerFileRecordSegment (4 bytes):** A 32-bit unsigned integer that contains the number of

clusters in a file record segment.

**MftValidDataLength (8 bytes):** A 64-bit signed integer that contains the size of the **master file**

**table** in bytes.

**MftStartLcn (8 bytes):** A 64-bit signed integer that contains the starting **logical cluster number**

**(LCN)** of the master file table.

**Mft2StartLcn (8 bytes):** A 64-bit signed integer that contains the starting logical cluster number of

the master file table mirror.

**MftZoneStart (8 bytes):** A 64-bit signed integer that contains the starting logical cluster number of

the master file table zone.

**MftZoneEnd (8 bytes):** A 64-bit signed integer that contains the ending logical cluster number of the

master file table zone. The size of the master file table zone is ( **MftZoneEnd**   - **MftZoneStart** )
clusters.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned directly by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common
error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle specified is not open.|
|STATUS_VOLUME_DISMOUNTED<br>0xC000026E|The specified volume is no longer mounted.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain an**NTFS_VOLUME_DATA_BUFFER** <br>structure.|

**2.3.23** **FSCTL_GET_REFS_VOLUME_DATA Request**

This message requests that the server return information about the ReFS file system volume that
contains the file or directory that is associated with the handle on which this FSCTL was invoked.

This message does not contain any parameters.
**2.3.24** **FSCTL_GET_REFS_VOLUME_DATA Reply**

The FSCTL_GET_REFS_VOLUME_DATA reply message returns the results of the
FSCTL_GET_REFS_VOLUME_DATA request as an REFS_VOLUME_DATA_BUFFER element.

The REFS_VOLUME_DATA_BUFFER contains information on a volume.

```
  ByteCount (32 bits)
  MajorVersion (32 bits)
  MinorVersion (32 bits)
  BytesPerPhysicalSector (32 bits)
  VolumeSerialNumber (32 bits)
  NumberSectors (32 bits)
  TotalClusters (32 bits)
  FreeClusters (32 bits)
  TotalReserved (32 bits)
  BytesPerSector (32 bits)
  BytesPerCluster (32 bits)
  MaximumSizeOfResidentFile (32 bits)
  Reserved (80 bytes) (32 bits)
  ...
```
**ByteCount (4 bytes):** A 32-bit unsigned integer that contains the valid data length for this structure.

**ByteCount** can be less than the size of this structure. Only the fields that entirely fit within the
valid data length for this structure, as defined by **ByteCount**, are valid.

**MajorVersion (4 bytes):** A 32-bit unsigned integer that contains the major version of the ReFS

volume.

**MinorVersion (4 bytes):** A 32-bit unsigned integer that contains the minor version of the ReFS

volume.

**BytesPerPhysicalSector (4 bytes):** A 32-bit unsigned integer that defines the number of bytes in a

physical sector on the specified volume.

**VolumeSerialNumber (8 bytes):** A 64-bit signed integer that contains the serial number of the

volume. This is a unique number assigned to the volume media by the operating system when the
volume is formatted.

**NumberSectors (8 bytes):** A 64-bit signed integer that contains the number of **sectors** in the

specified volume.

**TotalClusters (8 bytes):** A 64-bit signed integer that contains the total number of **clusters** in the

specified volume.

**FreeClusters (8 bytes):** A 64-bit signed integer that contains the number of free clusters in the

specified **volume** .

**TotalReserved (8 bytes):** A 64-bit signed integer that contains the number of reserved clusters in

the specified volume. Reserved clusters are used to guarantee clusters are available at points
when the file system can't properly report allocation failures.

**BytesPerSector (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in a sector

on the specified volume.

**BytesPerCluster (4 bytes):** A 32-bit unsigned integer that contains the number of bytes in a cluster

on the specified volume. This value is also known as the cluster factor.

**MaximumSizeOfResidentFile (8 bytes):** A 64-bit unsigned integer that defines the maximum

number of bytes a file can contain and be co-located with the file system metadata that describes
the file (commonly known as resident files).

**Reserved (80 bytes):** 80 bytes which, if included, as per the **ByteCount** field, are reserved, have an

undefined value, and are not interpreted.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned directly by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common
error codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The handle specified is not open.|
|STATUS_VOLUME_DISMOUNTED<br>0xC000026E|The specified volume is no longer mounted.|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a REFS_VOLUME_DATA_BUFFER<br>structure.|
