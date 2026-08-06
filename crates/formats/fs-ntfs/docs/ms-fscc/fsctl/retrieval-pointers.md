<!-- MS-FSCC: Retrieval Pointers (Extent Mapping) -->
<!-- GET_RETRIEVAL_POINTER_COUNT, GET_RETRIEVAL_POINTERS, GET_RETRIEVAL_POINTERS_AND_REFCOUNT. EXTENTS, EXTENT_AND_REFCOUNTS. -->

**2.3.29** **FSCTL_GET_RETRIEVAL_POINTER_COUNT Request**

The FSCTL_GET_RETRIEVAL_POINTER_COUNT request message requests that the server return a
count of extents for the file or directory associated with the handle on which this **FSCTL** was invoked.
The extents describe the mapping between **virtual cluster numbers (VCNs)** and **logical cluster**
**numbers (LCNs)** . This request is most commonly used by defragmentation utilities. This message
contains a STARTING_VCN_INPUT_BUFFER data element.

The STARTING_VCN_INPUT_BUFFER data element is as follows.

```
  StartingVcn (32 bits)
  ...
```

**StartingVcn (8 bytes)** : A 64-bit signed integer that contains the virtual cluster number (VCN) at

which to begin retrieving extents in the file. This value MUST be greater than or equal to 0.

**2.3.30** **FSCTL_GET_RETRIEVAL_POINTER_COUNT Reply**

The FSCTL_GET_RETRIEVAL_POINTER_COUNT reply message returns the results of the
FSCTL_GET_RETRIEVAL_POINTER_COUNT request as a fixed size data element,
RETRIEVAL_POINTER_COUNT, that specifies the number of extents on disk of a specific file.

The FSCTL_GET_RETRIEVAL_POINTER_COUNT reply returns the number of extents of nonresident
data. A file system MAY allow resident data, which is data that can be written to disk within the file's
directory record. Because resident data requires no additional disk space allocation, no extent
locations are associated with resident data.<30>
The RETRIEVAL_POINTER_COUNT data element is as follows.

```
  ExtentCount (32 bits)
```

**ExtentCount (4 bytes)** : A 32-bit unsigned integer that contains the number of extents. This number

can be zero if there are no clusters allocated at (or beyond) the specified StartingVcn.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this FSCTL is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a RETRIEVAL_POINTER_COUNT<br>structure.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer is too small to contain a STARTING_VCN_INPUT_BUFFER, or<br>the**StartingVcn** given is negative, or the handle is not to a file or directory.|
|STATUS_END_OF_FILE<br>0xC0000011|The stream is resident in the MFT and has no clusters allocated, or the starting<br>VCN is beyond the end of the file.|

**2.3.31** **FSCTL_GET_RETRIEVAL_POINTERS Request**

The FSCTL_GET_RETRIEVAL_POINTERS request message requests that the server return a list of
extents for the file or directory associated with the handle on which this **FSCTL** was invoked. The
extents describe the mapping between **virtual cluster numbers (VCNs)** and **logical cluster**
**numbers (LCNs)** . This request is most commonly used by defragmentation utilities. This message
contains a STARTING_VCN_INPUT_BUFFER data element.

The STARTING_VCN_INPUT_BUFFER data element is as follows.

```
  StartingVcn (32 bits)
  ...
```

**StartingVcn (8 bytes):** A 64-bit signed integer that contains the virtual cluster number (VCN) at

which to begin retrieving extents in the file. This value MUST be greater than or equal to 0.

**2.3.32** **FSCTL_GET_RETRIEVAL_POINTERS Reply**

The FSCTL_GET_RETRIEVAL_POINTERS reply message returns the results of the
FSCTL_GET_RETRIEVAL_POINTERS request as a variably sized data element,
RETRIEVAL_POINTERS_BUFFER, that specifies the allocation and location on disk of a specific file.

The FSCTL_GET_RETRIEVAL_POINTERS reply returns the extent locations (that is, locations of
allocated regions of disk space) of nonresident data. A file system MAY allow resident data, which is
data that can be written to disk within the file's directory record. Because resident data requires no
additional disk space allocation, no extent locations are associated with resident data.<31>

The RETRIEVAL_POINTERS_BUFFER data element is as follows.

```
  ExtentCount (32 bits)
  Unused (32 bits)
  StartingVcn (32 bits)
  Extents (variable) (32 bits)
  ...
```

**ExtentCount (4 bytes):** A 32-bit unsigned integer that contains the number of EXTENTS data

elements in the **Extents** array. This number can be zero if there are no **clusters** allocated at (or
beyond) the specified **StartingVcn** .

**Unused (4 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**StartingVcn (8 bytes):** A 64-bit signed integer that contains the starting **virtual cluster number**

**(VCN)** returned by the FSCTL_GET_RETRIEVAL_POINTERS reply. This is not necessarily the VCN
requested by the FSCTL_GET_RETRIEVAL_POINTERS request, as the file system driver might
return the starting VCN of the extent containing the requested starting VCN. This value MUST be
greater than or equal to 0.

**Extents (variable):** An array of zero or more EXTENTS data elements. For the number of EXTENTS

data elements in the array, see **ExtentCount** .

**2.3.32.1** **EXTENTS**

The **EXTENTS** data element is as follows.

```
  NextVcn (32 bits)
  Lcn (32 bits)
  ...
```

**NextVcn (8 bytes):** A 64-bit signed integer that contains the **VCN** at which the next extent begins.

This value minus either **StartingVcn** (for the first **Extents** array element) or the **NextVcn** of the
previous element of the array (for all other **Extents** array elements) is the length in **clusters** of
the current extent.
**Lcn (8 bytes):** A 64-bit signed integer that contains the **logical cluster number (LCN)** at which the

current extent begins on the **volume** . A 64-bit value of -1 indicates either a **compression unit**
that is partially allocated or an unallocated region of a **sparse file** . For more information about
sparse files, see [[SPARSE]. Compression is performed in 16-cluster units. If a given 16-cluster unit](https://go.microsoft.com/fwlink/?LinkId=90527)
compresses to fit in, for example, 9 clusters, there will be a 7-cluster extent of the file with an LCN
of -1.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a RETRIEVAL_POINTERS_BUFFER<br>structure.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer is too small to contain a STARTING_VCN_INPUT_BUFFER, or<br>the**StartingVcn** given is negative, or the handle is not to a file or directory.|
|STATUS_END_OF_FILE<br>0xC0000011|The stream is resident in the**MFT** and has no clusters allocated, or the starting<br>VCN is beyond the end of the file.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer filled before all the extents for this file were returned.|

**2.3.33** **FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT Request**

The FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT request message requests that the server
return a list of extents and their reference counts for the file or directory associated with the handle
on which this **FSCTL** was invoked. The extents describe the mapping between **virtual cluster**
**numbers (VCNs)** and **logical cluster numbers (LCNs)** . The reference count describes how many
times these **logical cluster numbers (LCNs)** are being used within the **volume** . This request is
most commonly used by deduplication utilities. This message contains a
STARTING_VCN_INPUT_BUFFER data element.<32>

The **STARTING_VCN_INPUT_BUFFER** data element is as follows.

```
  StartingVcn (32 bits)
  ...
```

**StartingVcn (8 bytes):** A 64-bit signed integer that contains the virtual cluster number (VCN) at

which to begin retrieving extents in the file. This value MUST be greater than or equal to 0.

**2.3.34** **FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT Reply**

The FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT reply message returns the results of the
FSCTL_GET_RETRIEVAL_POINTERS AND_REFCOUNT request as a variably-sized data element,
RETRIEVAL_POINTERS_AND_REFCOUNT_BUFFER, that specifies the allocation and location on disk of
a specific file.
The FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT reply returns the extent locations (that is,
locations of allocated regions of disk space) and their reference counts of nonresident data. A file
system MAY allow resident data, which is data that can be written to disk within the file's directory
record. Because resident data requires no additional disk space allocation, no extent locations or
reference counts are associated with resident data.<33>

The RETRIEVAL_POINTERS_AND_REFCOUNT_BUFFER data element is as follows.

```
  ExtentCount (32 bits)
  Unused (32 bits)
  StartingVcn (32 bits)
  Extents (variable) (32 bits)
  ...
```

**ExtentCount (4 bytes)** : A 32-bit unsigned integer that contains the number of

EXTENT_AND_REFCOUNTS data elements in the Extents array. This number can be zero if there
are no clusters allocated at (or beyond) the specified **StartingVcn** .

**Unused (4 bytes):** Reserved for alignment. This field can contain any value and MUST be ignored.

**StartingVcn (8 bytes):** A 64-bit signed integer that contains the starting **virtual cluster number**

**(VCN)** returned by the FSCTL_GET_RETRIEVAL_POINTER_AND_REFCOUNT reply. This is not
necessarily the VCN requested by the FSCTL_GET_RETRIEVAL_POINTERS request, as the file
system driver might return the starting VCN of the extent containing the requested starting VCN.
This value MUST be greater than or equal to 0.

**Extents (variable):** An array of zero or more EXTENT_AND_REFCOUNTS data elements. For the

number of EXTENT_AND_REFCOUNTS data elements in the array, see **ExtentCount** .

**2.3.34.1** **EXTENT_AND_REFCOUNTS**

The EXTENT_AND_REFCOUNTS data element is as follows.

```
  NextVcn (32 bits)
  Lcn (32 bits)
  ReferenceCount (32 bits)
  ...
```
**NextVcn (8 bytes):** A 64-bit signed integer that contains the **VCN** at which the next extent begins.

This value minus either **StartingVcn** (for the first **Extents** array element) or the **NextVcn** of the
previous element of the array (for all other Extents array elements) is the length in **clusters** of
the current extent.

**Lcn (8 bytes):** A 64-bit signed integer that contains the **logical cluster number (LCN)** at which the

current extent begins on the **volume** . A 64-bit value of -1 indicates either a **compression unit**
that is partially allocated or an unallocated region of a **sparse file** . For more information about
sparse files, see [[SPARSE]. Compression is performed in 16-cluster units. If a given 16-cluster unit](https://go.microsoft.com/fwlink/?LinkId=90527)
compresses to fit in, for example, 9 clusters, there will be a 7-cluster extent of the file with an LCN
of -1.

**ReferenceCount (4 bytes):** A 32-bit unsigned integer that contains the reference count on the

**logical cluster number (LCN)** at which the current extent begins on the **volume** . If no one else
is using the corresponding LCN, the reference count will be 1.

This message also returns a status code as specified in section 2.2. Upon success, the status code
returned by the function that processes this **FSCTL** is STATUS_SUCCESS. The most common error
codes are listed in the following table.

|Error code|Meaning|
|---|---|
|STATUS_BUFFER_TOO_SMALL<br>0xC0000023|The output buffer is too small to contain a RETRIEVAL_POINTERS_BUFFER<br>structure.|
|STATUS_INVALID_PARAMETER<br>0xC000000D|The input buffer is too small to contain a STARTING_VCN_INPUT_BUFFER, or<br>the**StartingVcn** given is negative, or the handle is not to a file or directory.|
|STATUS_END_OF_FILE<br>0xC0000011|The stream is resident in the MFT and has no clusters allocated, or the starting<br>VCN is beyond the end of the file.|
|STATUS_BUFFER_OVERFLOW<br>0x80000005|The output buffer filled before all the extents for this file were returned.|
