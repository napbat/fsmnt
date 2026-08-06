<!-- MS-FSCC Reference: Directory Change Notifications -->
<!-- FILE_NOTIFY_INFORMATION structure and change notification filter flags. Used for monitoring filesystem changes (file add/remove/modify/rename). -->

**2.7** **Directory Change Notifications**

The following definitions are part of the Directory Change Notification algorithm defined in [MS-FSA]
section 2.1.5.11.

**2.7.1** **FILE_NOTIFY_INFORMATION**

The **FILE_NOTIFY_INFORMATION** structure contains the changes for which the client is being
notified. The structure consists of the following.

```
  NextEntryOffset (32 bits)
  Action (32 bits)
  FileNameLength (32 bits)
  FileName (variable) (32 bits)
```

**NextEntryOffset (4 bytes):** The offset, in bytes, from the beginning of this structure to the

subsequent **FILE_NOTIFY_INFORMATION** structure. If there are no subsequent structures, the
**NextEntryOffset** field MUST be 0. **NextEntryOffset** MUST always be an integral multiple of 4.
The **FileName** array MUST be padded to the next 4-byte boundary counted from the beginning of
the structure.
**Action (4 bytes):** The changes that occurred on the file. This field MUST contain one of the following

values.<194>

|Value|Meaning|
|---|---|
|FILE_ACTION_ADDED<br>0x00000001|The file was renamed, and**FileName** contains the new name.<br>This notification is only sent when the rename operation<br>changes the directory the file resides in. The client will also<br>receive a FILE_ACTION_REMOVED notification. This notification<br>will not be received if the file is renamed within a directory.|
|FILE_ACTION_REMOVED<br>0x00000002|The file was renamed, and**FileName** contains the old name.<br>This notification is only sent when the rename operation<br>changes the directory the file resides in. The client will also<br>receive a FILE_ACTION_ADDED notification. This notification<br>will not be received if the file is renamed within a directory.|
|FILE_ACTION_MODIFIED<br>0x00000003|The file was modified. This can be a change to the data or<br>attributes of the file.|
|FILE_ACTION_RENAMED_OLD_NAME<br>0x00000004|The file was renamed, and**FileName** contains the old name.<br>This notification is only sent when the rename operation does<br>not change the directory the file resides in. The client will also<br>receive a FILE_ACTION_RENAMED_NEW_NAME notification.<br>This notification will not be received if the file is renamed to a<br>different directory.|
|FILE_ACTION_RENAMED_NEW_NAME<br>0x00000005|The file was renamed, and**FileName** contains the new name.<br>This notification is only sent when the rename operation does<br>not change the directory the file resides in. The client will also<br>receive a FILE_ACTION_RENAMED_OLD_NAME notification. This<br>notification will not be received if the file is renamed to a<br>different directory.|
|FILE_ACTION_ADDED_STREAM<br>0x00000006|The file was added to a named stream.|
|FILE_ACTION_REMOVED_STREAM<br>0x00000007|The file was removed from the named stream.|
|FILE_ACTION_MODIFIED_STREAM<br>0x00000008|The file was modified. This can be a change to the data or<br>attributes of the file.|
|FILE_ACTION_REMOVED_BY_DELETE<br>0x00000009|An object ID was removed because the file the object ID<br>referred to was deleted.<br> <br>This notification is only sent when the directory being<br>monitored is the special directory<br>"\$Extend\$ObjId:$O:$INDEX_ALLOCATION".|
|FILE_ACTION_ID_NOT_TUNNELLED<br>0x0000000A|An attempt to tunnel object ID information to a file being<br>created or renamed failed because the object ID is in use by<br>another file on the same volume.<br> <br>This notification is only sent when the directory being<br>monitored is the special directory<br>"\$Extend\$ObjId:$O:$INDEX_ALLOCATION".|
|FILE_ACTION_TUNNELLED_ID_COLLISION<br>0x0000000B|An attempt to tunnel object ID information to a file being<br>renamed failed because the file already has an object ID.<br>|
|Value|Meaning|
|---|---|
||This notification is only sent when the directory being<br>monitored is the special directory<br>"\$Extend\$ObjId:$O:$INDEX_ALLOCATION".|

If two or more files have been renamed, the corresponding **FILE_NOTIFY_INFORMATION** entries
for each file rename MUST be consecutive in this response for the client to make the correct
correspondence between old and new names.

**FileNameLength (4 bytes):** The length, in bytes, of the file name in the **FileName** field.

**FileName (variable):** A Unicode string with the name of the file that changed.
