<!-- Source: Apple File System Reference (Apple Inc., 2020-06-22). Converted from PDF with pymupdf4llm. -->

## About Apple File System

Apple File System is the default file format used on Apple platforms. Apple File System is the successor to HFS Plus, so some aspects of its design intentionally follow HFS Plus to enable data migration from HFS Plus to Apple File System. Other aspects of its design address limitations with HFS Plus and enable features like cloning files, snapshots, encryption, and sharing free space between volumes.

Most apps interact with the file system using high-level interfaces provided by Foundation, which means most developers donʼt need to read this document. This document is for developers of software that interacts with the file system directly, without using any frameworks or the operating system — for example, a disk recovery utility or an implementation of Apple File System on another platform. The on-disk data structures described in this document make up the file system; software that interacts with them defines corresponding in-memory data structures.

## **Note**

If you need to boot from an Apple File System volume, but donʼt need to mount the volume or interact with the file system directly, read Booting from an Apple File System Partition.

## **Layered Design**

The Apple File System is conceptually divided into two layers, the container layer and the file-system layer. The container layer organizes file-system layer information and stores higher level information, like volume metadata, snapshots of the volume, and encryption state. The file-system layer is made up of the data structures that store information, like directory structures, file metadata, and file content. Many types are prefixed with _`nx_`_ or _`j_`_ , which indicates that theyʼre part of the container layer or the file-system layer, respectively. The abbreviated prefixes donʼt have a meaningful long form; theyʼre an artifact of how Appleʼs implementation was developed.

There are several design differences between the layers. Container objects are larger, with a typical size measured in blocks, and contain padding fields that keep data aligned on 64-bit boundaries, to avoid the performance penalty of unaligned memory access. File-system objects are smaller, with a typical size measured in bytes, and are almost always packed to minimize space used.

Numbers in both layers are stored on disk in little-endian order. Objects in both layers begin with a common header that enables object-oriented design patterns in implementations of Apple File System, although the layers have different headers. Container layer objects begin with an instance of _`obj_phys_t`_ and file-system objects begin with an instance of _`j_key_t`_ ,

## **Container Layer**

Container objects have an object identifier that you use to locate the object; the steps vary depending on how the object is stored:

- _Physical objects_ are stored on disk at a particular physical block address.

- _Ephemeral objects_ are stored in memory while the container is mounted and in a checkpoint when the container isnʼt mounted.

- _Virtual objects_ are stored on disk at a location that you look up in an object map (an instance of _`omap_phys_t`_ ).

The object map includes a B-tree whose keys contain a transaction identifier and an object identifier and whose values contain a physical block address where the object is stored.


7

**About Apple File System**

An Apple File System partition has a single container, which provides space management and crash protection. A container can contain multiple volumes (also known as file systems), each of which contains a directory structure for files and folders. For example, the figure below shows a storage device that has one Apple File System partition, and it shows the major divisions of the space inside that container.

**==> picture [401 x 224] intentionally omitted <==**

Although thereʼs only one container, there are several copies of the container superblock (an instance of _`nx_super block_t`_ ) stored on disk. These copies hold the state of the container at past points in time. Block zero contains a copy of the container superblock thatʼs used as part of the mounting process to find the checkpoints. Block zero is typically a copy of the latest container superblock, assuming the device was properly unmounted and was last modified by a correct Apple File System implementation. However, in practice, you use the block zero copy only to find the checkpoints and use the latest version from the checkpoint for everything else.

Within a container, the checkpoint mechanism and the copy-on-write approach to modifying objects enable crash protection. In-memory state is periodically written to disk in checkpoints, followed by a copy of the container superblock at that point in time. Checkpoint information is stored in two regions: The checkpoint descriptor area contains instances of _`checkpoint_map_phys_t`_ and _`nx_superblock_t`_ , and the checkpoint data area contains ephemeral objects that represent the in-memory state at the point in time when the checkpoint was written to disk.

When mounting a device, you use the most recent checkpoint information thatʼs valid, as discussed in Mounting an Apple File System Partition. If the process of writing a checkpoint is interrupted, that checkpoint is invalid and therefore is ignored the next time the device is mounted, rolling the file system back to the last valid state. Because the checkpoint stores in-memory state, mounting an Apple File System partition includes reading the ephemeral objects from the checkpoint back into memory, re-creating that state in memory.

## **File-System Layer**

File-system objects are made up of several records, and each record is stored as a key and value in a B-tree (an instance of _`btree_node_phys_t`_ ). For example, a typical directory object is made up of an inode record, several directory entry records, and an extended attributes record. A record contains an object identifier thatʼs used to find it within the B-tree that contains it.


8
