# OCI-tar

This is a tool to handle file system layers. One of the the format is 
[OCI filesystem layer](https://github.com/opencontainers/image-spec/blob/main/layer.md).

Filesystem layers are file that records actions (creation, modification, and deletion of files) to a file system.
Creation and modification of files are trivial to accomplish using `tar` but not deletion. To overcome this problem,
the OCI specification make use of special `whiteout` files are represent deletion of files from the parent layer.
In addition to the way OCI handle it, this tool is able to write a custom pax header that contains all paths to whiteout.
The extra header does not affect most tar implementation to list and extract the archive directly.


# Usage


### Creating a layer

```shell=
ocitar -cf mylayer.tar --remove folder/0 folder1 folder2 folder3
```

This creates a OCI compatible layer that archived `folder1` `folder2` `folder3` with whiteout file `folder/.wh.0` included.

Output to stdout is also supported

```shell=
ocitar -cf - --remove folder/0 folder1 folder2 folder3
```

### Stage a layer
Given an OCI compatible layer `mylayer.tar` created in previous session. The following command stage the layer to `myfolder`.

```shell=
ocitar -xf mylayer.tar -C myfolder
```

Reading the layer from stdin can be done by
```shell=
ocitar -xf- -C myfolder
```

### ZStandard compression

Creating and extracting ZStandard compressed layer can be done by adding `--zstd` to the argument list.


