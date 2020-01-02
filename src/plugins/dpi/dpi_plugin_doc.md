# DPI plugin for VPP    {#dpi_plugin_doc}

## Version

The DPI plugin is currently in *beta* version.
Both CLIs and APIs are subject to *heavy* changes.
Wich also means feedback is really welcome regarding features, apis, etc...

## Overview


## Performances


## Configuration

### Global DPI parameters


### Configure the VIPs


## Design notes


### Hash Table

A DPI requires an efficient read and write hash table. The hash table
used by ip6-forward is very read-efficient, but not so much for writing. In
addition, it is not a big deal if writing into the hash table fails (again,
MagLev uses a flow table but does not heaviliy relies on it).

The plugin therefore uses a very specific (and stupid) hash table.
	- Fixed (and power of 2) number of buckets (configured at runtime)
	- Fixed (and power of 2) elements per buckets (configured at compilation time)
