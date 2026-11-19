# modloader

`modloader` is a Linux command-line tool intended as an alternative to
`modprobe`. It is designed to work with KernelSU and supports probing for
non-exported kernel symbols.

> **Warning:** This tool operates on kernel modules and requires root
> privileges. Loading an incompatible or untrusted module can crash the
> device, compromise its security, or make it unbootable. Use only modules
> you trust and only on devices you own or are authorized to administer.
> Do not experiment on production systems.

## Usage

```text
modloader path/to/module.ko
```

The program also accepts `-` as the module path to read from standard input:

```text
some-command | modloader -
```

Run it with root privileges. The module must be compatible with the device's
kernel, architecture, and configuration. This project is not a general-purpose
replacement for every `modprobe` feature.

## Building

This is a Rust project. A standard release build can be started with:

```sh
cargo build --release
```

The repository's release workflow is the source of truth for supported
cross-compilation targets and release artifacts. Consult it when building for
Android or another non-host target.

## Operational notes

- Use only modules from a trusted source.
- Confirm the target device and kernel compatibility before running the tool.
- Prefer a recoverable test device with a known-good boot image.
- Review the source and build artifacts before running with root privileges.
- The tool interacts with kernel interfaces; behavior may vary across kernel
  versions and device configurations.

## Contributing

Bug reports and pull requests are welcome. For changes involving kernel
interaction, include the affected architecture and kernel environment, the
expected behavior, and the observed behavior. Avoid testing risky changes on
devices that cannot be recovered.
