# luci-app-ndpi build notes

This revision targets OpenWrt 25.12 with APK v3.

## Build

Copy this directory into the matching OpenWrt 25.12.5 buildroot or SDK package
tree, select `luci-app-ndpi`, and rebuild it. The package release is `r2`.

After building, verify the APK metadata:

```sh
apk adbdump ./luci-app-ndpi-1.0.0-r2.apk | sed -n '/^info:/,/^paths:/p'
```

The metadata must contain `arch: noarch`. It should also list `luci-base`,
`luci-compat`, `rpcd`, `jshn`, and `ndpi-tools` as dependencies.

## Install

```sh
sed -i '/^luci-app-ndpi/d' /etc/apk/world
apk add --allow-untrusted ./luci-app-ndpi-1.0.0-r2.apk
/etc/init.d/rpcd restart
/etc/init.d/ndpi enable
/etc/init.d/ndpi restart
```

The service command was updated for nDPI 6: JSON output uses `-K json -k`,
tunnel dissection uses `-t`, and global engine settings use `--cfg`.
