# ACL Allowlist Test

Six Docker nodes use per-node ACL files mounted at the hardcoded runtime paths:

- `node-a` and `node-b` carry the insider allowlist (`a`, `b`, `e`, `f`)
- `node-c` and `node-d` each carry a self-only allowlist containing their own npub
- `node-e` and `node-f` do not mount any ACL files locally

This lets us test three different node behaviors at once:

- insiders (`a`, `b`) explicitly allow `a`, `b`, `e`, and `f`
- outsiders (`c`, `d`) only allow themselves, so they reject outbound connects to `a`
- allowed remotes (`e`, `f`) rely on the insider ACLs and do not need local ACL files

## Test Identities

Allowed:

- `node-a`
  - `npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m`
  - `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20`
- `node-b`
  - `npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le`
  - `b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0`

Denied:

- `node-c`
  - `npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6`
  - `c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0`
- `node-d`
  - `npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl`
  - `d102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd0`

Additional allowed:

- `node-e`
  - `npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6`
  - `nsec1egyrmekfw3u4l88v8zhrak9uht503s2kvn9v49tqgp6c5l2yuxgsv386l0`
- `node-f`
  - `npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c`
  - `nsec1afh3nysthqh47awpdewcw59wvvp499f8dvlyclmnv4gvpxdk56dsa6eqsn`

The generated `fips.key` fixtures use a mix of bare hex and `nsec1...` values.
FIPS accepts either format in key files.

## Run

Build the Linux binaries and test image:

```bash
./testing/scripts/build.sh --no-docker
```

Start the ACL test mesh:

```bash
./testing/acl-allowlist/generate-configs.sh
docker compose -f testing/acl-allowlist/docker-compose.yml up -d --build
```

Or run the full integration check:

```bash
./testing/acl-allowlist/test.sh
```

`test.sh` regenerates the ACL fixtures automatically before starting Docker.

The ACL harness pins the expected test entrypoint explicitly so it does not
accidentally reuse an older `fips-test:latest` image with a different startup
script.

ACL paths are fixed in this branch:

- `/etc/fips/peers.allow`
- `/etc/fips/peers.deny`

Mounted ACL files in this harness:

- `node-a` and `node-b`: insider allowlist
- `node-c` and `node-d`: self-only allowlist
- `node-e` and `node-f`: no ACL files mounted

Generated fixture location:

- `testing/acl-allowlist/generated-configs/`

Inspect peer state:

```bash
docker exec fips-acl-a fipsctl show peers
docker exec fips-acl-b fipsctl show peers
docker exec fips-acl-c fipsctl show peers
docker exec fips-acl-d fipsctl show peers
docker exec fips-acl-e fipsctl show peers
docker exec fips-acl-f fipsctl show peers
```

Expected:

- `node-a` sees `node-b`, `node-e`, and `node-f`
- `node-b` sees `node-a`
- `node-c` sees no peers
- `node-d` sees no peers
- `node-e` sees `node-a`
- `node-f` sees `node-a`

Visible rejection logs:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml logs -f node-a node-b node-c node-d node-e node-f
```

You should see warnings like:

```text
Rejected peer by ACL ... context=outbound_connect decision=not in allowlist
```

Stop and clean up:

```bash
docker compose -f testing/acl-allowlist/docker-compose.yml down
```
