# @shieldbattery/stimpack

**@shieldbattery/stimpack:** Rust-based Node.js native module for launching processes and injecting DLLs into them

## Local development

To do local development and testing, you can utilize `npm link` to work off of your local copy:

```sh
cd path/to/stimpack
yarn link
cd path/to/shieldbattery/app
yarn link @shieldbattery/stimpack
```

To return to the published version:

```sh
cd path/to/stimpack
yarn unlink
cd path/to/shieldbattery/app
yarn unlink @shieldbattery/stimpack
yarn install --check-files
```
