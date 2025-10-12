# Crystal Kit

This repo is a technical and social experiment to see if replacing Cobalt Strike's evasion primitives (Sleepmask/BeaconGate) with Crystal Palace PIC(O)s is feasible (or even desirable) for advanced evasion scenarios.  Also see the accompanying [blog post](https://rastamouse.me/crystal-kit/).

## Usage

1. Disable the Sleepmask and stage obfuscations in Malleable C2.

```text
stage {
    set rdll_loader "PrependLoader";
    set sleep_mask "false";
    set cleanup "true";
    transform-obfuscate { }
}

post-ex {
    set cleanup "true";
}
```

2. Copy `crystalpalace.jar` to your Cobalt Strike client directory.
3. Load `crystalkit.cna`.  

## TODO

There are lots of improvements that can be made to this codebase.  Some that come to mind include:

- [ ] Add BUD-style structures to track memory allocations.
- [ ] Don't use RWX memory for Beacon.
- [ ] Add GMA & GPA patching to the postex loader (`smartinject` is not yet supported in `stage` for prepended loaders).
- [ ] Add AMSI & ETW bypasses to the postex loader.
- [ ] Add memory freeing code on ExitThread.
