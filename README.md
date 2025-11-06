# Crystal Kit

This repo is a technical and social experiment to see if replacing Cobalt Strike's evasion primitives (Sleepmask/BeaconGate) with Crystal Palace PIC is feasible (or even desirable) for advanced evasion scenarios.  Also see the accompanying [blog post](https://rastamouse.me/crystal-kit/).

## Usage

1. Disable the Sleepmask and stage obfuscations in Malleable C2.

```text
stage {
    set rdll_loader "PrependLoader";
    set sleep_mask  "false";
    set cleanup     "true";
    
    transform-obfuscate { }
}

post-ex {
    set cleanup "true";
}
```

2. Copy `crystalpalace.jar` to your Cobalt Strike client directory.
3. Load `crystalkit.cna`.  

### Notes

Tested on CS 4.11.1.