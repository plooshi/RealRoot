# RealRoot
### Kext using Lilu to allow using the underlying FS of the root snapshot in macOS Big Sur and up.
#### SIP flag 0x2 is needed to access all files on Big Sur & Monterey as the sandbox patch hasn't been added yet for these versions.
> SIP flag 0x800 replacement (allows easy snapshot reverting by removing the kext, and fixes FileVault), x64 only (for arm64, use the plooshfinder-based static patcher)
