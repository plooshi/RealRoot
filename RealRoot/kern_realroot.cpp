#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_version.hpp>
#include <Headers/kern_devinfo.hpp>

#include "kern_realroot.hpp"

static const char *kextAPFSPath[] { "/System/Library/Extensions/apfs.kext/Contents/MacOS/apfs" };

static KernelPatcher::KextInfo kextAPFS { "com.apple.filesystems.apfs", kextAPFSPath, 1, {true, true}, {}, KernelPatcher::KextInfo::Unloaded };

uint64_t selectSnapshotPatch(void *_Arg1, void *_Arg2, void **Arg3) {
	*Arg3 = nullptr;
	return 0;
}

uint32_t RetZero() {
	return 0;
}
uint32_t RetOne() {
	return 1;
}

void PatchAPFS(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
	KernelPatcher::RouteRequest req("_apfs_root_snapshot_select", selectSnapshotPatch);
	if (!patcher.routeMultiple(index, &req, 1))
		panic("Failed to route apfs_root_snapshot_select!");
	if (getKernelVersion() >= KernelVersion::Sonoma) {
		KernelPatcher::RouteRequest req("_apfs_mount_upgrade_checks", RetZero);
		if (!patcher.routeMultiple(index, &req, 1))
			panic("Failed to route apfs_mount_upgrade_checks!");
	} else {
		KernelPatcher::RouteRequest req("_apfs_allow_root_update", RetOne);
		if (!patcher.routeMultiple(index, &req, 1))
			panic("Failed to route apfs_allow_root_update!");
	}
	auto apfs_vfsop_mount = patcher.solveSymbol(index, "_apfs_vfsop_mount");
	size_t dataOffset = 0;
	if (!KernelPatcher::findPattern(apfsVfsopMountOrig, apfsVfsopMountMask, sizeof(apfsVfsopMountOrig), (void *) apfs_vfsop_mount, 32768, &dataOffset)) {
		panic("Failed to find apfs_vfsop_mount LiveFS patch!");
	}
	MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock);
	mach_vm_address_t patchPoint = apfs_vfsop_mount + dataOffset + 0x15;
	if (*(uint8_t *)(patchPoint + 1) == 0x85) { // jne
		// replace entire call w/ nop
		for (int i = 0; i < 6; i++) {
			*(uint8_t *)(patchPoint + i) = 0x90;
		}
	} else {
		// force jump
		*(uint8_t *)(patchPoint) = 0x90;
		*(uint8_t *)(patchPoint + 1) = 0xe9;
	}
	MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock);
}

void PatchKernel(KernelPatcher &patcher) {
	auto pivot_root = patcher.solveSymbol(0, "_pivot_root");
	if (!KernelPatcher::findAndReplaceWithMask((void *) pivot_root, 32768, pivotRootOrig, sizeof(pivotRootOrig), pivotRootMask, sizeof(pivotRootMask), pivotRootReplace, sizeof(pivotRootReplace), pivotRootReplaceMask, sizeof(pivotRootReplaceMask))) {
		panic("Failed to patch pivot_root!");
	}
}

void InitRealRoot() {
	lilu.onPatcherLoadForce([](void *user, KernelPatcher &patcher) {
		PatchKernel(patcher);
	});
	lilu.onKextLoadForce(&kextAPFS, 1,
	[](void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
		if (kextAPFS.loadIndex == index) PatchAPFS(patcher, index, address, size);
	});
}
