#include <Headers/kern_api.hpp>
#include <Headers/kern_user.hpp>
#include <Headers/kern_util.hpp>
#include <Headers/kern_version.hpp>
#include <Headers/kern_devinfo.hpp>

#include "kern_realroot.hpp"

struct segment_command_64 *get_segment(mach_header_64 *header, const char *name) {
	auto lcmd = (struct load_command *) (header + 1);

	for (int i = 0; i < header->ncmds; i++) {
		if (lcmd->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segment = (struct segment_command_64 *) lcmd;
			if (strcmp(segment->segname, name) == 0) {
				return segment;
			}
		} else {
			break;
		}

		lcmd = (struct load_command *) ((char *) lcmd + lcmd->cmdsize);
	}

	return NULL;
}

struct section_64 *get_section(struct segment_command_64 *segment, const char *name) {
	auto section = (struct section_64 *) (segment + 1);

	for (int i = 0; i < segment->nsects; i++) {
		if (strcmp(section->sectname, name) == 0) {
			return section;
		}

		section++;
	}

	return NULL;
}

static const char *kextAPFSPath[] { "/System/Library/Extensions/apfs.kext/Contents/MacOS/apfs" };

static KernelPatcher::KextInfo kextAPFS { "com.apple.filesystems.apfs", kextAPFSPath, 1, {true, true}, {}, KernelPatcher::KextInfo::Unloaded };


static const char *kextSandboxPath[] { "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox" };

static KernelPatcher::KextInfo kextSandbox { "com.apple.security.sandbox", kextSandboxPath, 1, {true, true}, {}, KernelPatcher::KextInfo::Unloaded };

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

void PatchAPFS(void *_user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
	if (kextAPFS.loadIndex == index) {
		auto apfs_vfsop_mount = patcher.solveSymbol(index, "_apfs_vfsop_mount");
		if (getKernelVersion() >= KernelVersion::Ventura) {
			KernelPatcher::RouteRequest req("_apfs_root_snapshot_select", selectSnapshotPatch);
			if (!patcher.routeMultiple(index, &req, 1))
				panic("Failed to route apfs_root_snapshot_select!");
		} else if (getKernelVersion() == KernelVersion::Monterey) {
			if (!KernelPatcher::findAndReplaceWithMask((void *) apfs_vfsop_mount, 32768, SnapshotOrig, arrsize(SnapshotOrig), SnapshotMask, arrsize(SnapshotMask), SnapshotReplace, arrsize(SnapshotReplace), SnapshotReplaceMask, arrsize(SnapshotReplaceMask))) {
				panic("Failed to patch apfs_root_snapshot_select!");
			}
		} else {
			if (!KernelPatcher::findAndReplaceWithMask((void *) apfs_vfsop_mount, 32768, SnapshotOrigBigSur, arrsize(SnapshotOrigBigSur), SnapshotMaskBigSur, arrsize(SnapshotMaskBigSur), SnapshotReplaceBigSur, arrsize(SnapshotReplaceBigSur), SnapshotReplaceMaskBigSur, arrsize(SnapshotReplaceMaskBigSur))) {
				panic("Failed to patch apfs_root_snapshot_select!");
			}
		}
		if (getKernelVersion() >= KernelVersion::Sonoma) {
			KernelPatcher::RouteRequest req("_apfs_mount_upgrade_checks", RetZero);
			if (!patcher.routeMultiple(index, &req, 1))
				panic("Failed to route apfs_mount_upgrade_checks!");
		} else if (getKernelVersion() == KernelVersion::Ventura){
			KernelPatcher::RouteRequest req("_apfs_allow_root_update", RetOne);
			if (!patcher.routeMultiple(index, &req, 1))
				panic("Failed to route apfs_allow_root_update!");
		} else {
			if (!KernelPatcher::findAndReplaceWithMask((void *) apfs_vfsop_mount, 32768, oldRWPatchOrig, arrsize(oldRWPatchOrig), oldRWPatchMask, arrsize(oldRWPatchMask), oldRWPatchReplace, arrsize(oldRWPatchReplace), oldRWPatchReplaceMask, arrsize(oldRWPatchReplaceMask))) {
				panic("Failed to patch apfs_vfsop_mount RW patch!");
			}
		}
		size_t dataOffset = 0;
		if (getKernelVersion() >= KernelVersion::Ventura) {
			if (!KernelPatcher::findPattern(apfsVfsopMountOrig, apfsVfsopMountMask, arrsize(apfsVfsopMountOrig), (void *) apfs_vfsop_mount, 32768, &dataOffset)) {
				panic("Failed to find apfs_vfsop_mount LiveFS patch!");
			}
		} else if (getKernelVersion() == KernelVersion::Monterey) {
			if (!KernelPatcher::findPattern(apfsVfsopMountOrigMonterey, apfsVfsopMountMaskMonterey, arrsize(apfsVfsopMountOrigMonterey), (void *) apfs_vfsop_mount, 32768, &dataOffset)) {
				panic("Failed to find apfs_vfsop_mount LiveFS patch!");
			}
		} else {
			if (!KernelPatcher::findPattern(apfsVfsopMountOrigBigSur, apfsVfsopMountMaskBigSur, arrsize(apfsVfsopMountOrigBigSur), (void *) apfs_vfsop_mount, 32768, &dataOffset)) {
				panic("Failed to find apfs_vfsop_mount LiveFS patch!");
			}
		}
		MachInfo::setKernelWriting(true, KernelPatcher::kernelWriteLock);
		size_t offset = 0;
		switch (getKernelVersion()) {
			case BigSur:
				for (int i = 0; i < 0x30; i++) {
					if (*(uint8_t *)(apfs_vfsop_mount + dataOffset + i) == 0x0f && (*(uint8_t *)(apfs_vfsop_mount + dataOffset + i + 1) & 0xfe) == 0x84) {
						offset = i;
						break;
					}
				}
				if (!offset) panic("Failed to find j(n)e for LiveFS patch!");
				break;
			case Monterey:
				offset = 0x12;
				break;
			default:
				offset = 0x15;
				break;
		}
		mach_vm_address_t patchPoint = apfs_vfsop_mount + dataOffset + offset;
		if (*(uint8_t *)(patchPoint + 1) == 0x85) { // jne
			// replace entire call w/ nop
			for (int i = 0; i < 6; i++) {
				*(uint8_t *)(patchPoint + i) = 0x90;
			}
		} else if (*(uint8_t *)(patchPoint + 1) == 0x84) {
			// force jump
			*(uint8_t *)(patchPoint) = 0x90;
			*(uint8_t *)(patchPoint + 1) = 0xe9;
		} else {
			panic("LiveFS patch has a bad offset!!");
		}
		MachInfo::setKernelWriting(false, KernelPatcher::kernelWriteLock);
	}
}

void PatchSandbox(void *_user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
	if (kextSandbox.loadIndex == index) {
		auto apply_rootless_modifier = patcher.solveSymbol(index, "_apply_rootless_modifier");
		auto sb_evaluate_internal = patcher.solveSymbol(index, "_sb_evaluate_internal");
		size_t dataOffset = 0;
		if (!KernelPatcher::findPattern(RootlessOrig, RootlessMask, arrsize(RootlessOrig), (void *) (getKernelVersion() >= KernelVersion::Ventura ? apply_rootless_modifier : sb_evaluate_internal), 32768, &dataOffset)) {
			panic("Failed to find apfs_vfsop_mount LiveFS patch!");
		}
		mach_vm_address_t patchPoint = (getKernelVersion() >= KernelVersion::Ventura ? apply_rootless_modifier : sb_evaluate_internal) + dataOffset + 0xc;
		if (*(uint8_t *)patchPoint == 0x75) { // jne
			// replace entire call w/ nop
			for (int i = 0; i < 2; i++) {
				*(uint8_t *)(patchPoint + i) = 0x90;
			}
		} else if (*(uint8_t *)(patchPoint + 1) == 0x84) {
			// force jump
			*(uint8_t *) patchPoint = 0xeb;
		} else {
			panic("Sandbox patch has a bad offset!!");
		}
	}
}

mach_vm_address_t getKernelBase() {
#ifdef LILU_COMPRESSION_SUPPORT
	static constexpr const char *prelinkKernelPaths[7] {
		// This is the usual kernel cache place, which often the best thing to use
		"/System/Library/Caches/com.apple.kext.caches/Startup/kernelcache",
		// Otherwise fallback to one of the prelinked kernels
		// Since we always verify the LC_UUID value, trying the kernels could be done in any order.
		"/System/Library/PrelinkedKernels/prelinkedkernel", // normal
		"/macOS Install Data/Locked Files/Boot Files/prelinkedkernel", // 10.13 installer
		"/com.apple.boot.R/prelinkedkernel", // 10.12+ fusion drive installer
		"/com.apple.boot.S/System/Library/PrelinkedKernels/prelinkedkernel", // 10.11 fusion drive installer
		"/com.apple.recovery.boot/prelinkedkernel", // recovery
		"/kernelcache" // 10.7 installer
	};
#endif

	static constexpr const char *kernelPaths[2] {
		"/System/Library/Kernels/kernel",
		"/mach_kernel"
	};
	static mach_vm_address_t kbase = 0;
	if (!kbase) {
		bool usePrelinkedCache = LILU_COMPRESSION_SUPPORT && WIOKit::usingPrelinkedCache();
		
		auto info = MachInfo::create(true, "kernel");
		if (!info) {
			return 0;
		} else if ((info->init(usePrelinkedCache ? prelinkKernelPaths : kernelPaths, usePrelinkedCache ? arrsize(prelinkKernelPaths) : arrsize(kernelPaths), 0, false)) != KERN_SUCCESS) {
			return 0;
		}
		
		kbase = info->findKernelBase();
		info->deinit();
		MachInfo::deleter(info);
	}
	return kbase;
}

void PatchKernel(void *_user, KernelPatcher &patcher) {
	auto searchBase = patcher.solveSymbol(0, "_pivot_root");
	size_t searchSize = 32768;
	if (!searchBase) {
		// our pattern is so unique that we can afford to do this
		auto kInfo = (mach_header_64 *) getKernelBase();
		auto kTextExec = get_segment(kInfo, "__TEXT_EXEC");
		if (!kTextExec) panic("Failed to get kernel text segment!");
		auto kText = get_section(kTextExec, "__text");
		if (!kText) panic("Failed to get kernel text section!");
		searchBase = (mach_vm_address_t) kInfo + kText->addr;
		searchSize = kText->size;
	}
	if (!KernelPatcher::findAndReplaceWithMask((void *) searchBase, searchSize, pivotRootOrig, arrsize(pivotRootOrig), pivotRootMask, arrsize(pivotRootMask), pivotRootReplace, arrsize(pivotRootReplace), pivotRootReplaceMask, arrsize(pivotRootReplaceMask))) {
		panic("Failed to patch RootVP!");
	}
}

void InitRealRoot() {
	lilu.onPatcherLoadForce(PatchKernel);
	lilu.onKextLoadForce(&kextAPFS, 1, PatchAPFS);
	if (getKernelVersion() >= KernelVersion::Ventura) lilu.onKextLoadForce(&kextSandbox, 1, PatchSandbox);
}
