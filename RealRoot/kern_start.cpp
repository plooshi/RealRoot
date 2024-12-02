#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>

#include "kern_realroot.hpp"

static const char *bootargOff[] {
	"-rroff"
};

static const char *bootargDebug[] {
	"-rrdbg"
};

static const char *bootargBeta[] {
	"-rrbeta"
};

PluginConfiguration ADDPR(config) {
	xStringify(PRODUCT_NAME),
	parseModuleVersion(xStringify(MODULE_VERSION)),
	LiluAPI::AllowNormal | LiluAPI::AllowSafeMode,
	bootargOff,
	arrsize(bootargOff),
	bootargDebug,
	arrsize(bootargDebug),
	bootargBeta,
	arrsize(bootargBeta),
	KernelVersion::BigSur,
    KernelVersion::Sequoia,
    InitRealRoot
};
