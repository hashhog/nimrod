## CPU Feature Detection
## Runtime detection of hardware crypto acceleration capabilities
##
## Detects:
## - x86: SHA-NI, SSE4.1, AVX2, SSSE3
## - AArch64: SHA2 extensions

import std/strutils

type
  CpuFeature* = enum
    ## Detected CPU features for crypto acceleration
    cfSSE3        ## SSE3 instructions
    cfSSSE3       ## Supplemental SSE3
    cfSSE41       ## SSE4.1 instructions
    cfSSE42       ## SSE4.2 instructions
    cfAVX         ## AVX instructions (with OS support)
    cfAVX2        ## AVX2 instructions (with OS support)
    cfSHANI       ## SHA-NI (x86) or SHA2 (ARM) extensions
    cfNEON        ## ARM NEON

when defined(amd64) or defined(i386):
  # x86/x64 CPUID feature bits
  const
    CPUID_LEAF_BASIC = 1'u32
    CPUID_LEAF_EXTENDED = 7'u32

    # EAX=1, ECX flags
    SSE3_BIT = 0
    SSSE3_BIT = 9
    SSE41_BIT = 19
    SSE42_BIT = 20
    XSAVE_BIT = 27
    AVX_BIT = 28

    # EAX=7, EBX flags
    AVX2_BIT = 5
    SHA_NI_BIT = 29

  # Use C-level cpuid function
  {.emit: """
  #include <cpuid.h>

  static void nimrod_cpuid(unsigned int leaf, unsigned int subleaf,
                           unsigned int* eax, unsigned int* ebx,
                           unsigned int* ecx, unsigned int* edx) {
    __cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
  }

  static unsigned long long nimrod_xgetbv(unsigned int index) {
    unsigned int lo, hi;
    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(index));
    return ((unsigned long long)hi << 32) | lo;
  }
  """.}

  proc nimrod_cpuid(leaf, subleaf: cuint, eax, ebx, ecx, edx: ptr cuint)
    {.importc, nodecl.}

  proc nimrod_xgetbv(index: cuint): culonglong
    {.importc, nodecl.}

  var
    cachedFeatures: set[CpuFeature]
    featuresDetected = false

proc detectCpuFeatures*(): set[CpuFeature] =
  ## Detect available CPU features at runtime
  ## Results are cached after first call

  when defined(amd64) or defined(i386):
    if featuresDetected:
      return cachedFeatures

    var features: set[CpuFeature] = {}
    var eax, ebx, ecx, edx: cuint

    # Get basic features (leaf 1)
    nimrod_cpuid(CPUID_LEAF_BASIC, 0, addr eax, addr ebx, addr ecx, addr edx)

    if ((ecx shr SSE3_BIT) and 1) == 1:
      features.incl(cfSSE3)
    if ((ecx shr SSSE3_BIT) and 1) == 1:
      features.incl(cfSSSE3)
    if ((ecx shr SSE41_BIT) and 1) == 1:
      features.incl(cfSSE41)
    if ((ecx shr SSE42_BIT) and 1) == 1:
      features.incl(cfSSE42)

    # Check for AVX support (requires XSAVE and OS support)
    let hasXSAVE = ((ecx shr XSAVE_BIT) and 1) == 1
    let hasAVX = ((ecx shr AVX_BIT) and 1) == 1

    if hasXSAVE and hasAVX:
      # Check OS has enabled AVX state saving
      let xcr0 = nimrod_xgetbv(0)
      let avxOsSupport = (xcr0 and 0x6) == 0x6  # XMM and YMM state enabled

      if avxOsSupport:
        features.incl(cfAVX)

        # Get extended features (leaf 7)
        nimrod_cpuid(CPUID_LEAF_EXTENDED, 0, addr eax, addr ebx, addr ecx, addr edx)

        if ((ebx shr AVX2_BIT) and 1) == 1:
          features.incl(cfAVX2)
        if ((ebx shr SHA_NI_BIT) and 1) == 1:
          features.incl(cfSHANI)
    elif cfSSE41 in features:
      # Still check for SHA-NI even without AVX
      nimrod_cpuid(CPUID_LEAF_EXTENDED, 0, addr eax, addr ebx, addr ecx, addr edx)
      if ((ebx shr SHA_NI_BIT) and 1) == 1:
        features.incl(cfSHANI)

    cachedFeatures = features
    featuresDetected = true
    result = features

  elif defined(arm64) or defined(aarch64):
    # AArch64 feature detection via Linux auxiliary vector
    var features: set[CpuFeature] = {}
    features.incl(cfNEON)  # NEON is always available on AArch64

    when defined(linux):
      # Read /proc/cpuinfo or use getauxval
      const
        AT_HWCAP = 16
        HWCAP_SHA2 = 1 shl 6

      proc getauxval(typ: culong): culong
        {.importc, header: "<sys/auxv.h>".}

      let hwcap = getauxval(AT_HWCAP)
      if (hwcap and HWCAP_SHA2) != 0:
        features.incl(cfSHANI)

    elif defined(macosx):
      # macOS ARM feature detection via sysctl
      proc sysctlbyname(name: cstring, oldp: pointer, oldlenp: ptr csize_t,
                        newp: pointer, newlen: csize_t): cint
        {.importc, header: "<sys/sysctl.h>".}

      var val: cint = 0
      var size: csize_t = sizeof(cint)
      if sysctlbyname("hw.optional.arm.FEAT_SHA256", addr val, addr size, nil, 0) == 0:
        if val != 0:
          features.incl(cfSHANI)

    result = features

  else:
    # Fallback for other platforms
    result = {}

proc hasFeature*(feature: CpuFeature): bool =
  ## Check if a specific CPU feature is available
  feature in detectCpuFeatures()

proc hasSHA256Acceleration*(): bool =
  ## Check if hardware SHA-256 acceleration is available
  cfSHANI in detectCpuFeatures()

proc hasAVX2*(): bool =
  ## Check if AVX2 is available (for 8-way parallel SHA-256)
  cfAVX2 in detectCpuFeatures()

proc hasSSE41*(): bool =
  ## Check if SSE4.1 is available (for 4-way parallel SHA-256)
  cfSSE41 in detectCpuFeatures()

proc cpuFeaturesString*(): string =
  ## Get a string description of detected CPU features
  let features = detectCpuFeatures()

  if features.len == 0:
    return "standard (no hardware acceleration)"

  var parts: seq[string]
  if cfSHANI in features:
    when defined(amd64) or defined(i386):
      parts.add("SHA-NI")
    else:
      parts.add("SHA2")
  if cfAVX2 in features:
    parts.add("AVX2")
  if cfAVX in features:
    parts.add("AVX")
  if cfSSE42 in features:
    parts.add("SSE4.2")
  if cfSSE41 in features:
    parts.add("SSE4.1")
  if cfSSSE3 in features:
    parts.add("SSSE3")
  if cfSSE3 in features:
    parts.add("SSE3")
  if cfNEON in features:
    parts.add("NEON")

  result = parts.join(", ")
