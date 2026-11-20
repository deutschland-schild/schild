package hostcheck

// dnfUpdatesScript is the fixed program CmdDnfUpdates runs (python3 -I -B -c,
// as nobody). It reads only: the rpm database (system repo), the metadata
// dnf already downloaded (/var/cache/dnf/<repo>-<hash>/repodata: repomd.xml,
// primary.xml.gz, updateinfo.xml.gz, modules.yaml.*) of the repos enabled in
// /etc/yum.repos.d, and the module state in /etc/dnf/modules.d. It never
// builds the solv cache (build_cache=False), logs to /dev/null and creates
// no cache dir. The result equals `dnf -C check-update` (latest per
// name.arch, module streams filtered like dnf does) plus the security flag
// of `dnf -C updateinfo list --security`.
//
// Output (stdout):
//
//	schild-dnf-updates 1
//	repos <n>                       enabled repos with a metadata cache
//	u <name> <arch> <evr> <0|1>     one pending update, 1 = security advisory
//
// Exit 0 ok, 2 hawkey/libdnf missing (dnf5 or yum hosts), 3 no metadata
// cache for any enabled repo, 4 module filtering not possible (results
// would be wrong on modular hosts), 1 anything else. Separators are tabs.
const dnfUpdatesScript = `import sys
try:
    import configparser, glob, gzip, lzma, os, warnings
    warnings.simplefilter("ignore")
    import hawkey, libdnf
except Exception:
    sys.exit(2)
CACHE = "/var/cache/dnf"
def enabled_repos():
    ids = set()
    for f in sorted(glob.glob("/etc/yum.repos.d/*.repo")):
        cp = configparser.RawConfigParser(strict=False)
        try:
            cp.read(f)
        except Exception:
            continue
        for s in cp.sections():
            if cp.get(s, "enabled", fallback="1").strip().lower() in ("1", "yes", "true", "on"):
                ids.add(s)
    return ids
def platform_id():
    try:
        for l in open("/etc/os-release"):
            if l.startswith("PLATFORM_ID="):
                return l.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass
    return ""
def yaml(p):
    if p.endswith(".xz"):
        return lzma.open(p).read().decode("utf-8")
    if p.endswith(".gz"):
        return gzip.open(p).read().decode("utf-8")
    return open(p, encoding="utf-8").read()
try:
    sack = hawkey.Sack(make_cache_dir=False, logfile="/dev/null")
    sack.load_system_repo(build_cache=False)
    mc = libdnf.module.ModulePackageContainer(False, "/", hawkey.detect_arch(), "/var/lib/dnf")
    ids = enabled_repos()
    loaded = 0
    for md in sorted(glob.glob(CACHE + "/*/repodata/repomd.xml")):
        d = os.path.dirname(md)
        rid = os.path.basename(os.path.dirname(d)).rsplit("-", 1)[0]
        if rid not in ids:
            continue
        r = hawkey.Repo(rid)
        r.repomd_fn = md
        for f in sorted(os.listdir(d)):
            p = os.path.join(d, f)
            if f.endswith("-primary.xml.gz") or f == "primary.xml.gz":
                r.primary_fn = p
            elif f.endswith("-updateinfo.xml.gz") or f == "updateinfo.xml.gz":
                r.updateinfo_fn = p
            elif "modules.yaml" in f:
                mc.add(yaml(p), rid)
        if not r.primary_fn:
            continue
        sack.load_repo(r, build_cache=False, load_filelists=False, load_presto=False, load_updateinfo=True)
        loaded += 1
    if loaded == 0:
        sys.exit(3)
except SystemExit:
    raise
except Exception:
    sys.exit(1)
try:
    mc.addDefaultsFromDisk()
    mc.moduleDefaultsResolve()
    done = False
    for args in ((mc, [], "/", platform_id(), False, False, False), (mc, [], "/", platform_id(), False, False), (mc, [], "/", platform_id())):
        try:
            sack.filter_modules(*args)
            done = True
            break
        except TypeError:
            continue
    if not done:
        sys.exit(4)
except SystemExit:
    raise
except Exception:
    sys.exit(4)
try:
    ups = hawkey.Query(sack).filter(upgrades=True, latest_per_arch=True)
    sec = set((p.name, p.arch) for p in hawkey.Query(sack).filter(upgrades=True, advisory_type="security"))
    out = ["schild-dnf-updates 1", "repos\t%d" % loaded]
    for p in sorted(ups, key=lambda p: (p.name, p.arch)):
        out.append("u\t%s\t%s\t%s\t%d" % (p.name, p.arch, p.evr, 1 if (p.name, p.arch) in sec else 0))
    sys.stdout.write("\n".join(out) + "\n")
except Exception:
    sys.exit(1)
`
