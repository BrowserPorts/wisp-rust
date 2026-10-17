/**
 * Builds the addon and places everything it needs in order to load beside it.
 *
 * The addon records its msquic dependency as `@rpath/libmsquic.2.dylib` and `build.rs` gives it an
 * `@loader_path` rpath, so dyld looks for that dylib in the directory the addon is loaded from.
 * Putting it there is therefore part of producing a working addon, not a packaging afterthought, and
 * it cannot live in `build.rs`: cargo runs a build script before the regular dependencies are built,
 * so msquic's cmake output does not exist yet at that point.
 *
 * Build and bundle are one command because the bundle is only correct for the build unit that was
 * just built. The profile, target triple, target directory and features all select a different
 * msquic output, so this wrapper resolves them once, hands the same values to `napi build` and to
 * cargo, and asks cargo which msquic output that unit actually used. Nothing here searches for the
 * newest library on disk, and every ambiguity fails the build instead of guessing.
 *
 * Every subprocess is spawned without a shell: the pinned napi cli runs as a script argument to this
 * process's own node binary, and cargo is whatever `CARGO` names, the way cargo's own tools resolve
 * it.
 *
 * `--release` selects the workspace's `release-napi` profile rather than `release`: the addon runs
 * inside the Bun front, and `release` aborts the whole process on any panic, where `release-napi`
 * unwinds. Every cargo call runs with `--locked`, so the build uses exactly the reviewed Cargo.lock
 * and fails instead of resolving anything new.
 *
 * Usage: node build-native.mjs [--release | --profile <name>] [--target <triple>]
 *                             [--target-dir <dir>] [--output-dir <dir>]
 *                             [--features <list>] [--no-default-features]
 */
import { execFileSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
} from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DYLIB = "libmsquic.2.dylib";
const INSTALL_NAME = `@rpath/${DYLIB}`;
/** msquic redistributes a statically linked quictls, so its notices travel with the dylib. */
const NOTICES = [
	["LICENSE", "LICENSE-msquic"],
	["THIRD-PARTY-NOTICES", "THIRD-PARTY-NOTICES-msquic"],
];

const crateDir = dirname(fileURLToPath(import.meta.url));
const manifestPath = join(crateDir, "Cargo.toml");
const localRequire = createRequire(import.meta.url);
/** cargo exports CARGO for the tools it spawns and napi honors it, so every call here agrees. */
const cargo = env("CARGO") || "cargo";
/** The profile `--release` stands for; see the header. */
const RELEASE_PROFILE = "release-napi";

function fail(message) {
	console.error(`[build-native] ${message}`);
	process.exit(1);
}

function capture(command, args) {
	return execFileSync(command, args, {
		cwd: crateDir,
		encoding: "utf8",
		shell: false,
		stdio: ["inherit", "pipe", "inherit"],
		maxBuffer: 512 * 1024 * 1024,
	});
}

function passthrough(command, args) {
	execFileSync(command, args, { cwd: crateDir, shell: false, stdio: "inherit" });
}

/**
 * `node_modules/.bin/napi` is a POSIX shell script, so executing it without a shell fails on
 * Windows. Resolving the pinned package and running its own cli entry with this process's node
 * binary works everywhere, and it can only ever run the locally installed cli, never an npx
 * auto-install of some other version.
 */
function napiCli() {
	let packagePath;
	try {
		packagePath = localRequire.resolve("@napi-rs/cli/package.json");
	} catch {
		fail("@napi-rs/cli is not installed for this crate, install its devDependencies first");
	}
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(packagePath, "utf8"));
	} catch (error) {
		fail(`could not read ${packagePath}: ${error.message}`);
	}
	const entry = typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.napi;
	if (!entry) fail(`${packagePath} declares no napi bin, so there is no cli entry to run`);
	const cli = resolve(dirname(packagePath), entry);
	if (!statSync(cli, { throwIfNoEntry: false })?.isFile()) {
		fail(`${packagePath} points its napi bin at ${cli}, which is not a file`);
	}
	return cli;
}

/**
 * Only the flags that change which msquic output belongs to the build are accepted, and each one is
 * forwarded verbatim to both `napi build` and cargo. Anything else is refused rather than quietly
 * dropped, because a flag this wrapper does not understand is a flag the bundle cannot account for.
 */
function parseArgs(argv) {
	const options = {
		release: false,
		profile: null,
		target: null,
		targetDir: null,
		outputDir: null,
		features: null,
		noDefaultFeatures: false,
	};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		const value = () => {
			const next = argv[index + 1];
			if (next === undefined || next.startsWith("-")) fail(`${flag} needs a value`);
			index += 1;
			return next;
		};
		switch (flag) {
			case "--release":
			case "-r":
				options.release = true;
				break;
			case "--profile":
				options.profile = value();
				break;
			case "--target":
			case "-t":
				options.target = value();
				break;
			case "--target-dir":
				options.targetDir = value();
				break;
			case "--output-dir":
			case "-o":
				options.outputDir = value();
				break;
			case "--features":
			case "-F":
				options.features = value();
				break;
			case "--no-default-features":
				options.noDefaultFeatures = true;
				break;
			default:
				fail(
					`unsupported flag ${flag}\n` +
						"this wrapper forwards only the flags that decide which build unit the bundled library " +
						"must come from: --release, --profile, --target, --target-dir, --output-dir, --features, " +
						"--no-default-features",
				);
		}
	}
	if (options.release && options.profile) fail("--release and --profile select different profiles, pass one");
	return options;
}

function env(name) {
	return (process.env[name] ?? "").trim();
}

/** cargo's own precedence, resolved here so the same triple reaches napi, cargo and the layout. */
function resolveTriple(options) {
	if (options.target) return options.target;
	const configured = env("CARGO_BUILD_TARGET");
	if (configured) return configured;
	const line = capture("rustc", ["-vV"])
		.split("\n")
		.find((candidate) => candidate.startsWith("host: "));
	if (!line) fail("rustc -vV did not report a host triple, so the target triple is unknown");
	return line.slice("host: ".length).trim();
}

function resolveTargetDir(options, metadata) {
	const chosen =
		options.targetDir || env("CARGO_TARGET_DIR") || env("CARGO_BUILD_TARGET_DIR") || metadata.target_directory;
	if (!chosen) fail("cargo metadata reported no target_directory and none was given");
	return resolve(crateDir, chosen);
}

/** The addon's `@rpath` dependencies, which are the ones a co-located file has to satisfy. */
function rpathDeps(file) {
	return capture("otool", ["-L", file])
		.split("\n")
		.slice(1)
		.map((line) => line.trim().split(" ")[0])
		.filter((name) => name.startsWith("@rpath/"));
}

function archsOf(file) {
	return capture("lipo", ["-archs", file]).trim().split(/\s+/).filter(Boolean);
}

/**
 * cargo replays `build-script-executed` for fresh units, so this reports the out_dir the build that
 * just ran actually linked against, including which of several msquic hashes it is. More than one is
 * an ambiguity we refuse rather than resolve by mtime, since the extras can differ in features.
 *
 * Messages are matched on the exact package id from `cargo metadata` rather than on the name, since
 * a path override can sit in a directory whose own name would match a looser test.
 *
 * The unit also has to come back fresh. A rebuild here means napi's invocation and this one disagree
 * about the unit, so the library now on disk would not be the one the already staged addon linked
 * against, and copying it would ship a mismatched pair.
 */
function msquicProvenance(cargoArgs, packageId) {
	const messages = capture(cargo, ["build", ...cargoArgs, "--message-format=json"]);
	const outDirs = new Set();
	const rebuilt = new Set();
	let sawArtifact = false;
	for (const line of messages.split("\n")) {
		if (!line.startsWith("{")) continue;
		let message;
		try {
			message = JSON.parse(line);
		} catch {
			continue;
		}
		if (message.package_id !== packageId) continue;
		if (message.reason === "build-script-executed" && message.out_dir) outDirs.add(message.out_dir);
		if (message.reason === "compiler-artifact") {
			sawArtifact = true;
			if (message.fresh !== true) for (const kind of message.target?.kind ?? ["unknown"]) rebuilt.add(kind);
		}
	}
	if (outDirs.size === 0) {
		fail(
			`the addon loads ${INSTALL_NAME} but cargo reported no build script for ${packageId} in this unit, ` +
				"so there is no provenance for the library to carry",
		);
	}
	if (outDirs.size > 1) {
		fail(
			`cargo reported ${outDirs.size} msquic build outputs for one unit and they can differ in features:\n` +
				[...outDirs].join("\n"),
		);
	}
	if (!sawArtifact) {
		fail(`cargo reported no artifact for ${packageId}, so there is no way to confirm the library was not rebuilt`);
	}
	if (rebuilt.size) {
		fail(
			`cargo rebuilt the msquic ${[...rebuilt].join(", ")} while resolving provenance, after the addon was ` +
				"already built, so the library on disk is not the one the addon linked against\n" +
				"run the build again, which will find both sides fresh, and report this if it repeats",
		);
	}
	return [...outDirs][0];
}

/** The selected msquic package, whether it came from the registry or a path override. */
function msquicPackage(metadata) {
	const packages = metadata.packages.filter((entry) => entry.name === "msquic");
	if (packages.length !== 1) {
		fail(
			`cargo metadata resolved ${packages.length} msquic packages, so both the library to carry and the ` +
				"notices to ship are ambiguous:\n" +
				packages.map((entry) => `${entry.version} ${entry.manifest_path}`).join("\n"),
		);
	}
	return packages[0];
}

const options = parseArgs(process.argv.slice(2));
const metadata = JSON.parse(
	capture(cargo, ["metadata", "--locked", "--format-version", "1", "--manifest-path", manifestPath]),
);
const triple = resolveTriple(options);
const targetDir = resolveTargetDir(options, metadata);
const outputDir = options.outputDir ? resolve(crateDir, options.outputDir) : crateDir;
const profileArgs = options.release
	? ["--profile", RELEASE_PROFILE]
	: options.profile
		? ["--profile", options.profile]
		: [];
const featureArgs = [
	...(options.features ? ["--features", options.features] : []),
	...(options.noDefaultFeatures ? ["--no-default-features"] : []),
];
const cargoArgs = [
	"--locked",
	"--manifest-path",
	manifestPath,
	"--target",
	triple,
	"--target-dir",
	targetDir,
	...profileArgs,
	...featureArgs,
];

if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

const cli = napiCli();

/**
 * Everything is built and assembled in a directory of our own inside the destination, then moved in
 * with rename, so nothing is ever written over a file that a running process has mapped and the move
 * never crosses a filesystem.
 */
const staging = mkdtempSync(join(outputDir, ".build-native-"));
try {
	passthrough(process.execPath, [
		cli,
		"build",
		"--platform",
		"--target",
		triple,
		"--target-dir",
		targetDir,
		"--output-dir",
		staging,
		...profileArgs,
		...featureArgs,
		// Everything after `--` goes to cargo unchanged.
		"--",
		"--locked",
	]);

	const built = readdirSync(staging).filter((name) => name.endsWith(".node"));
	if (built.length !== 1) {
		fail(
			`expected exactly one addon from this build, found ${built.length}${built.length ? `: ${built.join(", ")}` : ""}`,
		);
	}
	const [addonName] = built;
	const addon = join(staging, addonName);

	if (process.platform === "darwin") {
		const needed = rpathDeps(addon);
		const unknown = needed.filter((name) => name !== INSTALL_NAME);
		if (unknown.length) {
			fail(
				`${addonName} resolves ${unknown.join(", ")} through @rpath and this build only knows how to ` +
					`carry ${INSTALL_NAME}, so the addon would ship unable to load`,
			);
		}

		if (needed.includes(INSTALL_NAME)) {
			const msquic = msquicPackage(metadata);
			const source = join(msquicProvenance(cargoArgs, msquic.id), "lib", DYLIB);
			if (!statSync(source, { throwIfNoEntry: false })?.isFile()) {
				fail(`cargo named ${source} as this unit's msquic output and there is no ${DYLIB} there`);
			}

			const dylibArchs = archsOf(source);
			const addonArchs = archsOf(addon);
			const uncovered = addonArchs.filter((arch) => !dylibArchs.includes(arch));
			if (uncovered.length) {
				fail(
					`${addonName} is ${addonArchs.join(", ")} and the msquic output for this unit is ` +
						`${dylibArchs.join(", ")}, so ${uncovered.join(", ")} would have no library to load`,
				);
			}

			/**
			 * One directory holds one dylib, so an addon for another platform sitting here would be
			 * served the wrong architecture. Publishing those in separate directories is the fix, and
			 * silently shipping a mismatch is not.
			 */
			for (const other of readdirSync(outputDir)) {
				if (!other.endsWith(".node") || other === addonName) continue;
				const otherPath = join(outputDir, other);
				if (!rpathDeps(otherPath).includes(INSTALL_NAME)) continue;
				const missing = archsOf(otherPath).filter((arch) => !dylibArchs.includes(arch));
				if (missing.length) {
					fail(
						`${other} is already in ${outputDir}, loads ${INSTALL_NAME} from that same directory and ` +
							`needs ${missing.join(", ")}, which a ${dylibArchs.join(", ")} ${DYLIB} cannot serve\n` +
							"publish each platform in its own directory instead",
					);
				}
			}

			copyFileSync(source, join(staging, DYLIB));
			console.log(`[build-native] ${DYLIB} <- ${source}`);

			const sourceDir = dirname(msquic.manifest_path);
			for (const [from, to] of NOTICES) {
				const notice = join(sourceDir, from);
				if (!statSync(notice, { throwIfNoEntry: false })?.isFile()) {
					fail(`${DYLIB} ships with the addon and ${from} is not at ${notice}, so its license cannot ship with it`);
				}
				copyFileSync(notice, join(staging, to));
				console.log(`[build-native] ${to} <- ${notice}`);
			}
		} else {
			console.log(`[build-native] ${addonName} has no msquic dependency, nothing to carry`);
		}
	} else {
		console.log(`[build-native] ${process.platform} carries no library, only Apple builds resolve msquic by rpath`);
	}

	/** The addon lands last, so no load can find it before the library it needs is in place. */
	const staged = readdirSync(staging).sort(
		(left, right) => Number(left.endsWith(".node")) - Number(right.endsWith(".node")),
	);
	for (const name of staged) renameSync(join(staging, name), join(outputDir, name));
	console.log(`[build-native] ${outputDir} <- ${staged.join(", ")}`);
} finally {
	rmSync(staging, { recursive: true, force: true });
}
