"""Pinned deterministic WASI preview1 verifier for DM-061.

The runner is evidence-only.  It never receives Matrix custody, ledgers,
routes, grants, credentials, or ambient environment and cannot activate code.
"""

from __future__ import annotations

import base64
import os
import stat
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import wasmtime

from .canonical import canonical_bytes

RUNNER_VERSION: Final = "wasmtime-python/45.0.0-dm061.1"
EXECUTION_MODEL: Final = "wasm32-wasi-preview1-deterministic/v0"
RESULT_SCHEMA: Final = "daimon-test-result-jcs/v0"
MAX_SAFE_INTEGER: Final = 2**53 - 1
_WASI_MODULE: Final = "wasi_snapshot_preview1"
_PERMITTED_IMPORTS: Final = frozenset(
    {
        "args_get",
        "args_sizes_get",
        "clock_res_get",
        "clock_time_get",
        "environ_get",
        "environ_sizes_get",
        "fd_close",
        "fd_fdstat_get",
        "fd_filestat_get",
        "fd_pread",
        "fd_prestat_dir_name",
        "fd_prestat_get",
        "fd_read",
        "fd_seek",
        "fd_tell",
        "fd_write",
        "path_filestat_get",
        "path_open",
        "path_readlink",
        "proc_exit",
    }
)


class SpeciesRunnerError(ValueError):
    """The runner profile, bundle, or deterministic execution failed closed."""

    def __init__(self, code: str, *, incomplete: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.incomplete = incomplete


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SpeciesRunnerError(code)
    return value


def _uint(value: Any, minimum: int, maximum: int, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= min(maximum, MAX_SAFE_INTEGER)
    ):
        raise SpeciesRunnerError(code)
    return value


@dataclass(frozen=True)
class ResourceProfile:
    cpu_fuel: int
    aggregate_cpu_fuel: int
    case_count: int
    wall_timeout_ms: int
    aggregate_wall_timeout_ms: int
    memory_bytes: int
    stdout_bytes: int
    stderr_bytes: int
    filesystem_bytes: int
    file_count: int

    @classmethod
    def validate(cls, value: Any) -> ResourceProfile:
        row = _closed(
            value,
            {
                "aggregate_cpu_fuel",
                "aggregate_wall_timeout_ms",
                "case_count",
                "clock",
                "cpu_fuel",
                "environment",
                "execution_model",
                "file_count",
                "filesystem_bytes",
                "memory_bytes",
                "network",
                "process_count",
                "randomness",
                "schema",
                "stderr_bytes",
                "stdout_bytes",
                "thread_count",
                "wall_timeout_ms",
            },
            "resource_profile_fields",
        )
        if (
            row["schema"] != "species-resource-profile/v0"
            or row["execution_model"] != EXECUTION_MODEL
            or row["network"] != "denied"
            or row["clock"] != "fixed-zero"
            or row["randomness"] != "denied"
            or row["environment"] != []
            or row["process_count"] != 1
            or row["thread_count"] != 1
        ):
            raise SpeciesRunnerError("resource_profile_authority")
        result = cls(
            cpu_fuel=_uint(row["cpu_fuel"], 1, 1_000_000_000, "cpu_fuel"),
            aggregate_cpu_fuel=_uint(
                row["aggregate_cpu_fuel"],
                1,
                64_000_000_000,
                "aggregate_cpu_fuel",
            ),
            case_count=_uint(row["case_count"], 1, 4096, "case_count"),
            wall_timeout_ms=_uint(row["wall_timeout_ms"], 1, 600_000, "wall_timeout"),
            aggregate_wall_timeout_ms=_uint(
                row["aggregate_wall_timeout_ms"],
                1,
                3_600_000,
                "aggregate_wall_timeout",
            ),
            memory_bytes=_uint(row["memory_bytes"], 1, 1_073_741_824, "memory_bytes"),
            stdout_bytes=_uint(row["stdout_bytes"], 0, 8_388_608, "stdout_bytes"),
            stderr_bytes=_uint(row["stderr_bytes"], 0, 8_388_608, "stderr_bytes"),
            filesystem_bytes=_uint(
                row["filesystem_bytes"], 0, 536_870_912, "filesystem_bytes"
            ),
            file_count=_uint(row["file_count"], 0, 4096, "file_count"),
        )
        if result.aggregate_cpu_fuel < result.cpu_fuel:
            raise SpeciesRunnerError("aggregate_cpu_fuel_too_small")
        if result.aggregate_wall_timeout_ms < result.wall_timeout_ms:
            raise SpeciesRunnerError("aggregate_wall_timeout_too_small")
        return result


@dataclass(frozen=True)
class Execution:
    result: Mapping[str, Any]
    result_bytes: bytes
    fuel_consumed: int


def _owner_directory(path: Path) -> None:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SpeciesRunnerError("runner_root_not_owner_only")


def _safe_relative(path: str) -> tuple[str, ...]:
    if (
        not isinstance(path, str)
        or not path
        or "\\" in path
        or path.startswith("/")
        or path.endswith("/")
    ):
        raise SpeciesRunnerError("bundle_path_invalid")
    parts = tuple(path.split("/"))
    if len(parts) > 32 or any(part in {"", ".", ".."} for part in parts):
        raise SpeciesRunnerError("bundle_path_invalid")
    return parts


def _materialize_files(
    root: Path, files: Mapping[str, bytes], profile: ResourceProfile
) -> None:
    if len(files) > profile.file_count:
        raise SpeciesRunnerError("bundle_file_count")
    if sum(len(value) for value in files.values()) > profile.filesystem_bytes:
        raise SpeciesRunnerError("bundle_filesystem_bytes")
    for name in sorted(files):
        parts = _safe_relative(name)
        target = root.joinpath(*parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise SpeciesRunnerError("bundle_path_alias")
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            raw = files[name]
            if os.write(descriptor, raw) != len(raw):
                raise SpeciesRunnerError("bundle_write_short")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)


class DeterministicWasiRunner:
    """Execute one fresh, bounded Wasmtime store per exact test case."""

    version: Final = RUNNER_VERSION

    @staticmethod
    def _engine() -> wasmtime.Engine:
        config = wasmtime.Config()
        config.consume_fuel = True
        config.epoch_interruption = True
        config.wasm_threads = False
        config.wasm_memory64 = False
        config.wasm_relaxed_simd = False
        config.wasm_relaxed_simd_deterministic = True
        config.parallel_compilation = False
        config.cranelift_nan_canonicalization = True
        return wasmtime.Engine(config)

    @staticmethod
    def _validate_imports(module: wasmtime.Module) -> None:
        for item in module.imports:
            if item.module != _WASI_MODULE or item.name not in _PERMITTED_IMPORTS:
                raise SpeciesRunnerError("runner_forbidden_import")

    def run(
        self,
        *,
        case_id: str,
        module_bytes: bytes,
        export_name: str,
        input_bytes: bytes,
        bundle_files: Mapping[str, bytes],
        dependency_files: Mapping[str, Mapping[str, bytes]],
        resource_profile: Mapping[str, Any],
    ) -> Execution:
        profile = ResourceProfile.validate(resource_profile)
        if not isinstance(case_id, str) or not 1 <= len(case_id.encode("utf-8")) <= 128:
            raise SpeciesRunnerError("case_id_invalid")
        if (
            not isinstance(export_name, str)
            or not export_name
            or len(export_name.encode("utf-8")) > 128
        ):
            raise SpeciesRunnerError("entrypoint_invalid")
        if not isinstance(module_bytes, bytes) or len(module_bytes) > 67_108_864:
            raise SpeciesRunnerError("module_size")
        if not isinstance(input_bytes, bytes) or len(input_bytes) > 67_108_864:
            raise SpeciesRunnerError("input_size")
        engine = self._engine()
        try:
            module = wasmtime.Module(engine, module_bytes)
        except wasmtime.WasmtimeError as error:
            raise SpeciesRunnerError("module_invalid") from error
        self._validate_imports(module)
        closure_files = len(bundle_files) + sum(
            len(files) for files in dependency_files.values()
        )
        closure_bytes = sum(len(value) for value in bundle_files.values()) + sum(
            len(value)
            for files in dependency_files.values()
            for value in files.values()
        )
        if closure_files > profile.file_count:
            raise SpeciesRunnerError("bundle_file_count")
        if closure_bytes > profile.filesystem_bytes:
            raise SpeciesRunnerError("bundle_filesystem_bytes")
        with tempfile.TemporaryDirectory(prefix="dm-species-runner-") as raw_root:
            root = Path(raw_root)
            os.chmod(root, 0o700)
            _owner_directory(root)
            bundle_root = root / "bundle"
            deps_root = root / "deps"
            bundle_root.mkdir(mode=0o700)
            deps_root.mkdir(mode=0o700)
            _materialize_files(bundle_root, bundle_files, profile)
            for dependency_id in sorted(dependency_files):
                if not dependency_id.startswith("dm:species-content:v0:"):
                    raise SpeciesRunnerError("dependency_id_invalid")
                dependency_root = deps_root / dependency_id
                dependency_root.mkdir(mode=0o700)
                _materialize_files(
                    dependency_root, dependency_files[dependency_id], profile
                )
            stdin = root / "stdin"
            stdout = root / "stdout"
            stderr = root / "stderr"
            stdin.write_bytes(input_bytes)
            stdout.touch(mode=0o600)
            stderr.touch(mode=0o600)
            wasi = wasmtime.WasiConfig()
            wasi.argv = []
            wasi.env = []
            wasi.stdin_file = str(stdin)
            wasi.stdout_file = str(stdout)
            wasi.stderr_file = str(stderr)
            wasi.preopen_dir(
                str(bundle_root),
                "/bundle",
                wasmtime.DirPerms.READ_ONLY,
                wasmtime.FilePerms.READ_ONLY,
            )
            wasi.preopen_dir(
                str(deps_root),
                "/deps",
                wasmtime.DirPerms.READ_ONLY,
                wasmtime.FilePerms.READ_ONLY,
            )
            store = wasmtime.Store(engine)
            store.set_limits(
                memory_size=profile.memory_bytes,
                table_elements=10_000,
                instances=1,
                tables=8,
                memories=8,
            )
            store.set_fuel(profile.cpu_fuel)
            store.set_epoch_deadline(1)
            store.set_wasi(wasi)
            linker = wasmtime.Linker(engine)
            linker.allow_shadowing = True
            linker.define_wasi()

            def fixed_clock(
                caller: wasmtime.Caller,
                _clock_id: int,
                _precision: int,
                output_pointer: int,
            ) -> int:
                memory = caller.get("memory")
                if not isinstance(memory, wasmtime.Memory):
                    return 21
                memory.write(caller, b"\x00" * 8, output_pointer)
                return 0

            linker.define_func(
                _WASI_MODULE,
                "clock_time_get",
                wasmtime.FuncType(
                    [
                        wasmtime.ValType.i32(),
                        wasmtime.ValType.i64(),
                        wasmtime.ValType.i32(),
                    ],
                    [wasmtime.ValType.i32()],
                ),
                fixed_clock,
                access_caller=True,
            )

            def fixed_clock_resolution(
                caller: wasmtime.Caller,
                _clock_id: int,
                output_pointer: int,
            ) -> int:
                memory = caller.get("memory")
                if not isinstance(memory, wasmtime.Memory):
                    return 21
                memory.write(caller, (1).to_bytes(8, "little"), output_pointer)
                return 0

            linker.define_func(
                _WASI_MODULE,
                "clock_res_get",
                wasmtime.FuncType(
                    [wasmtime.ValType.i32(), wasmtime.ValType.i32()],
                    [wasmtime.ValType.i32()],
                ),
                fixed_clock_resolution,
                access_caller=True,
            )
            timer = threading.Timer(
                profile.wall_timeout_ms / 1000.0, engine.increment_epoch
            )
            timer.daemon = True
            timer.start()
            exit_code = 0
            try:
                instance = linker.instantiate(store, module)
                exported = instance.exports(store).get(export_name)
                if not isinstance(exported, wasmtime.Func):
                    raise SpeciesRunnerError("entrypoint_missing")
                function_type = exported.type(store)
                if function_type.params or function_type.results:
                    raise SpeciesRunnerError("entrypoint_signature")
                exported(store)
            except wasmtime.ExitTrap as error:
                message = str(error)
                exit_code = 0 if "status 0" in message else 1
            except wasmtime.Trap as error:
                message = str(error).lower()
                if "epoch deadline" in message or "interrupt" in message:
                    raise SpeciesRunnerError(
                        "runner_timeout", incomplete=True
                    ) from error
                exit_code = 1
            finally:
                timer.cancel()
            stdout_bytes = stdout.read_bytes()
            stderr_bytes = stderr.read_bytes()
            if len(stdout_bytes) > profile.stdout_bytes:
                raise SpeciesRunnerError("stdout_limit")
            if len(stderr_bytes) > profile.stderr_bytes:
                raise SpeciesRunnerError("stderr_limit")
            remaining = store.get_fuel()
            result: dict[str, Any] = {
                "case_id": case_id,
                "exit_code": exit_code,
                "schema": RESULT_SCHEMA,
                "stderr_base64": base64.b64encode(stderr_bytes).decode("ascii"),
                "stdout_base64": base64.b64encode(stdout_bytes).decode("ascii"),
            }
            raw_result = canonical_bytes(result)
            return Execution(
                result=result,
                result_bytes=raw_result,
                fuel_consumed=profile.cpu_fuel - remaining,
            )


__all__ = [
    "EXECUTION_MODEL",
    "RESULT_SCHEMA",
    "RUNNER_VERSION",
    "DeterministicWasiRunner",
    "Execution",
    "ResourceProfile",
    "SpeciesRunnerError",
]
