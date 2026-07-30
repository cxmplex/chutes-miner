class DuplicateServer(Exception): ...


class NonEmptyServer(Exception): ...


class GPUlessServer(Exception): ...


class DeploymentFailure(Exception): ...


class BootstrapFailure(Exception): ...


class UnsupportedRuntime(BootstrapFailure):
    """The requested legacy operation is not implemented by this seedless runtime."""

    code = "unsupported_runtime"


class GraValBootstrapFailure(BootstrapFailure): ...


class TEEBootstrapFailure(BootstrapFailure): ...


class VerificationFailure(BootstrapFailure): ...
