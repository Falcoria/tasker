from enum import Enum
from uuid import UUID

from typing import Optional, List, Annotated

from pydantic import BaseModel, Field, constr, field_validator, PrivateAttr


class TaskNames(str, Enum):
    PROJECT_SCAN = "project.nmap.scan"
    PROJECT_CANCEL = "project.nmap.cancel"


class TcpScanType(str, Enum):
    syn = "-sS"
    connect = "-sT"
    ack = "-sA"
    window = "-sW"
    maimon = "-sM"


class TcpStealthScanType(str, Enum):
    null = "-sN"
    fin = "-sF"
    xmas = "-sX"


class TransportProtocol(str, Enum):
    tcp = "tcp"
    udp = "udp"  # maps to -sU


class OpenPortsOpts(BaseModel):
    skip_host_discovery: bool = Field(default=True, description="-Pn")
    dns_resolution: Optional[bool] = Field(default=None, description="-n (False), -R (True)")
    transport_protocol: TransportProtocol = Field(default=TransportProtocol.tcp, description="TCP or UDP")
    max_retries: Optional[int] = Field(default=None, ge=0, le=20, description="--max-retries")
    min_parallelism: Optional[int] = Field(default=None, ge=1, le=700, description="--min-parallelism")
    max_parallelism: Optional[int] = Field(default=None, ge=1, le=700, description="--max-parallelism")
    min_rtt_timeout_ms: Optional[int] = Field(default=None, ge=1, le=60000, description="--min-rtt-timeout")
    max_rtt_timeout_ms: Optional[int] = Field(default=None, ge=1, le=60000, description="--max-rtt-timeout")
    initial_rtt_timeout_ms: Optional[int] = Field(default=None, ge=1, le=60000, description="--initial-rtt-timeout")
    min_rate: Optional[int] = Field(default=None, ge=1, le=30000, description="--min-rate")
    max_rate: Optional[int] = Field(default=None, ge=1, le=30000, description="--max-rate")
    ports: List[str] = Field(
        ...,  # Ellipsis makes the field required
        description="List of ports or port ranges (e.g., '22', '80', '1000-2000')"
    )

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports):
        if ports is None:
            return ports
        
        for port in ports:
            if "-" in port:
                parts = port.split("-")
                if len(parts) != 2:
                    raise ValueError(f"Invalid port range format: {port}")
                start, end = parts
                if not (start.isdigit() and end.isdigit()):
                    raise ValueError(f"Port range must be numeric: {port}")
                start, end = int(start), int(end)
                if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValueError(f"Port range out of bounds (1-65535): {port}")
                if start > end:
                    raise ValueError(f"Port range start must be <= end: {port}")
            else:
                if not port.isdigit():
                    raise ValueError(f"Port must be a number: {port}")
                num = int(port)
                if not (1 <= num <= 65535):
                    raise ValueError(f"Port out of bounds (1-65535): {port}")

        return ports

    def to_nmap_args(self) -> List[str]:
        args = []

        if self.skip_host_discovery:
            args.append("-Pn")
        
        if self.dns_resolution is not None:
            args.append("-R" if self.dns_resolution else "-n")
        
        #if self.tcp_scan_type is not None:
        #    args.append(f"{self.tcp_scan_type.value}")

        if self.transport_protocol == TransportProtocol.udp:
            args.append("-sU")

        if self.max_retries is not None:
            args.append(f"--max-retries {self.max_retries}")

        #if self.host_timeout_ms is not None:
        #    args.append(f"--host-timeout {self.host_timeout_ms}ms")

        if self.min_parallelism is not None:
            args.append(f"--min-parallelism {self.min_parallelism}")

        if self.max_parallelism is not None:
            args.append(f"--max-parallelism {self.max_parallelism}")

        if self.min_rtt_timeout_ms is not None:
            args.append(f"--min-rtt-timeout {self.min_rtt_timeout_ms}ms")

        if self.max_rtt_timeout_ms is not None:
            args.append(f"--max-rtt-timeout {self.max_rtt_timeout_ms}ms")

        if self.initial_rtt_timeout_ms is not None:
            args.append(f"--initial-rtt-timeout {self.initial_rtt_timeout_ms}ms")

        if self.min_rate is not None:
            args.append(f"--min-rate {self.min_rate}")

        if self.max_rate is not None:
            args.append(f"--max-rate {self.max_rate}")
        
        #if self.top_ports is not None:
        #    args.append(f"--top-ports {self.top_ports}")
        
        if self.ports:
            args.append(f"-p {','.join(self.ports)}")

        return args


class ServiceOpts(OpenPortsOpts):
    ports: None = Field(default=None, exclude=True)
    #top_ports: None = Field(default=None, exclude=True)

    aggressive_scan: bool = Field(default=False, description="Enable aggressive scan mode (-A)")
    default_scripts: bool = Field(default=False, description="Use default Nmap scripts (-sC)")
    os_detection: bool = Field(default=False, description="Enable OS detection (-O)")
    traceroute: bool = Field(default=False, description="Trace hop path to each host (--traceroute)")
    #service_version: bool = Field(default=True, description="Probe open ports to determine service/version info (-sV)")
    _force_service_version: bool = PrivateAttr(default=True)

    def to_nmap_args(self) -> List[str]:
        args = super().to_nmap_args()

        if self.aggressive_scan:
            args.append("-A")
        #if self.service_version:
        #    args.append("-sV")
        if self.default_scripts:
            args.append("-sC")
        if self.os_detection:
            args.append("-O")
        if self.traceroute:
            args.append("--traceroute")
        if self._force_service_version:
            args.append("-sV")

        return args


class NmapTask(BaseModel):
    ip: str
    project: UUID
    open_ports_opts: str
    service_opts: str
    timeout: int


HostName = Annotated[
    str,
    constr(
        max_length=253,
        # not valid.
        pattern=r"^((?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})$"
    )
]

class RunNmapRequest(BaseModel):
    hosts: List[HostName]
    open_ports_opts: OpenPortsOpts
    service_opts: ServiceOpts
    timeout: int = Field(default=1200, ge=1, le=60*60*24, description="Timeout in seconds for the scan")


class RunNmapWithProject(RunNmapRequest):
    project_id: Optional[str] = Field(
        default=None,
        title="Project ID",
        description="UUID of the project to run the scan on",
        example="123e4567-e89b-12d3-a456-426614174000"
    )